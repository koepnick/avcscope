//! Parsing of SELinux AVC audit lines, the data model, and de-duplication.
//!
//! Everything here is pure / read-only: it takes log text in and produces
//! structured, aggregated denials out. Nothing in this module (or anywhere in
//! the program) can change SELinux policy, labels, booleans, or modes.

use std::collections::BTreeSet;

/// An SELinux security context, e.g. `system_u:system_r:httpd_t:s0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    pub user: String,
    pub role: String,
    pub ty: String,   // the "type" -- almost always the field that matters
    pub level: String,
    pub raw: String,
}

impl Context {
    pub fn parse(raw: &str) -> Context {
        // Levels can themselves contain ':' (e.g. s0-s0:c0.c1023), so we split
        // into at most 4 parts and let the level absorb the remainder.
        let mut parts = raw.splitn(4, ':');
        let user = parts.next().unwrap_or("").to_string();
        let role = parts.next().unwrap_or("").to_string();
        let ty = parts.next().unwrap_or("").to_string();
        let level = parts.next().unwrap_or("").to_string();
        Context { user, role, ty, level, raw: raw.to_string() }
    }
}

/// A single parsed AVC occurrence (one log line).
#[derive(Debug, Clone)]
pub struct Denial {
    pub timestamp: f64,
    pub serial: u64,
    pub outcome: String,      // "denied" or "granted"
    pub perms: Vec<String>,   // contents of the { ... } braces, sorted
    pub scontext: Context,    // subject (the process)
    pub tcontext: Context,    // object (the target)
    pub tclass: String,       // object class: file, dir, tcp_socket, ...
    pub comm: String,         // executable name
    pub path: Option<String>, // path= or name=
    pub pid: Option<u32>,
    pub dev: Option<String>,
    pub ino: Option<String>,
    pub permissive: Option<bool>, // was the system permissive at the time?
    pub raw: String,
}

/// A de-duplicated group of identical denials, with a running count.
#[derive(Debug, Clone)]
pub struct AggDenial {
    pub key: String,
    pub outcome: String,
    pub perms: Vec<String>,
    pub scontext: Context,
    pub tcontext: Context,
    pub tclass: String,
    pub comm: String,
    pub count: usize,                 // how many raw lines collapsed into this
    pub first_ts: f64,
    pub last_ts: f64,
    pub paths: BTreeSet<String>,      // distinct paths/names observed
    pub pids: BTreeSet<u32>,          // distinct pids observed
    pub permissive: Option<bool>,
    pub sample_raw: String,
}

impl AggDenial {
    /// One-line summary used in the list view.
    pub fn summary(&self) -> String {
        format!(
            "{} {{{}}} {} -> {} [{}]",
            self.comm,
            self.perms.join(" "),
            self.scontext.ty,
            self.tcontext.ty,
            self.tclass
        )
    }

    /// Lowercased haystack for the `/` search.
    pub fn search_blob(&self) -> String {
        let paths: Vec<&str> = self.paths.iter().map(|s| s.as_str()).collect();
        format!(
            "{} {} {} {} {} {} {}",
            self.comm,
            self.perms.join(" "),
            self.scontext.raw,
            self.tcontext.raw,
            self.tclass,
            self.outcome,
            paths.join(" ")
        )
        .to_lowercase()
    }
}

/// The fields that make two denials "the same" for de-duplication.
///
/// We deliberately exclude pid, timestamp, inode and the specific path: an
/// `httpd_t` process being denied `read` on `user_home_t` files is *one*
/// problem whether it happens to 1 file or 500, and collapsing it is exactly
/// what makes the list readable. The distinct paths are still preserved inside
/// the group for the detail view.
fn dedup_key(d: &Denial) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        d.outcome,
        d.perms.join(","),
        d.scontext.raw,
        d.tcontext.raw,
        d.tclass,
        d.comm
    )
}

/// Split a log line into fields, honoring double-quoted values so that
/// `name="my file"` stays a single token.
fn split_fields(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for c in s.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Parse a single audit line into a `Denial`, or `None` if it isn't an AVC.
pub fn parse_line(line: &str) -> Option<Denial> {
    // Must look like an AVC (kernel AVC or USER_AVC). USER_AVC nests the real
    // message in single quotes, but the key=value pairs we want still appear.
    if !line.contains("avc:") {
        return None;
    }

    // Outcome + permission set live in `avc:  denied  { perm perm } for ...`.
    let outcome = if line.contains("denied") {
        "denied"
    } else if line.contains("granted") {
        "granted"
    } else {
        "denied"
    }
    .to_string();

    let mut perms = Vec::new();
    if let (Some(open), Some(close)) = (line.find('{'), line.find('}')) {
        if close > open {
            perms = line[open + 1..close]
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
        }
    }
    perms.sort();

    // Timestamp + serial from audit(1700000000.123:456).
    let (mut timestamp, mut serial) = (0.0_f64, 0_u64);
    if let Some(start) = line.find("audit(") {
        if let Some(end_rel) = line[start..].find(')') {
            let inner = &line[start + 6..start + end_rel]; // "1700000000.123:456"
            let mut it = inner.split(':');
            if let Some(ts) = it.next() {
                timestamp = ts.parse().unwrap_or(0.0);
            }
            if let Some(sn) = it.next() {
                serial = sn.parse().unwrap_or(0);
            }
        }
    }

    // Generic key=value extraction for everything else.
    let mut scontext = Context::parse("");
    let mut tcontext = Context::parse("");
    let mut tclass = String::new();
    let mut comm = String::new();
    let mut name: Option<String> = None;
    let mut path: Option<String> = None;
    let mut pid = None;
    let mut dev = None;
    let mut ino = None;
    let mut permissive = None;

    for tok in split_fields(line) {
        if let Some((k, v)) = tok.split_once('=') {
            match k {
                "scontext" => scontext = Context::parse(v),
                "tcontext" => tcontext = Context::parse(v),
                "tclass" => tclass = v.to_string(),
                "comm" => comm = v.to_string(),
                "name" => name = Some(v.to_string()),
                "path" => path = Some(v.to_string()),
                "pid" => pid = v.parse().ok(),
                "dev" => dev = Some(v.to_string()),
                "ino" => ino = Some(v.to_string()),
                "permissive" => permissive = Some(v == "1"),
                _ => {}
            }
        }
    }

    Some(Denial {
        timestamp,
        serial,
        outcome,
        perms,
        scontext,
        tcontext,
        tclass,
        comm,
        path: path.or(name),
        pid,
        dev,
        ino,
        permissive,
        raw: line.trim().to_string(),
    })
}

/// Parse a whole blob of log text and de-duplicate.
///
/// Returns `(groups, total_raw)` where `total_raw` is the number of individual
/// denial lines parsed -- the "running total" displayed alongside the unique
/// count.
pub fn aggregate(text: &str) -> (Vec<AggDenial>, usize) {
    use std::collections::HashMap;
    let mut map: HashMap<String, AggDenial> = HashMap::new();
    let mut total_raw = 0usize;

    for line in text.lines() {
        let Some(d) = parse_line(line) else { continue };
        total_raw += 1;
        let key = dedup_key(&d);
        let entry = map.entry(key.clone()).or_insert_with(|| AggDenial {
            key,
            outcome: d.outcome.clone(),
            perms: d.perms.clone(),
            scontext: d.scontext.clone(),
            tcontext: d.tcontext.clone(),
            tclass: d.tclass.clone(),
            comm: d.comm.clone(),
            count: 0,
            first_ts: d.timestamp,
            last_ts: d.timestamp,
            paths: BTreeSet::new(),
            pids: BTreeSet::new(),
            permissive: d.permissive,
            sample_raw: d.raw.clone(),
        });
        entry.count += 1;
        if d.timestamp > 0.0 {
            if entry.first_ts == 0.0 || d.timestamp < entry.first_ts {
                entry.first_ts = d.timestamp;
            }
            if d.timestamp > entry.last_ts {
                entry.last_ts = d.timestamp;
            }
        }
        if let Some(p) = &d.path {
            entry.paths.insert(p.clone());
        }
        if let Some(pid) = d.pid {
            entry.pids.insert(pid);
        }
    }

    (map.into_values().collect(), total_raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str = r#"type=AVC msg=audit(1717250001.111:401): avc:  denied  { read open } for  pid=2041 comm="httpd" name="my file.html" dev="sda1" ino=66001 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0"#;

    #[test]
    fn parses_core_fields() {
        let d = parse_line(LINE).expect("should parse");
        assert_eq!(d.outcome, "denied");
        assert_eq!(d.perms, vec!["open", "read"]); // sorted
        assert_eq!(d.scontext.ty, "httpd_t");
        assert_eq!(d.tcontext.ty, "user_home_t");
        assert_eq!(d.tclass, "file");
        assert_eq!(d.comm, "httpd");
        assert_eq!(d.path.as_deref(), Some("my file.html")); // quoted w/ space
        assert_eq!(d.pid, Some(2041));
        assert_eq!(d.serial, 401);
        assert_eq!(d.permissive, Some(false));
        assert!((d.timestamp - 1717250001.111).abs() < 0.001);
    }

    #[test]
    fn ignores_non_avc_lines() {
        assert!(parse_line("type=SYSCALL msg=audit(1.2:3): arch=c000 success=yes").is_none());
    }

    #[test]
    fn level_with_colons_is_preserved() {
        let c = Context::parse("system_u:system_r:httpd_t:s0-s0:c0.c1023");
        assert_eq!(c.ty, "httpd_t");
        assert_eq!(c.level, "s0-s0:c0.c1023");
    }

    #[test]
    fn dedup_collapses_repeats_and_counts() {
        let text = format!("{LINE}\n{LINE}\n{LINE}");
        let (groups, total) = aggregate(&text);
        assert_eq!(total, 3, "running total counts every line");
        assert_eq!(groups.len(), 1, "identical denials collapse to one group");
        assert_eq!(groups[0].count, 3);
    }

    #[test]
    fn distinct_paths_kept_but_still_one_group() {
        let a = LINE.to_string();
        let b = LINE.replace("my file.html", "other.html");
        let (groups, total) = aggregate(&format!("{a}\n{b}"));
        assert_eq!(total, 2);
        assert_eq!(groups.len(), 1, "different file, same denial pattern");
        assert_eq!(groups[0].paths.len(), 2, "both paths preserved in detail");
    }
}
