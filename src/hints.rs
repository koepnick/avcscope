//! Read-only diagnosis hints.
//!
//! Given a de-duplicated denial, produce *suggestions* that steer the analyst
//! toward the root cause -- in the order recommended by the debugging
//! procedure (label first, then booleans/ports, custom policy only as a last
//! resort). Every command suggested here is either read-only or is shown as
//! text for the human to review and run deliberately. This tool never runs a
//! mutating command itself.

use crate::avc::AggDenial;

/// A category for color/labeling in the UI.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HintKind {
    Likely,   // strong root-cause hypothesis
    Consider, // secondary possibility
    Inspect,  // read-only commands to gather more evidence
    Caution,  // safety reminders
}

pub struct Hint {
    pub kind: HintKind,
    pub text: String,
}

// Target types that, on a confined daemon touching files/dirs, very often mean
// "this object is mislabeled" rather than "the daemon needs this access".
const SUSPICIOUS_FILE_TYPES: &[&str] = &[
    "user_home_t",
    "user_home_dir_t",
    "admin_home_t",
    "user_tmp_t",
    "default_t",
    "unlabeled_t",
    "var_t",
    "tmp_t",
    "etc_runtime_t",
];

fn is_file_class(tclass: &str) -> bool {
    matches!(
        tclass,
        "file" | "dir" | "lnk_file" | "chr_file" | "blk_file" | "fifo_file" | "sock_file"
    )
}

fn is_socket_class(tclass: &str) -> bool {
    matches!(
        tclass,
        "tcp_socket" | "udp_socket" | "socket" | "rawip_socket"
    )
}

/// A tiny built-in map of (source type, signal) -> the boolean most likely to
/// be relevant. Not exhaustive -- just the ones people hit constantly.
fn relevant_booleans(d: &AggDenial) -> Vec<&'static str> {
    let mut out = Vec::new();
    let s = d.scontext.ty.as_str();
    let networky = is_socket_class(&d.tclass)
        || d.perms.iter().any(|p| p == "name_connect" || p == "name_bind");
    if s == "httpd_t" {
        if networky {
            out.push("httpd_can_network_connect");
            out.push("httpd_can_network_connect_db");
        }
        if d.tcontext.ty.starts_with("user_home") {
            out.push("httpd_enable_homedirs");
            out.push("httpd_read_user_content");
        }
    }
    if networky && (s == "httpd_t" || s == "nginx_t") {
        out.push("nis_enabled");
    }
    out
}

pub fn diagnose(d: &AggDenial) -> Vec<Hint> {
    let mut hints = Vec::new();

    if d.outcome == "granted" {
        hints.push(Hint {
            kind: HintKind::Consider,
            text: "This is a GRANTED record (logged because the access was \
                   audited, e.g. in permissive mode). It was not blocked."
                .into(),
        });
    }

    // --- Hypothesis 1: mislabeling (the most common cause) ---
    if is_file_class(&d.tclass) && SUSPICIOUS_FILE_TYPES.contains(&d.tcontext.ty.as_str()) {
        hints.push(Hint {
            kind: HintKind::Likely,
            text: format!(
                "MISLABEL likely: a '{}' process was denied on an object \
                 labeled '{}'. That target type is a generic/home/default \
                 label, which usually means the file is in the wrong place or \
                 kept an old label after a mv/restore -- not that the service \
                 needs this access.",
                d.scontext.ty, d.tcontext.ty
            ),
        });
        if let Some(p) = d.paths.iter().next() {
            hints.push(Hint {
                kind: HintKind::Inspect,
                text: format!(
                    "Compare actual vs expected label:  ls -Z {p}   and   \
                     matchpathcon {p}   (both read-only). If they differ, the \
                     fix is to relabel, e.g.  restorecon -Rv {p}  -- run that \
                     yourself after confirming.",
                    p = p
                ),
            });
        } else {
            hints.push(Hint {
                kind: HintKind::Inspect,
                text: "Compare actual vs expected label with  ls -Z <path>  \
                       and  matchpathcon <path>  (read-only)."
                    .into(),
            });
        }
    }

    // --- Hypothesis 2: port / network ---
    if is_socket_class(&d.tclass)
        || d.perms.iter().any(|p| p == "name_connect" || p == "name_bind")
    {
        hints.push(Hint {
            kind: HintKind::Likely,
            text: format!(
                "NETWORK/PORT issue: '{}' was denied '{}' against '{}'. Either \
                 the port needs labeling, or a boolean gates this connectivity.",
                d.scontext.ty,
                d.perms.join(" "),
                d.tcontext.ty
            ),
        });
        hints.push(Hint {
            kind: HintKind::Inspect,
            text: "List port labels (read-only):  semanage port -l | grep <type>  \
                   -- e.g. to confirm which ports a type owns. A non-standard \
                   port is labeled with  semanage port -a -t <port_type> -p tcp <N>  \
                   (run yourself)."
                .into(),
        });
    }

    // --- Hypothesis 3: a relevant boolean ---
    let bools = relevant_booleans(d);
    if !bools.is_empty() {
        hints.push(Hint {
            kind: HintKind::Consider,
            text: format!(
                "Possibly gated by a boolean. Check (read-only):  getsebool {0}  \
                 .  If the behavior is intended, enable persistently with  \
                 setsebool -P {0} on  (run yourself).",
                bools[0]
            ),
        });
        if bools.len() > 1 {
            hints.push(Hint {
                kind: HintKind::Consider,
                text: format!("Other booleans worth reviewing: {}", bools[1..].join(", ")),
            });
        }
    }

    // --- Always: confirm the cause category, and the safety net ---
    hints.push(Hint {
        kind: HintKind::Inspect,
        text: "Confirm the cause category (read-only):  echo '<this denial>' | \
               audit2why   -- it reports whether a boolean, a missing rule, or \
               a constraint is responsible."
            .into(),
    });
    hints.push(Hint {
        kind: HintKind::Inspect,
        text: format!(
            "Ask the loaded policy whether the rule even exists (read-only):  \
             sesearch -A -s {} -t {} -c {}",
            d.scontext.ty, d.tcontext.ty, d.tclass
        ),
    });
    hints.push(Hint {
        kind: HintKind::Caution,
        text: "Last resort only: audit2allow can generate a module, but it will \
               happily grant access to a MISLABELED file. Rule out labels, \
               ports and booleans first, and always read the .te before \
               installing. This tool will not generate or install policy for you."
            .into(),
    });

    hints
}
