//! SELinux status detection and denial sources.
//!
//! Read-only by construction: we only ever *read* `/sys/fs/selinux/enforce`
//! or run read-only query commands (`getenforce`, `ausearch`). We never invoke
//! `setenforce`, `setsebool`, `semanage`, `semodule`, or `restorecon`.

use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforceStatus {
    Enforcing,
    Permissive,
    Disabled,
    Unknown,
}

impl EnforceStatus {
    pub fn label(&self) -> &'static str {
        match self {
            EnforceStatus::Enforcing => "ENFORCING",
            EnforceStatus::Permissive => "PERMISSIVE",
            EnforceStatus::Disabled => "DISABLED",
            EnforceStatus::Unknown => "UNKNOWN",
        }
    }
}

/// Detect the current mode without changing anything.
pub fn detect_status() -> EnforceStatus {
    // Primary: the selinuxfs pseudo-file. '1' = enforcing, '0' = permissive.
    let enforce = Path::new("/sys/fs/selinux/enforce");
    if enforce.exists() {
        if let Ok(s) = fs::read_to_string(enforce) {
            return match s.trim() {
                "1" => EnforceStatus::Enforcing,
                "0" => EnforceStatus::Permissive,
                _ => EnforceStatus::Unknown,
            };
        }
    }
    // If selinuxfs isn't mounted at all, SELinux is effectively disabled.
    if !Path::new("/sys/fs/selinux").exists() {
        // Fall back to `getenforce` in case of an unusual mount layout.
        if let Ok(out) = Command::new("getenforce").output() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();
            return match s.as_str() {
                "enforcing" => EnforceStatus::Enforcing,
                "permissive" => EnforceStatus::Permissive,
                "disabled" => EnforceStatus::Disabled,
                _ => EnforceStatus::Unknown,
            };
        }
        return EnforceStatus::Disabled;
    }
    EnforceStatus::Unknown
}

/// Where the denial text came from -- shown in the footer for transparency.
#[derive(Debug, Clone)]
pub enum Source {
    Demo,
    File(String),
    Stdin,
    Ausearch,
    AuditLog,
}

impl Source {
    pub fn describe(&self) -> String {
        match self {
            Source::Demo => "built-in demo data".to_string(),
            Source::File(p) => format!("file: {p}"),
            Source::Stdin => "stdin".to_string(),
            Source::Ausearch => "ausearch -m AVC,USER_AVC,SELINUX_ERR".to_string(),
            Source::AuditLog => "/var/log/audit/audit.log".to_string(),
        }
    }
}

/// Resolve where to read denials from, in priority order:
///   --demo            -> embedded sample data
///   --file PATH       -> that file
///   piped stdin       -> stdin
///   else              -> try `ausearch`, then audit.log, then demo.
pub fn load(force_demo: bool, file: Option<String>) -> (String, Source) {
    if force_demo {
        return (demo_data().to_string(), Source::Demo);
    }
    if let Some(p) = file {
        match fs::read_to_string(&p) {
            Ok(text) => return (text, Source::File(p)),
            Err(e) => {
                eprintln!("could not read {p}: {e}; falling back to demo data");
                return (demo_data().to_string(), Source::Demo);
            }
        }
    }
    // Piped input (not a terminal) -> read stdin.
    use std::io::{IsTerminal, Read};
    if !std::io::stdin().is_terminal() {
        let mut buf = String::new();
        if std::io::stdin().read_to_string(&mut buf).is_ok() && !buf.trim().is_empty() {
            return (buf, Source::Stdin);
        }
    }
    // Try the canonical live query.
    if let Ok(out) = Command::new("ausearch")
        .args(["-m", "AVC,USER_AVC,SELINUX_ERR", "-ts", "today"])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            if text.contains("avc:") {
                return (text, Source::Ausearch);
            }
        }
    }
    // Fall back to the raw audit log.
    if let Ok(text) = fs::read_to_string("/var/log/audit/audit.log") {
        if text.contains("avc:") {
            return (text, Source::AuditLog);
        }
    }
    // Nothing real available -- show the demo so the tool is still useful.
    (demo_data().to_string(), Source::Demo)
}

/// Realistic sample denials. They intentionally cover the common root causes
/// from the debugging procedure (mislabel, network boolean, non-standard port)
/// and include repeats so the de-duplication and running total are visible.
pub fn demo_data() -> &'static str {
    r#"type=AVC msg=audit(1717250001.111:401): avc:  denied  { read } for  pid=2041 comm="httpd" name="index.html" dev="sda1" ino=66001 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0
type=AVC msg=audit(1717250002.220:402): avc:  denied  { read } for  pid=2042 comm="httpd" name="about.html" dev="sda1" ino=66002 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0
type=AVC msg=audit(1717250003.330:403): avc:  denied  { read } for  pid=2043 comm="httpd" name="contact.html" dev="sda1" ino=66003 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0
type=AVC msg=audit(1717250004.440:404): avc:  denied  { open } for  pid=2044 comm="httpd" name="index.html" dev="sda1" ino=66001 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0
type=AVC msg=audit(1717250010.500:410): avc:  denied  { name_connect } for  pid=2050 comm="httpd" dest=3306 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:mysqld_port_t:s0 tclass=tcp_socket permissive=0
type=AVC msg=audit(1717250011.600:411): avc:  denied  { name_connect } for  pid=2051 comm="httpd" dest=3306 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:mysqld_port_t:s0 tclass=tcp_socket permissive=0
type=AVC msg=audit(1717250020.700:420): avc:  denied  { name_bind } for  pid=3120 comm="nginx" src=8090 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:unreserved_port_t:s0 tclass=tcp_socket permissive=0
type=AVC msg=audit(1717250030.800:430): avc:  denied  { write } for  pid=4010 comm="mysqld" name="ibdata1" dev="sdb1" ino=70001 scontext=system_u:system_r:mysqld_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0
type=AVC msg=audit(1717250031.900:431): avc:  denied  { write } for  pid=4011 comm="mysqld" name="ib_logfile0" dev="sdb1" ino=70002 scontext=system_u:system_r:mysqld_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0
type=AVC msg=audit(1717250040.010:440): avc:  denied  { getattr } for  pid=5001 comm="sshd" path="/home/deploy/.ssh/authorized_keys" dev="sda1" ino=80001 scontext=system_u:system_r:sshd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0
type=USER_AVC msg=audit(1717250050.120:450): pid=900 uid=81 auid=4294967295 ses=4294967295 msg='avc:  denied  { send_msg } for msgtype=method_call interface=org.freedesktop.DBus scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:system_r:system_dbusd_t:s0 tclass=dbus permissive=0'
type=AVC msg=audit(1717250060.220:460): avc:  denied  { read } for  pid=2099 comm="httpd" name="index.html" dev="sda1" ino=66001 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0
"#
}
