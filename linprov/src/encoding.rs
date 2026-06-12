//! On-disk / on-wire / on-screen representations of untrusted path bytes.
//!
//! Kernel filenames can contain newlines, tabs, `;`, `#`, and other control
//! bytes. Written raw they corrupt the audit-db TSV, the allowlist file,
//! logs, and the control-socket wire (finding #4). Two representations, by
//! purpose:
//!
//! * **base64** — the authoritative, unambiguous, exactly-reversible form.
//!   linprov stores and recovers bytes through it, so there are no escaping
//!   edge cases on the path that feeds hashing/comparison. The audit db keeps
//!   a base64 column it decodes back to the raw bytes; an allowlist value that
//!   isn't safe as plaintext is stored `b64:<base64>`.
//! * **escape** — a best-effort, human-readable form for *display only*
//!   (logs, the tray wire, and the audit db's human column). It is NOT
//!   reversible and is never used to recover bytes for hashing.
//!
//! Hashing is always over the raw bytes (the plain value, or the base64
//! decode), so representation never changes a match result.

use base64::{engine::general_purpose::STANDARD, Engine as _};

/// Best-effort human-readable escaping for display sinks (logs, the wire,
/// the audit db's human column). Neutralizes control bytes so a crafted
/// filename can't forge a log line or desync the tab/newline wire, and makes
/// non-printables visible. NOT reversible — to recover bytes, use base64.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str("\\x");
                out.push(hex((c as u32 >> 4) & 0xf));
                out.push(hex(c as u32 & 0xf));
            }
            c => out.push(c),
        }
    }
    out
}

fn hex(n: u32) -> char {
    char::from_digit(n, 16).unwrap_or('0')
}

/// base64 of the raw bytes — the authoritative, exactly-reversible form.
pub fn b64(s: &str) -> String {
    STANDARD.encode(s.as_bytes())
}

/// Decode base64 back to the raw string. `None` only on corrupt input (our
/// own writer never produces that); callers treat a failure as "skip".
pub fn unb64(s: &str) -> Option<String> {
    STANDARD
        .decode(s.as_bytes())
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// Marker prefix for a base64-encoded allowlist value.
const B64_PREFIX: &str = "b64:";

/// Can `v` NOT be stored as a plain allowlist value? True if it would break
/// the line format or be ambiguous: a control byte / `;` / `#`, leading or
/// trailing whitespace (the parser trims), or a literal `b64:` prefix.
pub fn needs_b64(v: &str) -> bool {
    v != v.trim()
        || v.starts_with(B64_PREFIX)
        || v.bytes().any(|b| b < 0x20 || b == 0x7f || b == b';' || b == b'#')
}

/// Encode an allowlist value: plain when safe (so normal rules stay
/// human-readable and hand-editable), `b64:<base64>` when not. Exact inverse
/// of [`decode_value`].
pub fn encode_value(v: &str) -> String {
    if needs_b64(v) {
        format!("{B64_PREFIX}{}", b64(v))
    } else {
        v.to_string()
    }
}

/// Decode an allowlist value written by [`encode_value`] or hand-typed plain.
/// A `b64:` prefix is base64; anything else is taken literally.
pub fn decode_value(v: &str) -> String {
    match v.strip_prefix(B64_PREFIX) {
        Some(rest) => unb64(rest).unwrap_or_else(|| v.to_string()),
        None => v.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_is_display_only_and_kills_framing_bytes() {
        assert_eq!(escape("plain/path"), "plain/path");
        assert_eq!(escape("a\nb\tc"), "a\\nb\\tc");
        assert_eq!(escape("x\x01y\x7f"), "x\\x01y\\x7f");
        // `;`/`#` are harmless in a log/TSV field — left readable.
        assert_eq!(escape("a;b#c"), "a;b#c");
        for bad in ['\n', '\t', '\r'] {
            assert!(!escape("a\nb\tc\rd").contains(bad));
        }
    }

    #[test]
    fn base64_round_trips_any_string() {
        for s in ["", "/usr/bin/curl", "café/π", "a\nb\t;#\\x", " sp ace "] {
            assert_eq!(unb64(&b64(s)).as_deref(), Some(s));
        }
    }

    #[test]
    fn safe_values_stay_plain() {
        // Common case: readable, editable, no base64, exact round-trip.
        for s in ["/opt/app/bin", "/home/u/My Documents/x", "a=b", "/p/π"] {
            assert_eq!(encode_value(s), s, "{s:?} should stay plain");
            assert_eq!(decode_value(&encode_value(s)), s);
        }
    }

    #[test]
    fn unsafe_values_go_base64_and_round_trip() {
        for s in [
            "a;b", "a#b", "x\ny", "x\ty", " leading", "trailing ", "b64:literal", "ctrl\x01x",
        ] {
            let enc = encode_value(s);
            assert!(enc.starts_with(B64_PREFIX), "{s:?} -> {enc:?}");
            for bad in ['\n', '\t', '\r', ';', '#'] {
                assert!(!enc.contains(bad), "{enc:?} still has {bad:?}");
            }
            assert_eq!(decode_value(&enc), s, "round-trip failed for {s:?}");
        }
    }
}
