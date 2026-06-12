//! Reversible escaping for untrusted path bytes that land in line- or
//! field-structured text: the audit-db TSV, the allowlist file, log lines,
//! and the tab-separated control-socket wire.
//!
//! Kernel filenames may contain newlines, tabs, `;`, `#`, and other control
//! bytes. Written raw they corrupt those formats — injecting audit-db rows,
//! forging journal lines, breaking or injecting allowlist rules (finding
//! #4). [`escape`] neutralizes them; [`unescape`] is its exact inverse.
//!
//! Crucially the FNV hashes that gate enforcement are always computed over
//! the **raw** string, never the escaped form: the allowlist parser and the
//! audit-db loader `unescape` back to raw before anything hashes, so a value
//! round-trips byte-for-byte and escaping never changes a match result. Only
//! the on-disk / on-wire / on-screen *representation* is escaped.

/// Escape `\`, the format metacharacters `;` and `#`, and control bytes so
/// the result is safe on a single TSV field, a single allowlist line, a log
/// line, and the tab-separated wire. `\n`/`\r`/`\t` get readable named
/// escapes; `;`/`#`/other C0 controls and DEL use `\xHH`. Printable ASCII
/// and all multi-byte UTF-8 pass through unchanged.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ';' | '#' => push_hex(&mut out, c as u32),
            c if (c as u32) < 0x20 || c == '\u{7f}' => push_hex(&mut out, c as u32),
            c => out.push(c),
        }
    }
    out
}

/// Inverse of [`escape`]. Lenient on malformed input (an unknown `\x`
/// sequence, or a lone `\` before some other byte, is kept literally) so a
/// pre-existing path with a bare backslash in an older db/allowlist still
/// round-trips rather than getting mangled.
pub fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('x') => {
                let hi = chars.next();
                let lo = chars.next();
                match (hi.and_then(|c| c.to_digit(16)), lo.and_then(|c| c.to_digit(16))) {
                    (Some(h), Some(l)) => out.push(((h << 4 | l) as u8) as char),
                    _ => {
                        // Malformed \x — keep the bytes we consumed, literally.
                        out.push_str("\\x");
                        if let Some(c) = hi {
                            out.push(c);
                        }
                        if let Some(c) = lo {
                            out.push(c);
                        }
                    }
                }
            }
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'), // trailing backslash
        }
    }
    out
}

fn push_hex(out: &mut String, b: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push('\\');
    out.push('x');
    out.push(HEX[((b >> 4) & 0xf) as usize] as char);
    out.push(HEX[(b & 0xf) as usize] as char);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for s in [
            "",
            "/usr/bin/curl",
            "/home/u/Downloads/inst.sh",
            "café/naïve/π", // multi-byte UTF-8 untouched
            "a;b",
            "a#b",
            "a=b",
            "line1\nline2",
            "tab\there",
            "back\\slash",
            "carriage\rreturn",
            "\x01\x02\x1f\x7f",
            "/x\n;#\t\\mix",
        ] {
            assert_eq!(unescape(&escape(s)), s, "round-trip failed for {s:?}");
        }
    }

    #[test]
    fn escaped_form_has_no_structural_bytes() {
        // The whole point: an escaped value can't break a line/field format.
        let e = escape("a\nb\tc;d#e\rf");
        for bad in ['\n', '\t', '\r', ';', '#'] {
            assert!(!e.contains(bad), "escaped {e:?} still contains {bad:?}");
        }
    }

    #[test]
    fn known_encodings() {
        assert_eq!(escape("a\nb"), "a\\nb");
        assert_eq!(escape("a;b"), "a\\x3bb");
        assert_eq!(escape("a#b"), "a\\x23b");
        assert_eq!(escape("a\\b"), "a\\\\b");
        assert_eq!(escape("plain/path"), "plain/path");
    }

    #[test]
    fn unescape_is_lenient_on_bare_backslash() {
        // An older allowlist/db could hold a literal backslash path.
        assert_eq!(unescape("/weird\\path"), "/weird\\path");
    }
}
