use crate::models::StructuralSkeleton;
use std::net::IpAddr;

/// Preprocessor that extracts static structural skeletons while preserving actual captured variable values.
#[derive(Debug, Default, Clone)]
pub struct StructuralPreprocessor;

impl StructuralPreprocessor {
    pub fn new() -> Self {
        Self
    }

    /// Process a log line into a StructuralSkeleton.
    ///
    /// Preserves BOTH:
    /// - Structural skeleton: e.g. "<VAR> <VAR> logins from device <VAR>"
    /// - Actual captured values: e.g. [("VAR1", "john"), ("VAR2", "Tuesday"), ("VAR3", "6799")]
    pub fn process(&self, raw_line: &str) -> StructuralSkeleton {
        let raw_trimmed = raw_line.trim();
        if raw_trimmed.is_empty() {
            return StructuralSkeleton {
                skeleton: String::new(),
                variables: Vec::new(),
                tokens: Vec::new(),
            };
        }

        let words: Vec<&str> = raw_trimmed.split_whitespace().collect();
        let mut skeleton_tokens = Vec::with_capacity(words.len());
        let mut variables = Vec::new();
        let mut var_idx = 1;

        for word in words {
            // Check if token contains key=value format
            if let Some(eq_pos) = word.find('=') {
                let key = &word[..eq_pos];
                let val = &word[eq_pos + 1..];

                if !val.is_empty() {
                    let var_name = format!("VAR{}", var_idx);
                    var_idx += 1;
                    variables.push((var_name.clone(), val.to_string()));
                    skeleton_tokens.push(format!("{}=<VAR>", key));
                } else {
                    skeleton_tokens.push(word.to_string());
                }
            } else if self.is_variable_candidate(word) {
                let var_name = format!("VAR{}", var_idx);
                var_idx += 1;
                variables.push((var_name.clone(), word.to_string()));
                skeleton_tokens.push("<VAR>".to_string());
            } else {
                skeleton_tokens.push(word.to_string());
            }
        }

        let skeleton = skeleton_tokens.join(" ");

        StructuralSkeleton {
            skeleton,
            variables,
            tokens: skeleton_tokens,
        }
    }

    /// Determine if a word candidate is likely dynamic variable data.
    fn is_variable_candidate(&self, token: &str) -> bool {
        let clean = token.trim_matches(|c| c == '"' || c == '\'' || c == '[' || c == ']' || c == '(' || c == ')' || c == ',');

        if clean.is_empty() {
            return false;
        }

        // 1. IP Address check
        if clean.parse::<IpAddr>().is_ok() {
            return true;
        }

        // 2. Pure integer or decimal number
        if clean.chars().all(|c| c.is_ascii_digit() || c == '.' || c == '-') && clean.chars().any(|c| c.is_ascii_digit()) {
            return true;
        }

        // 3. Hexadecimal / MAC address (e.g. 00:1A:2B:3C:4D:5E or 0x1234)
        if clean.contains(':') && clean.split(':').count() == 6 && clean.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
            return true;
        }
        if clean.starts_with("0x") && clean.len() > 2 && clean[2..].chars().all(|c| c.is_ascii_hexdigit()) {
            return true;
        }

        // 4. ISO-8601 or standard syslog date/timestamp (e.g. 2026-09-18T..., 2026-09-18)
        if clean.len() >= 10 && clean.chars().nth(4) == Some('-') && clean.chars().nth(7) == Some('-') {
            return true;
        }

        // 5. Quoted string token
        if (token.starts_with('"') && token.ends_with('"')) || (token.starts_with('\'') && token.ends_with('\'')) {
            return true;
        }

        // 6. UUID pattern
        if clean.len() == 36 && clean.chars().filter(|&c| c == '-').count() == 4 {
            return true;
        }

        // 7. Dynamic identifiers with digits (e.g. user123, server01, sess_9812)
        if clean.chars().any(|c| c.is_ascii_digit()) && clean.chars().any(|c| c.is_ascii_alphabetic()) {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variable_and_skeleton_preservation() {
        let preproc = StructuralPreprocessor::new();
        let log = "john Tuesday logins from device 6799";
        let res = preproc.process(log);

        assert_eq!(res.skeleton, "john Tuesday logins from device <VAR>");
        assert_eq!(res.variables.len(), 1);
        assert_eq!(res.variables[0], ("VAR1".to_string(), "6799".to_string()));

        let net_log = "SRC=192.168.1.1 DST=10.0.0.2 DPT=443 ACTION=ALLOW";
        let net_res = preproc.process(net_log);
        assert_eq!(net_res.skeleton, "SRC=<VAR> DST=<VAR> DPT=<VAR> ACTION=<VAR>");
        assert_eq!(net_res.variables.len(), 4);
        assert_eq!(net_res.variables[0].1, "192.168.1.1");
        assert_eq!(net_res.variables[1].1, "10.0.0.2");
        assert_eq!(net_res.variables[2].1, "443");
        assert_eq!(net_res.variables[3].1, "ALLOW");
    }
}
