use crate::models::ParserVariant;
use std::collections::HashMap;

/// A leaf node in the Bidirectional Pattern Tree.
/// Associated with a structural family and holds an ordered array of validated parser variants.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BptLeafNode {
    pub skeleton_id: String,
    pub skeleton_string: String,
    pub token_count: usize,
    /// Ordered array of parser variants: sorted strictly by Type Specificity (most constrained first).
    pub variants: Vec<ParserVariant>,
}

impl BptLeafNode {
    pub fn new(skeleton_id: impl Into<String>, skeleton_string: impl Into<String>, token_count: usize) -> Self {
        Self {
            skeleton_id: skeleton_id.into(),
            skeleton_string: skeleton_string.into(),
            token_count,
            variants: Vec::new(),
        }
    }

    /// Add a variant and sort variants by Type Specificity (IpAddress > HexMacTime > Integer > GenericString),
    /// using match_count descending as secondary tie-breaker.
    pub fn add_or_update_variant(&mut self, mut variant: ParserVariant) {
        if let Some(existing) = self.variants.iter_mut().find(|v| v.variant_id == variant.variant_id) {
            existing.version += 1;
            existing.regex_pattern = variant.regex_pattern;
            existing.field_mappings = variant.field_mappings;
            existing.field_types = variant.field_types;
            existing.type_constraint = variant.type_constraint;
            existing.is_active = variant.is_active;
            let _ = existing.compile();
        } else {
            let _ = variant.compile();
            self.variants.push(variant);
        }
        self.sort_variants();
    }

    /// Sort variants so more-constrained types are always tried first.
    pub fn sort_variants(&mut self) {
        self.variants.sort_by(|a, b| {
            // Primary: Type constraint descending (IpAddress=4 > Integer=2 > GenericString=1)
            b.type_constraint.cmp(&a.type_constraint)
                // Secondary: Match count descending
                .then_with(|| b.match_count.cmp(&a.match_count))
        });
    }

    /// Get active compatible variants.
    pub fn active_variants(&self) -> impl Iterator<Item = &ParserVariant> {
        self.variants.iter().filter(|v| v.is_active)
    }

    /// Get active compatible variants mutably (for incrementing match count).
    pub fn active_variants_mut(&mut self) -> impl Iterator<Item = &mut ParserVariant> {
        self.variants.iter_mut().filter(|v| v.is_active)
    }
}

/// Internal tree node for bidirectional pattern matching.
#[derive(Debug, Default)]
struct BptInternalNode {
    /// Branches indexed by (prefix_token, suffix_token)
    children: HashMap<(String, String), BptInternalNode>,
    /// Leaf node if this branch terminates a known skeleton
    leaf: Option<BptLeafNode>,
}

/// Bidirectional Pattern Tree (BDPT)
/// Matches tokens simultaneously from prefix (head) and suffix (tail) inward.
/// This prevents early-variable degradation (e.g. variable at token 0 or 1).
#[derive(Debug, Default)]
pub struct BidirectionalPatternTree {
    root: BptInternalNode,
    total_skeletons: usize,
}

impl BidirectionalPatternTree {
    pub fn new() -> Self {
        Self {
            root: BptInternalNode::default(),
            total_skeletons: 0,
        }
    }

    /// Insert a structural skeleton and its initial variant into the BDPT.
    pub fn insert(&mut self, skeleton: &str, variant: Option<ParserVariant>) -> &mut BptLeafNode {
        let tokens: Vec<&str> = skeleton.split_whitespace().collect();
        let token_count = tokens.len();

        let mut curr = &mut self.root;
        let mut left = 0;
        let mut right = token_count.saturating_sub(1);

        while left <= right {
            let prefix = tokens[left].to_string();
            let suffix = tokens[right].to_string();
            let key = (prefix, suffix);

            curr = curr.children.entry(key).or_default();

            if left == right {
                break;
            }
            left += 1;
            if right > 0 {
                right -= 1;
            } else {
                break;
            }
        }

        if curr.leaf.is_none() {
            self.total_skeletons += 1;
            let skeleton_id = format!("bpt_skel_{}", self.total_skeletons);
            curr.leaf = Some(BptLeafNode::new(skeleton_id, skeleton, token_count));
        }

        let leaf = curr.leaf.as_mut().unwrap();
        if let Some(v) = variant {
            leaf.add_or_update_variant(v);
        }
        leaf
    }

    /// Match a log line's structural tokens against the BDPT simultaneously from head and tail inward.
    pub fn match_tokens(&self, tokens: &[String]) -> Option<&BptLeafNode> {
        let token_count = tokens.len();
        if token_count == 0 {
            return None;
        }

        let mut curr = &self.root;
        let mut left = 0;
        let mut right = token_count.saturating_sub(1);

        while left <= right {
            let prefix = &tokens[left];
            let suffix = &tokens[right];

            // 1. Try exact (prefix, suffix) token match
            let key = (prefix.clone(), suffix.clone());
            if let Some(next) = curr.children.get(&key) {
                curr = next;
            } else {
                // 2. Try wildcard matches if exact match is not found
                // Case: prefix exact, suffix wildcard <VAR>
                let key_var_suf = (prefix.clone(), "<VAR>".to_string());
                // Case: prefix wildcard <VAR>, suffix exact
                let key_var_pre = ("<VAR>".to_string(), suffix.clone());
                // Case: both wildcards
                let key_var_both = ("<VAR>".to_string(), "<VAR>".to_string());

                if let Some(next) = curr.children.get(&key_var_suf) {
                    curr = next;
                } else if let Some(next) = curr.children.get(&key_var_pre) {
                    curr = next;
                } else if let Some(next) = curr.children.get(&key_var_both) {
                    curr = next;
                } else {
                    return None;
                }
            }

            if left == right {
                break;
            }
            left += 1;
            if right > 0 {
                right -= 1;
            } else {
                break;
            }
        }

        curr.leaf.as_ref()
    }

    /// Match mutably to allow incrementing match counts or updating leaf variants.
    pub fn match_tokens_mut(&mut self, tokens: &[String]) -> Option<&mut BptLeafNode> {
        let token_count = tokens.len();
        if token_count == 0 {
            return None;
        }

        let mut curr = &mut self.root;
        let mut left = 0;
        let mut right = token_count.saturating_sub(1);

        while left <= right {
            let prefix = tokens[left].clone();
            let suffix = tokens[right].clone();

            // Try exact or wildcard branches
            let key = (prefix.clone(), suffix.clone());
            let has_exact = curr.children.contains_key(&key);
            let has_var_suf = curr.children.contains_key(&(prefix.clone(), "<VAR>".to_string()));
            let has_var_pre = curr.children.contains_key(&("<VAR>".to_string(), suffix.clone()));
            let has_var_both = curr.children.contains_key(&("<VAR>".to_string(), "<VAR>".to_string()));

            let chosen_key = if has_exact {
                key
            } else if has_var_suf {
                (prefix, "<VAR>".to_string())
            } else if has_var_pre {
                ("<VAR>".to_string(), suffix)
            } else if has_var_both {
                ("<VAR>".to_string(), "<VAR>".to_string())
            } else {
                return None;
            };

            curr = curr.children.get_mut(&chosen_key)?;

            if left == right {
                break;
            }
            left += 1;
            if right > 0 {
                right -= 1;
            } else {
                break;
            }
        }

        curr.leaf.as_mut()
    }

    pub fn total_skeletons(&self) -> usize {
        self.total_skeletons
    }

    pub fn list_all_leaves(&self) -> Vec<BptLeafNode> {
        let mut leaves = Vec::new();
        Self::collect_leaves(&self.root, &mut leaves);
        leaves
    }

    fn collect_leaves(node: &BptInternalNode, leaves: &mut Vec<BptLeafNode>) {
        if let Some(ref leaf) = node.leaf {
            leaves.push(leaf.clone());
        }
        for child in node.children.values() {
            Self::collect_leaves(child, leaves);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::TypeConstraint;

    #[test]
    fn test_bdpt_bidirectional_early_variable() {
        let mut tree = BidirectionalPatternTree::new();
        // Skeleton with early variable at position 0:
        // "<VAR> Tuesday logins from device <VAR>"
        let skel = "<VAR> Tuesday logins from device <VAR>";
        tree.insert(skel, None);

        // Tokens: ["john", "Tuesday", "logins", "from", "device", "6799"]
        let tokens: Vec<String> = vec![
            "<VAR>".to_string(),
            "Tuesday".to_string(),
            "logins".to_string(),
            "from".to_string(),
            "device".to_string(),
            "<VAR>".to_string(),
        ];

        let matched = tree.match_tokens(&tokens);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().skeleton_string, skel);
    }

    #[test]
    fn test_polymorphic_variant_ordering() {
        let mut leaf = BptLeafNode::new("skel_1", "<VAR> accessed <VAR>", 3);

        // Add generic string variant
        let v_generic = ParserVariant::new(
            "v_generic",
            "Generic Variant",
            r"^(?P<user>\S+) accessed (?P<target>\S+)$",
            HashMap::from([("user".into(), "actor.user.name".into()), ("target".into(), "message".into())]),
            HashMap::from([("user".into(), "string".into()), ("target".into(), "string".into())]),
            TypeConstraint::GenericString,
        ).unwrap();

        // Add IP specific variant
        let v_ip = ParserVariant::new(
            "v_ip",
            "IP Variant",
            r"^(?P<ip>\d+\.\d+\.\d+\.\d+) accessed (?P<target>\S+)$",
            HashMap::from([("ip".into(), "src_endpoint.ip".into()), ("target".into(), "message".into())]),
            HashMap::from([("ip".into(), "ip".into()), ("target".into(), "string".into())]),
            TypeConstraint::IpAddress,
        ).unwrap();

        leaf.add_or_update_variant(v_generic);
        leaf.add_or_update_variant(v_ip);

        // IpAddress variant MUST be first in the array!
        assert_eq!(leaf.variants[0].variant_id, "v_ip");
        assert_eq!(leaf.variants[1].variant_id, "v_generic");
    }
}
