use crate::models::ParserVariant;
use std::collections::HashMap;

/// Versioned record in the authoritative Parser Registry.
#[derive(Debug, Clone)]
pub struct RegistryEntry {
    pub variant: ParserVariant,
    pub skeleton_link: String,
    pub previous_versions: Vec<ParserVariant>,
}

/// The authoritative Parser Registry.
/// Owns versioned, validated parser specifications, supports activation/deactivation,
/// versioning, rollback, and links directly to BPT structural skeletons.
#[derive(Debug, Default)]
pub struct ParserRegistry {
    entries: HashMap<String, RegistryEntry>, // variant_id -> RegistryEntry
    skeleton_to_variants: HashMap<String, Vec<String>>, // skeleton -> list of variant_ids
}

impl ParserRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register or update a validated parser variant linked to a structural skeleton.
    pub fn register_variant(&mut self, skeleton: &str, variant: ParserVariant) {
        let variant_id = variant.variant_id.clone();
        let skeleton_str = skeleton.to_string();

        if let Some(entry) = self.entries.get_mut(&variant_id) {
            // Save current version for rollback
            entry.previous_versions.push(entry.variant.clone());
            entry.variant = variant;
            entry.variant.version = (entry.previous_versions.len() as u32) + 1;
            entry.skeleton_link = skeleton_str.clone();
        } else {
            let entry = RegistryEntry {
                variant,
                skeleton_link: skeleton_str.clone(),
                previous_versions: Vec::new(),
            };
            self.entries.insert(variant_id.clone(), entry);
        }

        let variant_list = self.skeleton_to_variants.entry(skeleton_str).or_default();
        if !variant_list.contains(&variant_id) {
            variant_list.push(variant_id);
        }
    }

    /// Retrieve active variants for a structural skeleton.
    pub fn get_variants_for_skeleton(&self, skeleton: &str) -> Vec<&ParserVariant> {
        if let Some(var_ids) = self.skeleton_to_variants.get(skeleton) {
            let mut list: Vec<&ParserVariant> = var_ids
                .iter()
                .filter_map(|id| self.entries.get(id))
                .map(|entry| &entry.variant)
                .filter(|v| v.is_active)
                .collect();
            list.sort_by(|a, b| {
                b.type_constraint.cmp(&a.type_constraint)
                    .then_with(|| b.match_count.cmp(&a.match_count))
            });
            list
        } else {
            Vec::new()
        }
    }

    /// Deactivate a variant (e.g. if flagged during operations).
    pub fn deactivate_variant(&mut self, variant_id: &str) -> bool {
        if let Some(entry) = self.entries.get_mut(variant_id) {
            entry.variant.is_active = false;
            true
        } else {
            false
        }
    }

    /// Roll back a variant to its previous active version.
    pub fn rollback_variant(&mut self, variant_id: &str) -> bool {
        if let Some(entry) = self.entries.get_mut(variant_id) {
            if let Some(prev) = entry.previous_versions.pop() {
                entry.variant = prev;
                entry.variant.is_active = true;
                return true;
            }
        }
        false
    }

    /// Get a specific variant by ID.
    pub fn get_variant(&self, variant_id: &str) -> Option<&ParserVariant> {
        self.entries.get(variant_id).map(|e| &e.variant)
    }

    /// Get all active entries for RAG indexing or dashboard inspection.
    pub fn list_all_active(&self) -> Vec<(&String, &ParserVariant)> {
        self.entries
            .values()
            .filter(|e| e.variant.is_active)
            .map(|e| (&e.skeleton_link, &e.variant))
            .collect()
    }

    /// Total registered variants.
    pub fn total_count(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::TypeConstraint;

    #[test]
    fn test_registry_versioning_and_rollback() {
        let mut registry = ParserRegistry::new();
        let skel = "SRC=<VAR> DST=<VAR>";

        let v1 = ParserVariant::new(
            "var_1",
            "Firewall V1",
            r"SRC=(?P<src>\S+) DST=(?P<dst>\S+)",
            HashMap::from([("src".into(), "src_endpoint.ip".into()), ("dst".into(), "dst_endpoint.ip".into())]),
            HashMap::from([("src".into(), "ip".into()), ("dst".into(), "ip".into())]),
            TypeConstraint::IpAddress,
        ).unwrap();

        registry.register_variant(skel, v1);
        assert_eq!(registry.get_variant("var_1").unwrap().version, 1);

        // Update with v2
        let mut v2 = registry.get_variant("var_1").unwrap().clone();
        v2.name = "Firewall V2 Updated".to_string();
        registry.register_variant(skel, v2);
        assert_eq!(registry.get_variant("var_1").unwrap().version, 2);
        assert_eq!(registry.get_variant("var_1").unwrap().name, "Firewall V2 Updated");

        // Rollback to v1
        assert!(registry.rollback_variant("var_1"));
        assert_eq!(registry.get_variant("var_1").unwrap().name, "Firewall V1");
        assert_eq!(registry.get_variant("var_1").unwrap().version, 1);
    }
}
