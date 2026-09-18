use aegislog_engine::models::ParserVariant;
use std::collections::HashSet;

/// Historical parser template example retrieved via RAG.
#[derive(Debug, Clone)]
pub struct HistoricalContextExample {
    pub skeleton: String,
    pub variant_name: String,
    pub regex_pattern: String,
    pub field_mappings: Vec<(String, String)>,
    pub similarity: f64,
}

/// RAG retrieval index over validated historical parser knowledge.
///
/// NOTE: The Parser Registry is the authoritative source for validated variants.
/// RAG is strictly a retrieval layer providing few-shot context to the SLM when discovering new variants.
/// RAG NEVER executes parsers.
#[derive(Debug, Default)]
pub struct ParserRagIndex {
    examples: Vec<(String, ParserVariant)>, // (skeleton, variant)
}

impl ParserRagIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Index an approved parser variant from the Parser Registry.
    pub fn index_approved_variant(&mut self, skeleton: &str, variant: ParserVariant) {
        self.examples.push((skeleton.to_string(), variant));
    }

    /// Retrieve the top-k most structurally similar historical examples for a candidate skeleton.
    pub fn retrieve_similar(&self, candidate_skeleton: &str, top_k: usize) -> Vec<HistoricalContextExample> {
        let cand_tokens: HashSet<&str> = candidate_skeleton.split_whitespace().collect();
        if cand_tokens.is_empty() {
            return Vec::new();
        }

        let mut scored: Vec<(f64, &String, &ParserVariant)> = self
            .examples
            .iter()
            .map(|(skel, var)| {
                let skel_tokens: HashSet<&str> = skel.split_whitespace().collect();
                let intersection = cand_tokens.intersection(&skel_tokens).count();
                let union = cand_tokens.union(&skel_tokens).count();
                let similarity = if union > 0 {
                    intersection as f64 / union as f64
                } else {
                    0.0
                };
                (similarity, skel, var)
            })
            .collect();

        // Sort descending by similarity
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        scored
            .into_iter()
            .take(top_k)
            .map(|(similarity, skel, var)| HistoricalContextExample {
                skeleton: skel.clone(),
                variant_name: var.name.clone(),
                regex_pattern: var.regex_pattern.clone(),
                field_mappings: var
                    .field_mappings
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
                similarity,
            })
            .collect()
    }
}
