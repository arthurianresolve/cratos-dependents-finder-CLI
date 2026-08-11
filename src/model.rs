use std::fmt::{self, Write as _};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CrateSummary {
    pub name: String,
    pub max_version: String,
    pub repository: Option<String>,
    pub homepage: Option<String>,
    pub description: Option<String>,
    pub downloads: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RankedCrate {
    #[serde(flatten)]
    pub crate_info: CrateSummary,
    pub score: f64,
    pub match_reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResolutionResult {
    pub input: String,
    pub selected: Option<RankedCrate>,
    pub alternatives: Vec<RankedCrate>,
    pub resolution_method: String,
    pub requires_selection: bool,
    pub globally_exhaustive: bool,
    #[serde(default)]
    pub diagnostics: Vec<String>,
}

impl ResolutionResult {
    pub fn selected_name(&self) -> anyhow::Result<&str> {
        self.selected
            .as_ref()
            .map(|candidate| candidate.crate_info.name.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "target is ambiguous; pass an exact crate name, --crate-name, or --accept-closest"
                )
            })
    }

    pub fn repository(&self) -> Option<&str> {
        self.selected
            .as_ref()
            .and_then(|candidate| candidate.crate_info.repository.as_deref())
    }
}

impl fmt::Display for ResolutionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "input: {}", self.input)?;
        writeln!(f, "resolution: {}", self.resolution_method)?;
        if let Some(selected) = &self.selected {
            writeln!(
                f,
                "selected: {} {} (score {:.3}, {})",
                selected.crate_info.name,
                selected.crate_info.max_version,
                selected.score,
                selected.match_reason
            )?;
            if let Some(repository) = &selected.crate_info.repository {
                writeln!(f, "repository: {repository}")?;
            }
        } else {
            writeln!(f, "selected: none (explicit selection required)")?;
        }

        if !self.alternatives.is_empty() {
            writeln!(f, "alternatives:")?;
            for candidate in &self.alternatives {
                let mut line = String::new();
                write!(
                    line,
                    "  - {} {} (score {:.3}, {})",
                    candidate.crate_info.name,
                    candidate.crate_info.max_version,
                    candidate.score,
                    candidate.match_reason
                )?;
                if let Some(repository) = &candidate.crate_info.repository {
                    write!(line, " {repository}")?;
                }
                writeln!(f, "{line}")?;
            }
        }
        for diagnostic in &self.diagnostics {
            writeln!(f, "diagnostic: {diagnostic}")?;
        }
        writeln!(f, "globally_exhaustive: false")
    }
}
