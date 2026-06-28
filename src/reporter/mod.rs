// SPDX-License-Identifier: Apache-2.0

pub mod html;
pub mod json;
pub mod markdown;
pub mod terminal;

use std::fmt;
use std::str::FromStr;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub enum ReportFormat {
    #[default]
    Terminal,
    Json,
    Html,
    Markdown,
}

impl fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReportFormat::Terminal => write!(f, "terminal"),
            ReportFormat::Json => write!(f, "json"),
            ReportFormat::Html => write!(f, "html"),
            ReportFormat::Markdown => write!(f, "markdown"),
        }
    }
}

impl FromStr for ReportFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "terminal" | "text" | "" => Ok(ReportFormat::Terminal),
            "json" => Ok(ReportFormat::Json),
            "html" => Ok(ReportFormat::Html),
            "markdown" | "md" => Ok(ReportFormat::Markdown),
            _ => Err(format!("Format inconnu: {s}. Utiliser: terminal, json, html, markdown")),
        }
    }
}
