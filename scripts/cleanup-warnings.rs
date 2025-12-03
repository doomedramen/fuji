#!/usr/bin/env rust-script

//! Comprehensive Rust Warning Cleanup Script
//!
//! This script parses cargo check output to identify and suggest fixes for:
//! - Unused imports
//! - Unused variables
//! - Dead code warnings
//! - Fields that are never read
//! - Methods that are never used
//!
//! Usage: cargo run --bin cleanup-warnings OR ./cleanup-warnings.rs

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Warning {
    pub warning_type: WarningType,
    pub file_path: PathBuf,
    pub line_number: usize,
    pub column_number: usize,
    pub item_name: String,
    pub full_message: String,
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WarningType {
    UnusedImport,
    UnusedVariable,
    DeadCode,
    UnusedField,
    UnusedMethod,
    UnusedFunction,
    UnusedStruct,
    UnusedEnum,
    UnusedTrait,
    UnusedAssignment,
    UnusedMut,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FixSuggestion {
    pub file_path: PathBuf,
    pub line_number: usize,
    pub original_line: String,
    pub suggested_line: String,
    pub fix_type: FixType,
    pub confidence: f32,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum FixType {
    RemoveLine,
    PrefixUnderscore,
    RemoveImport,
    AddAllowDeadCode,
    ConvertToComment,
}

pub struct WarningAnalyzer {
    warnings: Vec<Warning>,
    fixes: Vec<FixSuggestion>,
    file_contents: HashMap<PathBuf, String>,
}

impl WarningAnalyzer {
    pub fn new() -> Self {
        Self {
            warnings: Vec::new(),
            fixes: Vec::new(),
            file_contents: HashMap::new(),
        }
    }

    /// Run cargo check and parse the output
    pub fn analyze_cargo_warnings(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Running cargo check to identify warnings...");

        let output = Command::new("cargo")
            .args(&["check", "--color", "never"])
            .output()
            .expect("Failed to execute cargo check");

        if !output.status.success() && output.stderr.len() > 0 {
            let stderr_str = String::from_utf8_lossy(&output.stderr);
            if stderr_str.contains("error:") {
                println!("Compilation errors found. Cannot proceed with warning analysis.");
                return Err("Compilation errors detected".into());
            }
        }

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let stderr_str = String::from_utf8_lossy(&output.stderr);

        // Warnings often go to stderr, so check both outputs
        if stdout_str.is_empty() && !stderr_str.is_empty() {
            self.parse_cargo_output(&stderr_str)?;
        } else {
            self.parse_cargo_output(&stdout_str)?;
        }

        println!("Found {} warnings", self.warnings.len());
        Ok(())
    }

    /// Parse cargo check output for various warning types
    fn parse_cargo_output(&mut self, output: &str) -> Result<(), Box<dyn std::error::Error>> {
        let lines: Vec<&str> = output.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if line.starts_with("warning:") {
                let warning_line = line;

                // Look for the file location line (usually next line)
                if i + 1 < lines.len() {
                    let location_line = lines[i + 1];
                    if location_line.contains("-->") {
                        self.parse_warning_pair(warning_line, location_line, output)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Parse a warning line and its location line
    fn parse_warning_pair(&mut self, warning_line: &str, location_line: &str, full_output: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Extract file path and line/column numbers
        let location_regex = Regex::new(r"--> ([^:]+):(\d+):(\d+)")?;
        if let Some(caps) = location_regex.captures(location_line) {
            let file_path = PathBuf::from(caps.get(1).unwrap().as_str());
            let line_number = caps.get(2).unwrap().as_str().parse::<usize>()?;
            let column_number = caps.get(3).unwrap().as_str().parse::<usize>()?;

            // Only process src/ directory files
            if !file_path.to_string_lossy().starts_with("src") {
                return Ok(());
            }

            let warning = self.create_warning_from_text(warning_line, &file_path, line_number, column_number, full_output)?;
            if let Some(w) = warning {
                self.warnings.push(w);
            }
        }

        Ok(())
    }

    /// Create a warning from parsed text
    fn create_warning_from_text(&self, warning_line: &str, file_path: &Path, line_number: usize, column_number: usize, full_output: &str) -> Result<Option<Warning>, Box<dyn std::error::Error>> {
        let (warning_type, item_name) = if warning_line.contains("unused import:") {
            let import_regex = Regex::new(r"unused import: `([^`]+)`")?;
            if let Some(caps) = import_regex.captures(warning_line) {
                (WarningType::UnusedImport, caps.get(1).unwrap().as_str().to_string())
            } else {
                return Ok(None);
            }
        } else if warning_line.contains("unused variable:") {
            let var_regex = Regex::new(r"unused variable: `([^`]+)`")?;
            if let Some(caps) = var_regex.captures(warning_line) {
                (WarningType::UnusedVariable, caps.get(1).unwrap().as_str().to_string())
            } else {
                return Ok(None);
            }
        } else if warning_line.contains("is never used") {
            let dead_code_regex = Regex::new(r"(function|method|struct|enum|trait) `([^`]+)` is never used")?;
            if let Some(caps) = dead_code_regex.captures(warning_line) {
                let code_type = caps.get(1).unwrap().as_str();
                let item_name = caps.get(2).unwrap().as_str().to_string();
                let warning_type = match code_type {
                    "function" => WarningType::UnusedFunction,
                    "method" => WarningType::UnusedMethod,
                    "struct" => WarningType::UnusedStruct,
                    "enum" => WarningType::UnusedEnum,
                    "trait" => WarningType::UnusedTrait,
                    _ => WarningType::DeadCode,
                };
                (warning_type, item_name)
            } else {
                return Ok(None);
            }
        } else if warning_line.contains("field") && warning_line.contains("is never read") {
            let field_regex = Regex::new(r"field `([^`]+)` is never read")?;
            if let Some(caps) = field_regex.captures(warning_line) {
                (WarningType::UnusedField, caps.get(1).unwrap().as_str().to_string())
            } else {
                return Ok(None);
            }
        } else if warning_line.contains("value assigned to") && warning_line.contains("is never read") {
            let assignment_regex = Regex::new(r"value assigned to `([^`]+)` is never read")?;
            if let Some(caps) = assignment_regex.captures(warning_line) {
                (WarningType::UnusedAssignment, caps.get(1).unwrap().as_str().to_string())
            } else {
                return Ok(None);
            }
        } else if warning_line.contains("variable does not need to be mutable") {
            (WarningType::UnusedMut, String::new())
        } else {
            return Ok(None);
        };

        Ok(Some(Warning {
            warning_type,
            file_path: file_path.to_path_buf(),
            line_number,
            column_number,
            item_name,
            full_message: self.extract_full_message(full_output, warning_line),
            suggestion: None,
        }))
    }

    
    /// Extract the full warning message from output
    fn extract_full_message(&self, full_output: &str, match_str: &str) -> String {
        let lines: Vec<&str> = full_output.lines().collect();
        let match_line = match_str.lines().next().unwrap_or("");

        // Find the line in the full output
        if let Some(pos) = lines.iter().position(|&l| l.starts_with(match_line)) {
            // Return the warning line and any following help/note lines
            let mut message_lines = Vec::new();
            message_lines.push(lines[pos]);

            // Add related help/note lines
            for i in (pos + 1)..lines.len() {
                if lines[i].starts_with("   |") || lines[i].starts_with("   =") || lines[i].starts_with("   help:") {
                    message_lines.push(lines[i]);
                } else if lines[i].trim().is_empty() || lines[i].starts_with("warning:") {
                    break;
                }
            }

            message_lines.join("\n")
        } else {
            match_str.to_string()
        }
    }

    /// Load file contents for analysis (src/ directory only)
    pub fn load_file_contents(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let src_path = Path::new("src");

        if !src_path.exists() {
            return Err("src/ directory not found".into());
        }

        println!("Loading Rust source files from src/ directory...");
        self.load_files_recursive(src_path)?;

        println!("Loaded {} source files", self.file_contents.len());
        Ok(())
    }

    /// Recursively load .rs files from a directory
    fn load_files_recursive(&mut self, dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                self.load_files_recursive(&path)?;
            } else if path.extension().map_or(false, |ext| ext == "rs") {
                let content = fs::read_to_string(&path)?;
                self.file_contents.insert(path, content);
            }
        }
        Ok(())
    }

    /// Generate fix suggestions for all warnings
    pub fn generate_fixes(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Generating fix suggestions...");

        for warning in &self.warnings.clone() {
            // Only process files in src/ directory
            if !warning.file_path.to_string_lossy().starts_with("src") {
                continue;
            }

            if let Some(content) = self.file_contents.get(&warning.file_path) {
                let fixes = self.generate_fixes_for_warning(warning, content)?;
                self.fixes.extend(fixes);
            }
        }

        println!("Generated {} fix suggestions", self.fixes.len());
        Ok(())
    }

    /// Generate fixes for a specific warning
    fn generate_fixes_for_warning(&self, warning: &Warning, file_content: &str) -> Result<Vec<FixSuggestion>, Box<dyn std::error::Error>> {
        let mut fixes = Vec::new();
        let lines: Vec<&str> = file_content.lines().collect();

        if warning.line_number == 0 || warning.line_number > lines.len() {
            return Ok(fixes);
        }

        let line_index = warning.line_number - 1;
        let current_line = lines[line_index];

        match &warning.warning_type {
            WarningType::UnusedImport => {
                fixes.push(self.generate_unused_import_fix(warning, current_line)?);
            },
            WarningType::UnusedVariable => {
                fixes.push(self.generate_unused_variable_fix(warning, current_line)?);
            },
            WarningType::DeadCode | WarningType::UnusedFunction | WarningType::UnusedMethod |
            WarningType::UnusedStruct | WarningType::UnusedEnum | WarningType::UnusedTrait => {
                fixes.push(self.generate_dead_code_fix(warning, current_line)?);
            },
            WarningType::UnusedField => {
                fixes.push(self.generate_unused_field_fix(warning, current_line)?);
            },
            WarningType::UnusedAssignment => {
                fixes.push(self.generate_unused_assignment_fix(warning, current_line)?);
            },
            WarningType::UnusedMut => {
                fixes.push(self.generate_unused_mut_fix(warning, current_line)?);
            },
        }

        Ok(fixes)
    }

    /// Generate fix for unused import
    fn generate_unused_import_fix(&self, warning: &Warning, line: &str) -> Result<FixSuggestion, Box<dyn std::error::Error>> {
        let suggested_line = self.remove_import_from_use(line, &warning.item_name)?;
        let fix_type = if suggested_line.trim().is_empty() { FixType::RemoveLine } else { FixType::RemoveImport };

        Ok(FixSuggestion {
            file_path: warning.file_path.clone(),
            line_number: warning.line_number,
            original_line: line.to_string(),
            suggested_line,
            fix_type,
            confidence: 0.9,
        })
    }

    /// Remove an import from a use statement
    fn remove_import_from_use(&self, use_line: &str, import_to_remove: &str) -> Result<String, Box<dyn std::error::Error>> {
        let line = use_line.trim();

        // Handle simple use statements: use std::path::Path;
        if line.starts_with("use ") && !line.contains("{") {
            return Ok(String::new());
        }

        // Handle use statements with braces: use std::path::{Path, PathBuf};
        if line.contains("{") {
            let re = Regex::new(r"use[^{]+\{([^}]+)\}")?;
            if let Some(caps) = re.captures(line) {
                let imports_str = caps.get(1).unwrap().as_str();
                let imports: Vec<&str> = imports_str.split(',').map(|s| s.trim()).collect();

                let remaining_imports: Vec<&str> = imports
                    .iter()
                    .filter(|&&import| {
                        import != import_to_remove
                    })
                    .copied()
                    .collect();

                if remaining_imports.is_empty() {
                    return Ok(String::new());
                }

                let before_brace = line.split('{').next().unwrap_or("").trim_end();
                return Ok(format!("{}{{{}}}", before_brace, remaining_imports.join(", ")));
            }
        }

        Ok(String::new())
    }

    /// Generate fix for unused variable
    fn generate_unused_variable_fix(&self, warning: &Warning, line: &str) -> Result<FixSuggestion, Box<dyn std::error::Error>> {
        let suggested_line = line.replace(&format!(" {}", warning.item_name), &format!(" _{}", warning.item_name));
        let suggested_line = suggested_line.replace(&warning.item_name, &format!("_{}", warning.item_name));

        Ok(FixSuggestion {
            file_path: warning.file_path.clone(),
            line_number: warning.line_number,
            original_line: line.to_string(),
            suggested_line,
            fix_type: FixType::PrefixUnderscore,
            confidence: 0.8,
        })
    }

    /// Generate fix for dead code
    fn generate_dead_code_fix(&self, warning: &Warning, line: &str) -> Result<FixSuggestion, Box<dyn std::error::Error>> {
        let suggested_line = if line.trim().starts_with("pub ") {
            line.replace("pub ", "#[allow(dead_code)]\npub ")
        } else {
            format!("#[allow(dead_code)]\n{}", line)
        };

        Ok(FixSuggestion {
            file_path: warning.file_path.clone(),
            line_number: warning.line_number,
            original_line: line.to_string(),
            suggested_line,
            fix_type: FixType::AddAllowDeadCode,
            confidence: 0.7,
        })
    }

    /// Generate fix for unused field
    fn generate_unused_field_fix(&self, warning: &Warning, line: &str) -> Result<FixSuggestion, Box<dyn std::error::Error>> {
        let suggested_line = if line.contains("pub ") {
            line.replace(&format!("pub {}", warning.item_name), &format!("pub _{}", warning.item_name))
        } else {
            line.replace(&warning.item_name, &format!("_{}", warning.item_name))
        };

        Ok(FixSuggestion {
            file_path: warning.file_path.clone(),
            line_number: warning.line_number,
            original_line: line.to_string(),
            suggested_line,
            fix_type: FixType::PrefixUnderscore,
            confidence: 0.8,
        })
    }

    /// Generate fix for unused assignment
    fn generate_unused_assignment_fix(&self, warning: &Warning, line: &str) -> Result<FixSuggestion, Box<dyn std::error::Error>> {
        let suggested_line = line.replace(&format!("let {}", warning.item_name), &format!("let _{}", warning.item_name));

        Ok(FixSuggestion {
            file_path: warning.file_path.clone(),
            line_number: warning.line_number,
            original_line: line.to_string(),
            suggested_line,
            fix_type: FixType::PrefixUnderscore,
            confidence: 0.8,
        })
    }

    /// Generate fix for unnecessary mut
    fn generate_unused_mut_fix(&self, warning: &Warning, line: &str) -> Result<FixSuggestion, Box<dyn std::error::Error>> {
        // Extract variable name from the line containing "let mut"
        let re = Regex::new(r"let mut (\w+)")?;
        let var_name = if let Some(caps) = re.captures(line) {
            caps.get(1).unwrap().as_str().to_string()
        } else {
            String::new()
        };

        let suggested_line = line.replace(&format!("let mut {}", var_name), &format!("let {}", var_name));

        Ok(FixSuggestion {
            file_path: warning.file_path.clone(),
            line_number: warning.line_number,
            original_line: line.to_string(),
            suggested_line,
            fix_type: FixType::PrefixUnderscore,
            confidence: 0.9,
        })
    }

    
    /// Apply all fixes to files
    pub fn apply_fixes(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Applying {} fix suggestions...", self.fixes.len());

        // Group fixes by file
        let mut file_fixes: HashMap<PathBuf, Vec<&FixSuggestion>> = HashMap::new();
        for fix in &self.fixes {
            file_fixes.entry(fix.file_path.clone()).or_insert_with(Vec::new).push(fix);
        }

        for (file_path, fixes) in file_fixes {
            self.apply_fixes_to_file(&file_path, &fixes)?;
        }

        Ok(())
    }

    /// Apply fixes to a specific file
    fn apply_fixes_to_file(&self, file_path: &Path, fixes: &[&FixSuggestion]) -> Result<(), Box<dyn std::error::Error>> {
        let content = fs::read_to_string(file_path)?;
        let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();

        // Sort fixes by line number in descending order to avoid shifting indices
        let mut sorted_fixes: Vec<&&FixSuggestion> = fixes.iter().collect();
        sorted_fixes.sort_by(|a, b| b.line_number.cmp(&a.line_number));

        for fix in sorted_fixes {
            if fix.line_number == 0 || fix.line_number > lines.len() {
                continue;
            }

            let line_index = fix.line_number - 1;

            match &fix.fix_type {
                FixType::RemoveLine => {
                    lines.remove(line_index);
                },
                FixType::RemoveImport => {
                    if fix.suggested_line.trim().is_empty() {
                        lines.remove(line_index);
                    } else {
                        lines[line_index] = fix.suggested_line.clone();
                    }
                },
                FixType::PrefixUnderscore | FixType::AddAllowDeadCode | FixType::ConvertToComment => {
                    lines[line_index] = fix.suggested_line.clone();
                },
            }
        }

        // Write the modified content back to the file
        fs::write(file_path, lines.join("\n") + "\n")?;
        println!("Applied {} fixes to {}", fixes.len(), file_path.display());

        Ok(())
    }

    /// Print a summary of findings and suggestions
    pub fn print_summary(&self) {
        println!("\n=== Warning Analysis Summary ===");

        let mut warning_counts = HashMap::new();
        for warning in &self.warnings {
            *warning_counts.entry(format!("{:?}", warning.warning_type)).or_insert(0) += 1;
        }

        println!("\nWarning Types Found:");
        for (warning_type, count) in &warning_counts {
            println!("  {}: {}", warning_type, count);
        }

        println!("\nTop Files with Warnings:");
        let mut file_counts = HashMap::new();
        for warning in &self.warnings {
            *file_counts.entry(&warning.file_path).or_insert(0) += 1;
        }

        let mut sorted_files: Vec<_> = file_counts.iter().collect();
        sorted_files.sort_by(|a, b| b.1.cmp(a.1));

        for (file_path, count) in sorted_files.iter().take(10) {
            println!("  {}: {} warnings", file_path.display(), count);
        }

        println!("\n=== Fix Suggestions ===");
        println!("Total fix suggestions: {}", self.fixes.len());

        let mut fix_counts = HashMap::new();
        for fix in &self.fixes {
            *fix_counts.entry(format!("{:?}", fix.fix_type)).or_insert(0) += 1;
        }

        println!("\nFix Types:");
        for (fix_type, count) in &fix_counts {
            println!("  {}: {}", fix_type, count);
        }

        // Show sample fixes
        println!("\nSample Fixes (first 10):");
        for (i, fix) in self.fixes.iter().take(10).enumerate() {
            println!("\n{}. {}:{}",
                i + 1,
                fix.file_path.display(),
                fix.line_number
            );
            println!("   Type: {:?}", fix.fix_type);
            println!("   Confidence: {:.1}", fix.confidence);
            println!("   Original: {}", fix.original_line.trim());
            println!("   Fixed:    {}", fix.suggested_line.trim());
        }

        if self.fixes.len() > 10 {
            println!("... and {} more fixes", self.fixes.len() - 10);
        }
    }

    /// Export findings to JSON
    pub fn export_to_json(&self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let export_data = serde_json::json!({
            "warnings": self.warnings,
            "fixes": self.fixes,
            "summary": {
                "total_warnings": self.warnings.len(),
                "total_fixes": self.fixes.len(),
                "files_affected": self.warnings.iter().map(|w| &w.file_path).collect::<HashSet<_>>().len()
            }
        });

        fs::write(filename, serde_json::to_string_pretty(&export_data)?)?;
        println!("Exported analysis to {}", filename);
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut analyzer = WarningAnalyzer::new();

    // Load file contents first
    analyzer.load_file_contents()?;

    // Analyze cargo warnings
    analyzer.analyze_cargo_warnings()?;

    // Generate fix suggestions
    analyzer.generate_fixes()?;

    // Print summary
    analyzer.print_summary();

    // Export to JSON for review
    analyzer.export_to_json("warning_analysis.json")?;

    // Ask user if they want to apply fixes
    println!("\nWould you like to apply these fixes? (y/N)");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    if input.trim().to_lowercase() == "y" {
        analyzer.apply_fixes()?;
        println!("All fixes have been applied successfully!");
    } else {
        println!("Fixes were not applied. Review warning_analysis.json for details.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_remove_import_from_use() {
        let analyzer = WarningAnalyzer::new();

        // Test simple import
        assert_eq!(analyzer.remove_import_from_use("use std::path::Path;", "Path").unwrap(), "");

        // Test multi-import
        assert_eq!(
            analyzer.remove_import_from_use("use std::path::{Path, PathBuf};", "Path").unwrap(),
            "use std::path::{PathBuf}"
        );

        // Test removing last import
        assert_eq!(analyzer.remove_import_from_use("use std::path::{Path};", "Path").unwrap(), "");
    }

    #[test]
    fn test_warning_creation() {
        let analyzer = WarningAnalyzer::new();
        let test_output = r#"warning: unused import: `Path`
  --> src/config/mod.rs:11:17
   |
11 | use std::path::{Path, PathBuf};
   |                 ^^^^"#;

        let regex = Regex::new(r"warning: unused import: `([^`]+)`.*?--> ([^:]+):(\d+):(\d+)").unwrap();
        if let Some(caps) = regex.captures(test_output) {
            let warning = analyzer.create_warning_from_match(&caps, WarningType::UnusedImport, test_output).unwrap();
            assert_eq!(warning.item_name, "Path");
            assert_eq!(warning.line_number, 11);
            assert_eq!(warning.column_number, 17);
        }
    }
}