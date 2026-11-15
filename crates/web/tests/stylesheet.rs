//! Checks on the shared stylesheet.

use std::collections::HashMap;

const STYLESHEET: &str = include_str!("../../../style/main.css");

/// A class styled by two top-level rules gets both, so a rule written for
/// one page quietly changes another. The Integrations tab once reused
/// `.target-list` from the administrator page, and its second rule indented
/// the administrator's table. Rules inside `@media` blocks are indented and
/// are meant to override, so only rules that start a line are compared.
#[test]
fn no_class_has_two_top_level_rules() {
    let mut seen: HashMap<&str, usize> = HashMap::new();
    let mut repeated = Vec::new();
    for (index, line) in STYLESHEET.lines().enumerate() {
        let Some(rest) = line.strip_prefix('.') else {
            continue;
        };
        let Some((name, _)) = rest.split_once(" {") else {
            continue;
        };
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            continue;
        }
        let number = index + 1;
        if let Some(first) = seen.insert(name, number) {
            repeated.push(format!(".{name} on lines {first} and {number}"));
        }
    }
    assert!(
        repeated.is_empty(),
        "classes styled twice: {}",
        repeated.join(", ")
    );
}
