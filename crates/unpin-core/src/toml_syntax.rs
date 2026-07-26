use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TomlAssignment<'a> {
    pub(crate) value: &'a str,
    pub(crate) value_start: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TomlTableKind {
    Standard,
    Array,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TomlTableHeader {
    pub(crate) name: String,
    pub(crate) kind: TomlTableKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TomlTableSection<'a> {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) content: &'a str,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum TomlStringState {
    #[default]
    None,
    Basic,
    Literal,
    MultilineBasic,
    MultilineLiteral,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct TomlScanState {
    string: TomlStringState,
    array_depth: usize,
    inline_table_depth: usize,
}

impl TomlScanState {
    fn is_top_level(self) -> bool {
        self.string == TomlStringState::None
            && self.array_depth == 0
            && self.inline_table_depth == 0
    }

    fn scan_line(&mut self, line: &str) -> bool {
        let bytes = line.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            match self.string {
                TomlStringState::MultilineBasic => {
                    if starts_with(bytes, index, b"\"\"\"") {
                        self.string = TomlStringState::None;
                        index += 3;
                    } else if bytes[index] == b'\\' {
                        index = (index + 2).min(bytes.len());
                    } else {
                        index += 1;
                    }
                }
                TomlStringState::MultilineLiteral => {
                    if starts_with(bytes, index, b"'''") {
                        self.string = TomlStringState::None;
                        index += 3;
                    } else {
                        index += 1;
                    }
                }
                TomlStringState::Basic => {
                    if bytes[index] == b'\\' {
                        index = (index + 2).min(bytes.len());
                    } else if bytes[index] == b'"' {
                        self.string = TomlStringState::None;
                        index += 1;
                    } else {
                        index += 1;
                    }
                }
                TomlStringState::Literal => {
                    if bytes[index] == b'\'' {
                        self.string = TomlStringState::None;
                    }
                    index += 1;
                }
                TomlStringState::None => {
                    if starts_with(bytes, index, b"\"\"\"") {
                        self.string = TomlStringState::MultilineBasic;
                        index += 3;
                    } else if starts_with(bytes, index, b"'''") {
                        self.string = TomlStringState::MultilineLiteral;
                        index += 3;
                    } else {
                        match bytes[index] {
                            b'#' => break,
                            b'"' => {
                                self.string = TomlStringState::Basic;
                                index += 1;
                            }
                            b'\'' => {
                                self.string = TomlStringState::Literal;
                                index += 1;
                            }
                            b'[' => {
                                self.array_depth = self.array_depth.saturating_add(1);
                                index += 1;
                            }
                            b']' => {
                                self.array_depth = self.array_depth.saturating_sub(1);
                                index += 1;
                            }
                            b'{' => {
                                self.inline_table_depth = self.inline_table_depth.saturating_add(1);
                                index += 1;
                            }
                            b'}' => {
                                self.inline_table_depth = self.inline_table_depth.saturating_sub(1);
                                index += 1;
                            }
                            _ => index += 1,
                        }
                    }
                }
            }
        }
        let unterminated_single_line_string = matches!(
            self.string,
            TomlStringState::Basic | TomlStringState::Literal
        );
        if unterminated_single_line_string {
            self.string = TomlStringState::None;
        }
        unterminated_single_line_string
    }
}

pub(crate) fn table_header(line: &str) -> Option<TomlTableHeader> {
    let trimmed = line_without_comment(line).trim();
    let (inner, kind) = if let Some(array_inner) = trimmed
        .strip_prefix("[[")
        .and_then(|value| value.strip_suffix("]]"))
    {
        (array_inner.trim(), TomlTableKind::Array)
    } else {
        (
            trimmed.strip_prefix('[')?.strip_suffix(']')?.trim(),
            TomlTableKind::Standard,
        )
    };

    if inner.is_empty() {
        return None;
    }

    Some(TomlTableHeader {
        name: inner.to_string(),
        kind,
    })
}

pub(crate) fn table_child_ids(raw: &str, table_prefix: &str) -> Vec<String> {
    let mut ids = table_headers(raw)
        .filter(|(_, header)| header.kind == TomlTableKind::Standard)
        .filter_map(|(_, header)| table_child_id(&header.name, table_prefix))
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids
}

pub(crate) fn duplicate_standard_table_names(raw: &str) -> Vec<String> {
    let mut declarations = BTreeMap::<Vec<String>, (String, usize)>::new();
    for (_, header) in table_headers(raw) {
        if header.kind != TomlTableKind::Standard {
            continue;
        }
        let Some(key) = table_key_components(&header.name) else {
            continue;
        };
        let entry = declarations
            .entry(key)
            .or_insert_with(|| (header.name.clone(), 0));
        entry.1 += 1;
    }
    declarations
        .into_values()
        .filter_map(|(name, count)| (count > 1).then_some(name))
        .collect()
}

pub(crate) fn duplicate_top_level_key_tables(raw: &str, key: &str) -> Vec<String> {
    let mut tables = all_table_sections(raw)
        .into_iter()
        .filter_map(|(header, section)| {
            (top_level_assignments(section.content, key).len() > 1).then_some(header.name)
        })
        .collect::<Vec<_>>();
    tables.sort();
    tables.dedup();
    tables
}

pub(crate) fn malformed_table_header_lines(raw: &str) -> Vec<usize> {
    let mut state = TomlScanState::default();
    let mut malformed = Vec::new();
    let mut open_construct_line = None;

    for (index, line) in raw.split_inclusive('\n').enumerate() {
        let line_number = index + 1;
        let was_top_level = state.is_top_level();
        if was_top_level {
            let trimmed = line_without_comment(line).trim();
            if trimmed.starts_with('[') && table_header(line).is_none() {
                malformed.push(line_number);
            }
        }
        if state.scan_line(line) {
            malformed.push(line_number);
        }
        if state.is_top_level() {
            open_construct_line = None;
        } else if was_top_level {
            open_construct_line = Some(line_number);
        }
    }

    if let Some(line_number) = open_construct_line {
        malformed.push(line_number);
    }

    malformed.sort_unstable();
    malformed.dedup();
    malformed
}

pub(crate) fn all_table_sections(raw: &str) -> Vec<(TomlTableHeader, TomlTableSection<'_>)> {
    let headers = table_headers(raw).collect::<Vec<_>>();
    headers
        .iter()
        .enumerate()
        .map(|(index, (start, header))| {
            let end = headers
                .get(index + 1)
                .map_or(raw.len(), |(next_start, _)| *next_start);
            (header.clone(), table_section(raw, *start, end))
        })
        .collect()
}

pub(crate) fn find_table_section<'a>(
    raw: &'a str,
    table_prefix: &str,
    table_id: &str,
) -> Option<TomlTableSection<'a>> {
    let mut matching = all_table_sections(raw).into_iter().filter(|(header, _)| {
        header.kind == TomlTableKind::Standard
            && table_child_id(&header.name, table_prefix).as_deref() == Some(table_id)
    });
    let (_, section) = matching.next()?;
    matching.next().is_none().then_some(section)
}

pub(crate) fn table_subtree_content(
    raw: &str,
    table_prefix: &str,
    table_id: &str,
) -> Option<String> {
    let target = [table_prefix, table_id];
    let mut found_parent = false;
    let mut content = String::new();

    for (header, section) in all_table_sections(raw) {
        let Some(components) = table_key_components(&header.name) else {
            continue;
        };
        if header.kind == TomlTableKind::Standard
            && components.len() == target.len()
            && components
                .iter()
                .map(String::as_str)
                .eq(target.iter().copied())
        {
            if found_parent {
                return None;
            }
            found_parent = true;
        }
        if components.len() >= target.len()
            && components
                .iter()
                .take(target.len())
                .map(String::as_str)
                .eq(target.iter().copied())
        {
            content.push_str(section.content);
        }
    }

    found_parent.then_some(content)
}

pub(crate) fn find_array_table_sections<'a>(
    raw: &'a str,
    target: &str,
) -> Vec<TomlTableSection<'a>> {
    let mut sections = Vec::new();
    let mut matching_start = None;
    let Some(target_components) = table_key_components(target) else {
        return sections;
    };

    for (line_start, header) in table_headers(raw) {
        if let Some(start) = matching_start.take() {
            sections.push(table_section(raw, start, line_start));
        }
        if header.kind == TomlTableKind::Array
            && table_key_components(&header.name).as_ref() == Some(&target_components)
        {
            matching_start = Some(line_start);
        }
    }

    if let Some(start) = matching_start {
        sections.push(table_section(raw, start, raw.len()));
    }
    sections
}

fn table_headers(raw: &str) -> impl Iterator<Item = (usize, TomlTableHeader)> + '_ {
    let mut state = TomlScanState::default();
    let mut offset = 0;

    raw.split_inclusive('\n').filter_map(move |line| {
        let line_start = offset;
        offset += line.len();
        let header = state.is_top_level().then(|| table_header(line)).flatten();
        let _unterminated_single_line_string = state.scan_line(line);
        header.map(|header| (line_start, header))
    })
}

fn table_section(raw: &str, start: usize, end: usize) -> TomlTableSection<'_> {
    TomlTableSection {
        start,
        end,
        content: &raw[start..end],
    }
}

fn line_without_comment(line: &str) -> &str {
    let mut in_basic_string = false;
    let mut in_literal_string = false;
    let mut escaped = false;

    for (index, character) in line.char_indices() {
        if in_basic_string {
            if escaped {
                escaped = false;
            } else {
                match character {
                    '\\' => escaped = true,
                    '"' => in_basic_string = false,
                    _ => {}
                }
            }
            continue;
        }
        if in_literal_string {
            if character == '\'' {
                in_literal_string = false;
            }
            continue;
        }

        match character {
            '"' => in_basic_string = true,
            '\'' => in_literal_string = true,
            '#' => return &line[..index],
            _ => {}
        }
    }

    line
}

pub(crate) fn table_child_id(header: &str, table_prefix: &str) -> Option<String> {
    let mut components = table_key_components(header)?;
    if components.len() != 2 || components[0] != table_prefix {
        return None;
    }
    components.pop().filter(|child| !child.is_empty())
}

fn table_key_components(header: &str) -> Option<Vec<String>> {
    let mut components = Vec::new();
    let mut remaining = header.trim();

    loop {
        let (component, rest) = parse_key_component(remaining)?;
        components.push(component);
        remaining = rest.trim_start();
        if remaining.is_empty() {
            break;
        }
        remaining = remaining.strip_prefix('.')?.trim_start();
        if remaining.is_empty() {
            return None;
        }
    }

    Some(components)
}

fn parse_key_component(input: &str) -> Option<(String, &str)> {
    match input.chars().next()? {
        '"' => parse_basic_key_component(input),
        '\'' => parse_literal_key_component(input),
        _ => {
            let end = input
                .char_indices()
                .take_while(|(_, character)| {
                    character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
                })
                .map(|(index, character)| index + character.len_utf8())
                .last()?;
            Some((input[..end].to_string(), &input[end..]))
        }
    }
}

fn parse_basic_key_component(input: &str) -> Option<(String, &str)> {
    let mut decoded = String::new();
    let mut index = 1;

    while index < input.len() {
        let character = input[index..].chars().next()?;
        index += character.len_utf8();
        match character {
            '"' => return Some((decoded, &input[index..])),
            '\\' => {
                let escaped = input[index..].chars().next()?;
                index += escaped.len_utf8();
                match escaped {
                    'b' => decoded.push('\u{0008}'),
                    't' => decoded.push('\t'),
                    'n' => decoded.push('\n'),
                    'f' => decoded.push('\u{000c}'),
                    'r' => decoded.push('\r'),
                    '"' => decoded.push('"'),
                    '\\' => decoded.push('\\'),
                    'u' => decoded.push(parse_unicode_escape(input, &mut index, 4)?),
                    'U' => decoded.push(parse_unicode_escape(input, &mut index, 8)?),
                    _ => return None,
                }
            }
            character if character <= '\u{001f}' || character == '\u{007f}' => return None,
            character => decoded.push(character),
        }
    }

    None
}

fn parse_literal_key_component(input: &str) -> Option<(String, &str)> {
    let mut index = 1;
    while index < input.len() {
        let character = input[index..].chars().next()?;
        let character_start = index;
        index += character.len_utf8();
        if character == '\'' {
            return Some((input[1..character_start].to_string(), &input[index..]));
        }
        if character <= '\u{001f}' || character == '\u{007f}' {
            return None;
        }
    }
    None
}

fn parse_unicode_escape(input: &str, index: &mut usize, digits: usize) -> Option<char> {
    let end = index.checked_add(digits)?;
    let raw = input.get(*index..end)?;
    if !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let codepoint = u32::from_str_radix(raw, 16).ok()?;
    *index = end;
    char::from_u32(codepoint)
}

pub(crate) fn top_level_assignment<'a>(section: &'a str, key: &str) -> Option<TomlAssignment<'a>> {
    top_level_assignments(section, key).into_iter().next()
}

pub(crate) fn top_level_assignments<'a>(section: &'a str, key: &str) -> Vec<TomlAssignment<'a>> {
    let mut state = TomlScanState::default();
    let mut line_start = 0;
    let mut assignments = Vec::new();

    for (line_index, line) in section.split_inclusive('\n').enumerate() {
        let line_without_newline = line.strip_suffix('\n').unwrap_or(line);
        let line_without_newline = line_without_newline
            .strip_suffix('\r')
            .unwrap_or(line_without_newline);
        if line_index != 0
            && state.is_top_level()
            && let Some(assignment) =
                top_level_assignment_on_line(line_without_newline, line_start, key)
        {
            assignments.push(assignment);
        }

        let _unterminated_single_line_string = state.scan_line(line);
        line_start += line.len();
    }

    assignments
}

fn top_level_assignment_on_line<'a>(
    line: &'a str,
    line_start: usize,
    key: &str,
) -> Option<TomlAssignment<'a>> {
    let leading_whitespace = line.len() - line.trim_start().len();
    let key_input = &line[leading_whitespace..];
    let (parsed_key, remaining) = parse_key_component(key_input)?;
    if parsed_key != key {
        return None;
    }

    let remaining = remaining.trim_start();
    let raw_value = remaining.strip_prefix('=')?;
    let equals_index = line.len() - remaining.len();
    let value_leading_whitespace = raw_value.len() - raw_value.trim_start().len();
    Some(TomlAssignment {
        value: raw_value.trim(),
        value_start: line_start + equals_index + 1 + value_leading_whitespace,
    })
}

fn starts_with(bytes: &[u8], index: usize, needle: &[u8]) -> bool {
    bytes
        .get(index..index.saturating_add(needle.len()))
        .is_some_and(|candidate| candidate == needle)
}

#[cfg(test)]
mod tests {
    use super::{
        TomlTableKind, all_table_sections, duplicate_standard_table_names,
        duplicate_top_level_key_tables, find_array_table_sections, find_table_section,
        malformed_table_header_lines, table_child_id, table_child_ids, table_header,
        table_subtree_content, top_level_assignment, top_level_assignments,
    };

    #[test]
    fn table_header_preserves_quoted_comment_markers_and_kind() {
        let header = table_header(r#"[mcp_servers."docs#api"] # dashboard"#).expect("table header");
        assert_eq!(header.name, r#"mcp_servers."docs#api""#);
        assert_eq!(header.kind, TomlTableKind::Standard);

        let header = table_header("[[ skills.config ]]").expect("array table header");
        assert_eq!(header.name, "skills.config");
        assert_eq!(header.kind, TomlTableKind::Array);
    }

    #[test]
    fn malformed_table_headers_are_reported_without_scanning_multiline_values() {
        let raw = concat!(
            "description = \"\"\"\n",
            "[not-a-header]\n",
            "\"\"\"\n",
            "[mcp_servers.valid]\n",
            "enabled = true\n",
            "[mcp_servers.missing\n",
        );
        assert_eq!(malformed_table_header_lines(raw), [6]);
    }

    #[test]
    fn unterminated_toml_values_are_reported_without_hiding_later_headers() {
        assert_eq!(
            malformed_table_header_lines(
                "description = \"unterminated\n[mcp_servers.visible]\nenabled = true\n"
            ),
            [1]
        );
        assert_eq!(
            malformed_table_header_lines(
                "description = 'unterminated\n[mcp_servers.visible]\nenabled = true\n"
            ),
            [1]
        );
        assert_eq!(
            malformed_table_header_lines(
                "values = [\n  \"one\",\n[mcp_servers.hidden]\nenabled = true\n"
            ),
            [1]
        );
        assert_eq!(
            malformed_table_header_lines(
                "metadata = {\n  enabled = true,\n[mcp_servers.hidden]\nenabled = true\n"
            ),
            [1]
        );
        assert_eq!(
            malformed_table_header_lines(
                "description = \"\"\"\n[mcp_servers.hidden]\nenabled = true\n"
            ),
            [1]
        );
    }

    #[test]
    fn document_table_scanner_ignores_headers_inside_multiline_values() {
        let raw = concat!(
            "description = \"\"\"\n",
            "[mcp_servers.decoy]\n",
            "\"\"\"\n",
            "[mcp_servers.real]\n",
            "enabled = true\n",
            "[plugins.example]\n",
            "enabled = false\n",
            "[[skills.config]]\n",
            "path = \"/one\"\n",
            "notes = '''\n",
            "[[skills.config]]\n",
            "'''\n",
            "[[skills.config]]\n",
            "path = \"/two\"\n",
        );

        assert_eq!(table_child_ids(raw, "mcp_servers"), ["real"]);
        let section = find_table_section(raw, "mcp_servers", "real").expect("real section");
        assert_eq!(section.content, "[mcp_servers.real]\nenabled = true\n");

        let skill_sections = find_array_table_sections(raw, "skills.config");
        assert_eq!(skill_sections.len(), 2);
        assert!(skill_sections[0].content.contains("path = \"/one\""));
        assert!(skill_sections[0].content.contains("[[skills.config]]"));
        assert!(skill_sections[1].content.contains("path = \"/two\""));

        let sections = all_table_sections(raw);
        assert_eq!(sections.len(), 4);
        assert_eq!(sections[0].0.name, "mcp_servers.real");
        assert_eq!(sections[1].0.name, "plugins.example");
    }

    #[test]
    fn table_subtree_content_includes_nested_tables_and_excludes_siblings() {
        let raw = concat!(
            "[mcp_servers.docs]\n",
            "command = \"docs\"\n",
            "[mcp_servers.docs.env]\n",
            "TOKEN = \"one\"\n",
            "[mcp_servers.other]\n",
            "command = \"other\"\n",
            "[mcp_servers.docs.headers]\n",
            "Accept = \"json\"\n",
        );

        let subtree =
            table_subtree_content(raw, "mcp_servers", "docs").expect("docs table subtree");
        assert!(subtree.contains("[mcp_servers.docs]\n"));
        assert!(subtree.contains("[mcp_servers.docs.env]\n"));
        assert!(subtree.contains("[mcp_servers.docs.headers]\n"));
        assert!(!subtree.contains("[mcp_servers.other]\n"));
    }

    #[test]
    fn assignment_scanner_skips_multiline_strings_and_collections() {
        let section = concat!(
            "[mcp_servers.example]\n",
            "description = \"\"\"\n",
            "enabled = true\n",
            "\"\"\"\n",
            "literal = '''\n",
            "enabled = true\n",
            "'''\n",
            "metadata = [\n",
            "  { enabled = true },\n",
            "]\n",
            "enabled = false # actual state\n",
        );

        let assignment = top_level_assignment(section, "enabled").expect("top-level assignment");
        assert_eq!(assignment.value, "false # actual state");
        assert_eq!(
            &section[assignment.value_start..assignment.value_start + 5],
            "false"
        );
    }

    #[test]
    fn assignment_scanner_normalizes_quoted_keys() {
        let section = concat!(
            "[mcp_servers.example]\n",
            "\"enabled\" = false # basic key\n",
        );
        let assignment = top_level_assignment(section, "enabled").expect("quoted assignment");
        assert_eq!(assignment.value, "false # basic key");
        assert_eq!(
            &section[assignment.value_start..assignment.value_start + 5],
            "false"
        );

        let literal_section = concat!(
            "[mcp_servers.example]\n",
            "'enabled' = true # literal key\n",
        );
        let assignment =
            top_level_assignment(literal_section, "enabled").expect("literal assignment");
        assert_eq!(assignment.value, "true # literal key");
    }

    #[test]
    fn assignment_scanner_reports_duplicate_normalized_keys() {
        let section = concat!(
            "[mcp_servers.example]\n",
            "enabled = false\n",
            "\"enabled\" = true\n",
        );
        assert_eq!(top_level_assignments(section, "enabled").len(), 2);
        assert_eq!(
            duplicate_top_level_key_tables(section, "enabled"),
            ["mcp_servers.example"]
        );
    }

    #[test]
    fn table_child_id_parses_quoted_dotted_keys() {
        assert_eq!(
            table_child_id(r#"mcp_servers."docs.example""#, "mcp_servers").as_deref(),
            Some("docs.example")
        );
        assert_eq!(
            table_child_id("plugins . 'connector.example'", "plugins").as_deref(),
            Some("connector.example")
        );
        assert_eq!(
            table_child_id(r#""mcp_servers"."docs\u002Eexample""#, "mcp_servers").as_deref(),
            Some("docs.example")
        );
        assert_eq!(
            table_child_id("mcp_servers.docs.example", "mcp_servers"),
            None
        );
        assert_eq!(table_child_id(r#"mcp_servers."""#, "mcp_servers"), None);
    }

    #[test]
    fn duplicate_standard_tables_are_canonicalized_and_fail_closed() {
        let raw = concat!(
            "[mcp_servers.docs]\n",
            "enabled = true\n",
            "[mcp_servers.\"docs\"]\n",
            "enabled = false\n",
            "[[skills.config]]\n",
            "path = \"/one\"\n",
            "[[skills.config]]\n",
            "path = \"/two\"\n",
        );

        assert_eq!(duplicate_standard_table_names(raw), ["mcp_servers.docs"]);
        assert_eq!(table_child_ids(raw, "mcp_servers"), ["docs"]);
        assert!(find_table_section(raw, "mcp_servers", "docs").is_none());
        assert_eq!(find_array_table_sections(raw, "skills.config").len(), 2);
    }

    #[test]
    fn array_table_lookup_normalizes_dotted_and_quoted_keys() {
        let raw = concat!(
            "[[skills . config]]\n",
            "path = \"/one\"\n",
            "[[skills.\"config\"]]\n",
            "path = \"/two\"\n",
        );

        let sections = find_array_table_sections(raw, "skills.config");
        assert_eq!(sections.len(), 2);
        assert!(sections[0].content.contains("path = \"/one\""));
        assert!(sections[1].content.contains("path = \"/two\""));
    }
}
