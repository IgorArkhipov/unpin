use ratatui::{
    style::{Modifier, Style},
    text::{Line, Span},
};
use unpin_core::discovery::{
    DiscoveryCategory, DiscoveryItem, DiscoveryLayer, DiscoveryOutput, ProviderId,
};
use unpin_core::mutation::load_backup_summaries_authenticated;

use super::{
    CategoryFilter, LayerFilter, ProviderFilter, TuiState, TuiView,
    backup_authentication_readiness_label, last_action_label, last_control_label, next_choice,
    provider_summary, search_summary, staged_toggle_label,
};

#[derive(Default)]
pub(super) struct InventoryRenderCache {
    rows: Vec<String>,
    search_text: Vec<String>,
    visible_indices: Vec<usize>,
    visible_valid: bool,
}

impl TuiState {
    pub(super) fn clear_staged(&mut self) {
        self.staged.clear();
        self.pending_confirmation = false;
    }

    pub(super) fn search_query(&self) -> &str {
        &self.search_query
    }

    pub(super) fn search_editing(&self) -> bool {
        self.search_editing
    }

    pub(super) fn start_search_editing(&mut self) {
        self.search_editing = true;
    }

    pub(super) fn finish_search_editing(&mut self) {
        self.search_editing = false;
        self.clamp_selected();
    }

    #[cfg(test)]
    pub(super) fn set_search_query(&mut self, query: impl Into<String>) {
        self.search_query = query.into();
        self.invalidate_visible_inventory();
        self.clamp_selected();
    }

    pub(super) fn clear_search_query(&mut self) {
        self.search_query.clear();
        self.search_editing = false;
        self.invalidate_visible_inventory();
        self.clamp_selected();
    }

    pub(super) fn push_search_char(&mut self, ch: char) {
        if ch.is_control() {
            return;
        }
        self.search_query.push(ch);
        self.invalidate_visible_inventory();
        self.clamp_selected();
    }

    pub(super) fn pop_search_char(&mut self) {
        self.search_query.pop();
        self.invalidate_visible_inventory();
        self.clamp_selected();
    }

    pub(super) fn refresh_discovery(&mut self, discovery: &DiscoveryOutput) {
        self.discovery.clone_from(discovery);
        *self.inventory_cache.borrow_mut() = InventoryRenderCache::default();
        self.preview_cache.borrow_mut().take();
        self.package_workflow.refresh(discovery);
        self.backups = load_backup_summaries_authenticated(
            &self.app_state_root,
            self.backup_authentication_key.as_ref(),
        );
        self.selected = 0;
        self.clear_staged();
        self.clamp_selected();
    }

    pub(super) fn staged_count(&self) -> usize {
        self.staged.len()
    }

    pub(super) fn pending_confirmation(&self) -> bool {
        self.pending_confirmation
    }

    pub(super) fn staged_summary_strings(&self) -> Vec<String> {
        self.staged.values().map(staged_toggle_label).collect()
    }

    pub(super) fn move_next(&mut self) {
        match self.view {
            TuiView::Packages => return self.package_workflow.select_next(),
            TuiView::Groups => {
                let visible_count = self.visible_count();
                return self.group_workflow.select_next(visible_count);
            }
            TuiView::Profiles => return self.profile_workflow.select_next(),
            TuiView::Gateways => return self.gateway_workflow.select_next(),
            TuiView::Sessions => return self.session_workflow.select_next(),
            TuiView::Hooks => return self.hook_workflow.select_next(),
            TuiView::RestoreOperations => return self.restore_workflow.select_next(),
            TuiView::Inventory => {}
        }
        let visible_count = self.visible_count();
        if visible_count == 0 {
            return;
        }

        self.selected = (self.selected + 1) % visible_count;
    }

    pub(super) fn move_previous(&mut self) {
        match self.view {
            TuiView::Packages => return self.package_workflow.select_previous(),
            TuiView::Groups => {
                let visible_count = self.visible_count();
                return self.group_workflow.select_previous(visible_count);
            }
            TuiView::Profiles => return self.profile_workflow.select_previous(),
            TuiView::Gateways => return self.gateway_workflow.select_previous(),
            TuiView::Sessions => return self.session_workflow.select_previous(),
            TuiView::Hooks => return self.hook_workflow.select_previous(),
            TuiView::RestoreOperations => return self.restore_workflow.select_previous(),
            TuiView::Inventory => {}
        }
        let visible_count = self.visible_count();
        if visible_count == 0 {
            return;
        }

        self.selected = if self.selected == 0 {
            visible_count - 1
        } else {
            self.selected - 1
        };
    }

    pub(super) fn inventory_filters_available(&self) -> bool {
        self.view == TuiView::Inventory
            || (self.view == TuiView::Groups && self.group_workflow.uses_inventory_rows())
    }

    pub(super) fn scope_control_available(&self) -> bool {
        self.view == TuiView::Profiles
            || (self.view == TuiView::Groups && self.group_workflow.can_cycle_draft_scope())
    }

    pub(super) fn group_mcp_export_available(&self) -> bool {
        self.view == TuiView::Groups && self.mcp_approval_handoff.is_some()
    }

    pub(super) fn cycle_provider_filter(&mut self) {
        if !self.inventory_filters_available() {
            return;
        }
        let choices = self.provider_choices();
        self.provider_filter = next_choice(self.provider_filter, &choices);
        self.invalidate_visible_inventory();
        self.clamp_selected();
    }

    pub(super) fn cycle_layer_filter(&mut self) {
        if !self.inventory_filters_available() {
            return;
        }
        let choices = self.layer_choices();
        self.layer_filter = next_choice(self.layer_filter, &choices);
        self.invalidate_visible_inventory();
        self.clamp_selected();
    }

    pub(super) fn cycle_category_filter(&mut self) {
        if !self.inventory_filters_available() {
            return;
        }
        let choices = self.category_choices();
        self.category_filter = next_choice(self.category_filter, &choices);
        self.invalidate_visible_inventory();
        self.clamp_selected();
    }

    pub(super) fn visible_items(&self) -> Vec<&DiscoveryItem> {
        self.visible_indices()
            .into_iter()
            .filter_map(|index| self.discovery.items.get(index))
            .collect()
    }

    pub(super) fn visible_count(&self) -> usize {
        self.prepare_visible_inventory();
        self.inventory_cache.borrow().visible_indices.len()
    }

    pub(super) fn selected_position(&self) -> Option<(usize, usize)> {
        let visible_count = self.visible_count();
        if visible_count == 0 {
            None
        } else {
            Some((self.selected + 1, visible_count))
        }
    }

    pub(super) fn filter_summary(&self) -> String {
        format!(
            "provider={} layer={} category={}",
            self.provider_filter.label(),
            self.layer_filter.label(),
            self.category_filter.label()
        )
    }

    pub(super) fn visible_indices(&self) -> Vec<usize> {
        self.prepare_visible_inventory();
        self.inventory_cache.borrow().visible_indices.clone()
    }

    pub(super) fn visible_index(&self, position: usize) -> Option<usize> {
        self.prepare_visible_inventory();
        self.inventory_cache
            .borrow()
            .visible_indices
            .get(position)
            .copied()
    }

    pub(super) fn prepared_inventory_rows(&self) -> Vec<String> {
        self.prepare_visible_inventory();
        let cache = self.inventory_cache.borrow();
        cache
            .visible_indices
            .iter()
            .map(|index| cache.rows[*index].clone())
            .collect()
    }

    fn invalidate_visible_inventory(&self) {
        self.inventory_cache.borrow_mut().visible_valid = false;
    }

    fn prepare_visible_inventory(&self) {
        let mut cache = self.inventory_cache.borrow_mut();
        if cache.rows.len() != self.discovery.items.len() {
            cache.rows = self
                .discovery
                .items
                .iter()
                .map(|item| {
                    format!(
                        "{} {} {} [{}] {}",
                        item.provider.as_str(),
                        item.layer.as_str(),
                        item.category.as_str(),
                        super::enabled_label(item.enabled),
                        item.display_name
                    )
                })
                .collect();
            cache.search_text = self
                .discovery
                .items
                .iter()
                .map(|item| {
                    [
                        item.id.as_str(),
                        item.display_name.as_str(),
                        item.provider.as_str(),
                        item.layer.as_str(),
                        item.category.as_str(),
                        item.kind.as_str(),
                        item.source_path.as_str(),
                        item.state_path.as_str(),
                    ]
                    .join("\0")
                    .to_lowercase()
                })
                .collect();
            cache.visible_valid = false;
        }
        if !cache.visible_valid {
            let query = self.search_query.trim().to_lowercase();
            cache.visible_indices = self
                .discovery
                .items
                .iter()
                .enumerate()
                .filter_map(|(index, item)| {
                    (self.provider_filter.matches(item)
                        && self.layer_filter.matches(item)
                        && self.category_filter.matches(item)
                        && (query.is_empty() || cache.search_text[index].contains(&query)))
                    .then_some(index)
                })
                .collect();
            cache.visible_valid = true;
        }
    }

    pub(super) fn clamp_selected(&mut self) {
        let visible_count = self.visible_count();
        if visible_count == 0 {
            self.selected = 0;
        } else if self.selected >= visible_count {
            self.selected = visible_count - 1;
        }
        self.group_workflow.clamp_member_selection(visible_count);
    }

    pub(super) fn provider_choices(&self) -> Vec<ProviderFilter> {
        let mut choices = vec![ProviderFilter::All];
        for provider in ProviderId::ALL {
            if self
                .discovery
                .items
                .iter()
                .any(|item| item.provider == provider)
            {
                choices.push(ProviderFilter::Provider(provider));
            }
        }
        choices
    }

    pub(super) fn layer_choices(&self) -> Vec<LayerFilter> {
        let mut choices = vec![LayerFilter::All];
        for layer in [DiscoveryLayer::Global, DiscoveryLayer::Project] {
            if self.discovery.items.iter().any(|item| item.layer == layer) {
                choices.push(LayerFilter::Layer(layer));
            }
        }
        choices
    }

    pub(super) fn category_choices(&self) -> Vec<CategoryFilter> {
        let mut choices = vec![CategoryFilter::All];
        for category in [
            DiscoveryCategory::Skill,
            DiscoveryCategory::ConfiguredMcp,
            DiscoveryCategory::Tool,
            DiscoveryCategory::Agent,
            DiscoveryCategory::Hook,
            DiscoveryCategory::ProviderSetting,
            DiscoveryCategory::PluginConfig,
            DiscoveryCategory::PluginManifest,
        ] {
            if self
                .discovery
                .items
                .iter()
                .any(|item| item.category == category)
            {
                choices.push(CategoryFilter::Category(category));
            }
        }
        choices
    }
}

pub(super) fn inventory_header_lines(state: &TuiState, content_height: u16) -> Vec<Line<'static>> {
    let full = vec![
        Line::from(vec![Span::styled(
            "Unpin",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(format!("Items: {}", state.discovery.items.len())),
        Line::from(format!("Packages: {}", state.package_workflow.len())),
        Line::from(format!("Showing: {}", state.visible_count())),
        Line::from(format!("Warnings: {}", state.discovery.warnings.len())),
        Line::from(format!(
            "Backups: {} | Backup authentication: {}",
            state.backups.len(),
            backup_authentication_readiness_label(state)
        )),
        Line::from(format!("Staged: {}", state.staged_count())),
        Line::from(format!("Last action: {}", last_action_label(state))),
        Line::from(format!("Last control: {}", last_control_label(state))),
        Line::from(format!("View: {}", state.view.title())),
        Line::from(provider_summary(&state.discovery.items)),
        Line::from(format!("Filters: {}", state.filter_summary())),
        Line::from(format!("Search: {}", search_summary(state))),
    ];
    if usize::from(content_height) >= full.len() {
        return full;
    }

    vec![
        Line::from(vec![
            Span::styled("Unpin", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!(" | View: {}", state.view.title())),
        ]),
        Line::from(format!(
            "Items: {} | Packages: {} | Showing: {} | Warnings: {} | Staged: {}",
            state.discovery.items.len(),
            state.package_workflow.len(),
            state.visible_count(),
            state.discovery.warnings.len(),
            state.staged_count(),
        )),
        Line::from(format!(
            "Filters: {} | Search: {}",
            state.filter_summary(),
            search_summary(state)
        )),
        Line::from(format!("Last action: {}", last_action_label(state))),
        Line::from(format!("Last control: {}", last_control_label(state))),
        Line::from(format!(
            "Backups: {} | Backup authentication: {}",
            state.backups.len(),
            backup_authentication_readiness_label(state)
        )),
        Line::from(provider_summary(&state.discovery.items)),
    ]
    .into_iter()
    .take(usize::from(content_height))
    .collect()
}
