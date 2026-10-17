//! Fluent Desk presentation. All operations use the existing desktop controller.
use super::*;

pub(super) struct Palette {
    pub canvas: Color32,
    pub surface: Color32,
    pub field: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub line: Color32,
    pub accent: Color32,
    pub on_accent: Color32,
    pub selected: Color32,
}
pub(super) fn palette(ui: &egui::Ui) -> Palette {
    colors(ui.visuals().dark_mode)
}
fn colors(dark: bool) -> Palette {
    if dark {
        Palette {
            canvas: Color32::from_rgb(23, 27, 32),
            surface: Color32::from_rgb(34, 39, 46),
            field: Color32::from_rgb(42, 48, 56),
            text: Color32::from_rgb(237, 242, 247),
            muted: Color32::from_rgb(174, 186, 197),
            line: Color32::from_rgb(61, 70, 80),
            accent: Color32::from_rgb(105, 216, 209),
            on_accent: Color32::from_rgb(17, 43, 43),
            selected: Color32::from_rgb(32, 61, 61),
        }
    } else {
        Palette {
            canvas: Color32::from_rgb(243, 245, 247),
            surface: Color32::WHITE,
            field: Color32::from_rgb(249, 250, 251),
            text: Color32::from_rgb(24, 36, 44),
            muted: Color32::from_rgb(88, 103, 114),
            line: Color32::from_rgb(218, 225, 230),
            accent: Color32::from_rgb(8, 124, 130),
            on_accent: Color32::WHITE,
            selected: Color32::from_rgb(224, 242, 240),
        }
    }
}
pub(super) fn configure_style(ctx: &egui::Context) {
    ctx.global_style_mut(|s| {
        let p = colors(s.visuals.dark_mode);
        s.spacing.item_spacing = egui::vec2(10.0, 10.0);
        s.spacing.button_padding = egui::vec2(14.0, 9.0);
        s.spacing.interact_size.y = 36.0;
        s.spacing.combo_height = 280.0;
        s.visuals.panel_fill = p.canvas;
        s.visuals.window_fill = p.surface;
        s.visuals.window_stroke = egui::Stroke::new(1.0, p.line);
        s.visuals.window_corner_radius = 12.into();
        s.visuals.text_edit_bg_color = Some(p.field);
        s.visuals.extreme_bg_color = p.field;
        s.visuals.faint_bg_color = p.field;
        s.visuals.override_text_color = Some(p.text);
        s.visuals.weak_text_color = Some(p.muted);
        s.visuals.hyperlink_color = p.accent;
        s.visuals.selection.bg_fill = p.selected;
        s.visuals.selection.stroke = egui::Stroke::new(1.0, p.accent);
        for w in [
            &mut s.visuals.widgets.inactive,
            &mut s.visuals.widgets.hovered,
            &mut s.visuals.widgets.active,
            &mut s.visuals.widgets.open,
        ] {
            w.corner_radius = 7.into();
            w.fg_stroke.color = p.text;
            w.bg_stroke = egui::Stroke::new(1.0, p.line);
        }
        s.visuals.widgets.inactive.bg_fill = p.surface;
        s.visuals.widgets.inactive.weak_bg_fill = p.surface;
        s.visuals.widgets.hovered.bg_fill = p.selected;
        s.visuals.widgets.hovered.weak_bg_fill = p.selected;
        s.visuals.widgets.hovered.bg_stroke.color = p.accent;
        s.visuals.widgets.active.bg_fill = p.selected;
        s.visuals.widgets.active.weak_bg_fill = p.selected;
        s.visuals.widgets.noninteractive.bg_stroke.color = p.line;
        s.visuals.widgets.noninteractive.fg_stroke.color = p.text;
        s.text_styles
            .insert(egui::TextStyle::Body, egui::FontId::proportional(14.0));
        s.text_styles
            .insert(egui::TextStyle::Button, egui::FontId::proportional(14.0));
        s.text_styles
            .insert(egui::TextStyle::Small, egui::FontId::proportional(12.0));
    });
}
fn card(ui: &egui::Ui) -> egui::Frame {
    let p = palette(ui);
    egui::Frame::new()
        .fill(p.surface)
        .stroke(egui::Stroke::new(1.0, p.line))
        .corner_radius(12)
        .inner_margin(20)
}
pub(super) fn primary(ui: &egui::Ui, label: &str) -> egui::Button<'static> {
    let p = palette(ui);
    egui::Button::new(RichText::new(label).color(p.on_accent)).fill(p.accent)
}
fn note(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(palette(ui).muted).size(12.0));
}
fn section_label(ui: &mut egui::Ui, text: &str, help: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(text).strong());
        let response = ui.small_button("?");
        if response.clicked() {
            response.request_focus();
        }
        let response = response.help_text(help);
        response.widget_info(|| {
            egui::WidgetInfo::labeled(egui::WidgetType::Button, true, format!("{text} help"))
        });
    });
}

impl App {
    pub(super) fn reset_search(&mut self) {
        self.engine.session = None;
        self.engine.progress = None;
        self.engine.state = State::Idle;
        self.engine.unlocked_password = None;
        self.engine.verified_this_run = false;
        self.engine.error = None;
        self.engine.notice.clear();
        self.prefix.clear();
        self.split_create = false;
        self.split_preview = None;
        self.view = View::Generate;
    }
    pub(super) fn open_session(&mut self, session: desktop::Session) {
        self.prefix = session.job.pattern.prefix.clone();
        self.engine.settings.profile = session.job.profile();
        self.engine.settings.benchmark_per_second = None;
        if session.job.profile().key_family() == crate::chains::KeyFamily::Ed25519 {
            self.engine.settings.mode = Mode::Cpu;
        }
        let split = session.kind != crate::split::SessionKind::Local;
        self.split_create = false;
        self.split_preview = None;
        let result = self.engine.select_session(session);
        self.fault(result);
        self.view = if split { View::Split } else { View::Generate };
    }
    pub(super) fn sidebar(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui);
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            egui::Frame::new()
                .fill(p.accent)
                .corner_radius(7)
                .inner_margin(7)
                .show(ui, |ui| {
                    ui.label(RichText::new("V").strong().color(p.on_accent).size(17.0));
                });
            ui.label(RichText::new("Vanity Pro").strong().size(19.0));
        });
        ui.add_space(12.0);
        if ui
            .add_enabled(
                self.available(),
                primary(ui, "New search").min_size(egui::vec2(ui.available_width(), 38.0)),
            )
            .help_text(text::NEW_SEARCH)
            .clicked()
        {
            self.reset_search();
        }
        ui.add_space(8.0);
        for (view, label) in [
            (View::Generate, "Search"),
            (View::Split, "Split-key search"),
            (View::Sessions, "Sessions"),
        ] {
            if ui
                .add(
                    egui::Button::new(label)
                        .selected(self.view == view)
                        .min_size(egui::vec2(ui.available_width(), 36.0)),
                )
                .clicked()
            {
                self.view = view;
            }
        }
        if ui
            .add(egui::Button::new("Settings").min_size(egui::vec2(ui.available_width(), 36.0)))
            .help_text("Set the storage folders, appearance, and compute preferences.")
            .clicked()
        {
            self.settings = Some(self.engine.settings.clone());
        }
        if ui
            .add(egui::Button::new("Diagnostics").min_size(egui::vec2(ui.available_width(), 36.0)))
            .help_text("Read hardware information. Measure search speed.")
            .clicked()
        {
            self.diagnostics = true;
        }
        if ui
            .add(egui::Button::new("Help").min_size(egui::vec2(ui.available_width(), 36.0)))
            .clicked()
        {
            self.help = true;
        }
        ui.add_space(14.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Saved sessions").strong().size(12.0));
            if ui
                .add_enabled(self.available(), egui::Button::new("Refresh").small())
                .help_text("Read the configured session folder again.")
                .clicked()
            {
                let result = self.engine.refresh_history();
                self.fault(result);
            }
        });
        let max = (ui.available_height() - 65.0).max(80.0);
        egui::ScrollArea::vertical()
            .id_salt("session-list")
            .max_height(max)
            .show(ui, |ui| {
                if self.engine.history.is_empty() {
                    note(ui, "No sessions found.");
                }
                for session in self.engine.history.clone().into_iter().take(12) {
                    let selected = self
                        .engine
                        .session
                        .as_ref()
                        .is_some_and(|s| s.job.session_id == session.job.session_id);
                    let profile = session.job.profile();
                    let title = format!(
                        "{} · {}",
                        profile.chain.label(),
                        display_prefix(profile, &session.job.pattern.prefix)
                    );
                    if ui
                        .add_enabled(
                            self.available(),
                            egui::Button::new(RichText::new(title).size(12.0))
                                .wrap()
                                .selected(selected)
                                .min_size(egui::vec2(ui.available_width(), 38.0)),
                        )
                        .help_text(format!(
                            "{}\n{}\n{}",
                            profile.address_type.label(),
                            date(session.created),
                            session.job.session_id
                        ))
                        .clicked()
                    {
                        self.open_session(session.clone());
                    }
                    note(
                        ui,
                        &format!("{} · {}", session.kind.label(), session.state.label()),
                    );
                    ui.add_space(4.0);
                }
            });
    }
    pub(super) fn sessions_view(&mut self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("Sessions").size(26.0));
        note(
            ui,
            "Select a session to read its status or continue its operation.",
        );
        ui.add_space(16.0);
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(self.available(), egui::Button::new("Refresh sessions"))
                .clicked()
            {
                let result = self.engine.refresh_history();
                self.fault(result);
            }
            if ui
                .button("Open session folder")
                .help_text("Open the configured root folder in Windows Explorer.")
                .clicked()
            {
                let root = self.engine.settings.sessions_root.clone();
                self.fault(open_folder(&root));
            }
        });
        note(
            ui,
            &self.engine.settings.sessions_root.display().to_string(),
        );
        ui.add_space(12.0);
        if self.engine.history.is_empty() {
            note(ui, text::EMPTY_SESSIONS);
        }
        for session in self.engine.history.clone() {
            ui.push_id(session.job.session_id, |ui| {
                card(ui).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    let profile = session.job.profile();
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(profile.chain.label()).strong());
                        ui.label(profile.address_type.label());
                        ui.label(session.kind.label());
                        ui.label(RichText::new(session.state.label()).color(palette(ui).accent));
                    });
                    ui.label(
                        RichText::new(display_prefix(profile, &session.job.pattern.prefix))
                            .monospace(),
                    );
                    if !session.job.pattern.suffix.is_empty() {
                        ui.label(format!("Address suffix: {}", session.job.pattern.suffix));
                    }
                    note(ui, &format!("Session date: {}", date(session.created)));
                    note(
                        ui,
                        &format!(
                            "Attempts: {} · Elapsed time: {}",
                            session.candidates,
                            duration(session.elapsed)
                        ),
                    );
                    if session.receipt.is_some() {
                        note(ui, text::EXPORT_RECORD);
                    }
                    ui.horizontal_wrapped(|ui| {
                        if ui
                            .add_enabled(self.available(), egui::Button::new("Open session"))
                            .help_text("Read this session. The search does not start.")
                            .clicked()
                        {
                            self.open_session(session.clone());
                        }
                        self.delete_session_button(ui, &session);
                    });
                });
            });
            ui.add_space(10.0);
        }
        self.messages(ui);
    }
    fn messages(&mut self, ui: &mut egui::Ui) {
        if let Some(error) = self.engine.error.clone() {
            ui.add_space(10.0);
            card(ui).show(ui, |ui| {
                ui.colored_label(
                    ui.visuals().error_fg_color,
                    "The application cannot complete this operation.",
                );
                ui.label(error);
                if ui.small_button("Close error message").clicked() {
                    self.engine.error = None;
                }
            });
        }
        if !self.engine.notice.is_empty() {
            ui.add_space(8.0);
            note(ui, &self.engine.notice);
        }
    }
    pub(super) fn split_view(&mut self, ui: &mut egui::Ui) {
        if self.split_create {
            self.main_view(ui);
            return;
        }
        ui.heading(RichText::new("Split-key search").size(26.0));
        if self
            .engine
            .session
            .as_ref()
            .is_none_or(|session| session.kind == crate::split::SessionKind::Local)
            || self.split_preview.is_some()
        {
            section_label(ui, "Owner and helper", text::SPLIT);
        }
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(self.available(), egui::Button::new("Create request"))
                .help_text(text::SPLIT_CREATE)
                .clicked()
            {
                self.reset_search();
                if self.engine.settings.profile.key_family() == crate::chains::KeyFamily::Ed25519 {
                    self.engine.settings.profile =
                        crate::chains::Profile::new(crate::chains::Chain::Ethereum, None)
                            .expect("Ethereum profile");
                }
                self.split_create = true;
                self.view = View::Split;
            }
            if ui
                .add_enabled(self.available(), egui::Button::new("Import search request"))
                .help_text(text::SPLIT_REQUEST)
                .clicked()
            {
                let result = self.pick(Pick::SplitRequestImport);
                self.fault(result);
            }
        });
        ui.add_space(16.0);
        if let Some(request) = self.split_preview.clone() {
            let profile = request.job.profile();
            card(ui).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.heading("Public search request");
                ui.label(format!("Blockchain: {}", profile.chain.label()));
                ui.label(format!("Address type: {}", profile.address_type.label()));
                ui.label(format!(
                    "Address prefix: {}",
                    display_prefix(profile, &request.job.pattern.prefix)
                ));
                if !request.job.pattern.suffix.is_empty() {
                    ui.label(format!("Address suffix: {}", request.job.pattern.suffix));
                }
                note(ui, &format!("Request ID: {}", request.job.session_id));
                note(ui, text::SPLIT_PREVIEW);
                ui.separator();
                section_label(ui, "Compute mode", text::AUTO);
                ui.add_enabled_ui(self.available(), |ui| {
                    mode_combo(ui, "split-compute-mode", &mut self.engine.settings.mode);
                });
                if ui
                    .add_enabled(self.available(), primary(ui, "Start search"))
                    .help_text(text::SPLIT_WORKER)
                    .clicked()
                {
                    let result = self.engine.start_split_worker(request);
                    if result.is_ok() {
                        self.split_preview = None;
                    }
                    self.fault(result);
                }
            });
            self.calibration_controls(ui);
            self.messages(ui);
        } else if self
            .engine
            .session
            .as_ref()
            .is_some_and(|s| s.kind != crate::split::SessionKind::Local)
        {
            self.main_view(ui);
        } else {
            note(
                ui,
                "Create request: keep the private share and give the public request to a helper.",
            );
            note(
                ui,
                "Import search request: find a match and give the public result to the owner.",
            );
            self.calibration_controls(ui);
            self.messages(ui);
        }
    }
    fn probability_panel(&mut self, ui: &mut egui::Ui, pattern: &crate::crypto::Pattern) {
        let estimate = self.probability_estimate(pattern);
        let rate = self
            .engine
            .progress
            .as_ref()
            .filter(|progress| progress.candidates_per_second > 0.0)
            .map(|progress| progress.candidates_per_second)
            .or(self.engine.settings.benchmark_per_second);
        let mut help = format!("{}\n{}", text::EXPECTED, text::PROBABILITY);
        let mut time_help = text::MEAN_TIME.to_owned();
        let mut long_search = pattern.prefix.len() >= 10;
        let (attempts, mean_time, status) = match estimate {
            Some(Ok(estimate)) => {
                let attempts = estimate
                    .probability
                    .map(|probability| 1.0 / probability)
                    .unwrap_or(f64::INFINITY);
                let seconds = rate
                    .filter(|rate| rate.is_finite() && *rate > 0.0)
                    .and_then(|rate| attempts.is_finite().then_some(attempts / rate));
                long_search |= seconds.is_some_and(|seconds| seconds > 86400.0);
                if !estimate.exact_model && estimate.samples > 0 {
                    help.push_str(&format!("\nSample matches: {} / {}. 95% probability interval: {:.3e} to {:.3e}.\nModel: {}.", estimate.matches, estimate.samples, estimate.lower_95, estimate.upper_95, estimate.model));
                }
                let status = if !estimate.exact_model && estimate.samples == 0 {
                    text::SAMPLE_UNAVAILABLE
                } else if !attempts.is_finite() {
                    text::NO_SAMPLE
                } else if long_search {
                    text::LONG_SEARCH
                } else if seconds.is_none() {
                    text::NO_RATE
                } else {
                    " "
                };
                if attempts.is_finite() && seconds.is_none() {
                    time_help.push('\n');
                    time_help.push_str(text::NO_RATE);
                }
                (
                    if attempts.is_finite() {
                        number(attempts)
                    } else {
                        "No estimate".into()
                    },
                    seconds
                        .map(duration)
                        .unwrap_or_else(|| "No estimate".into()),
                    status,
                )
            }
            Some(Err(error)) => {
                help.push('\n');
                help.push_str(&error);
                (
                    "No estimate".into(),
                    "No estimate".into(),
                    text::ESTIMATE_UNAVAILABLE,
                )
            }
            None => (
                "Calculating".into(),
                "Calculating".into(),
                text::ESTIMATE_PENDING,
            ),
        };
        if long_search {
            help.push('\n');
            help.push_str(text::LONG_SEARCH);
        }
        ui.add_space(8.0);
        // Every completion state has the same two metric rows and one short status row.
        // Keep modal-opening controls at the same position while a public task completes.
        ui.columns(2, |columns| {
            section_label(&mut columns[0], "Expected attempts", &help);
            columns[0].label(attempts);
            section_label(&mut columns[1], "Mean search time", &time_help);
            columns[1].label(mean_time);
        });
        ui.label(RichText::new(status).size(12.0).color(if long_search {
            ui.visuals().warn_fg_color
        } else {
            palette(ui).muted
        }));
    }
    pub(super) fn main_view(&mut self, ui: &mut egui::Ui) {
        if let Some(session) = &self.engine.session {
            self.prefix = session.job.pattern.prefix.clone();
        }
        let p = palette(ui);
        let owner_creation =
            self.view == View::Split && self.split_create && self.engine.session.is_none();
        let owner = owner_creation
            || self
                .engine
                .session
                .as_ref()
                .is_some_and(|s| s.kind == crate::split::SessionKind::Owner);
        if self.view != View::Split || owner_creation || self.engine.session.is_none() {
            ui.horizontal_wrapped(|ui| {
            ui.heading(RichText::new(if owner_creation { "Create split-key request" } else if self.engine.session.is_some() { "Search session" } else { "Find address" }).size(26.0));
            ui.label(RichText::new("Offline").color(p.accent).size(12.0))
                .help_text("The application does not use a network connection to make wallets or export wallet files.");
        });
            note(
                ui,
                if owner_creation {
                    text::SPLIT_CREATE
                } else if let Some(session) = &self.engine.session {
                    match session.kind {
                        crate::split::SessionKind::Local => text::SESSION,
                        crate::split::SessionKind::Owner => text::SPLIT_OWNER_SESSION,
                        crate::split::SessionKind::Worker => text::SPLIT_WORKER,
                    }
                } else {
                    text::START
                },
            );
            ui.add_space(18.0);
        }
        let editable = self.available() && self.engine.session.is_none();
        card(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            let selected = self.engine.session.is_some();
            if let Some(session) = &self.engine.session {
                ui.label(format!(
                    "{} · {} · {}",
                    session.job.profile().chain.label(),
                    session.job.profile().address_type.label(),
                    display_prefix(session.job.profile(), &self.prefix)
                ));
                if !session.job.pattern.suffix.is_empty() {
                    ui.label(format!("Address suffix: {}", session.job.pattern.suffix));
                }
            }
            let mut configuration = |ui: &mut egui::Ui| {
                ui.add_enabled_ui(editable, |ui| {
                    let previous = self.engine.settings.profile;
                    ui.columns(2, |cols| {
                        section_label(
                            &mut cols[0],
                            "Blockchain",
                            "Select the mainnet network for this wallet.",
                        );
                        egui::ComboBox::from_id_salt("chain-select")
                            .width(cols[0].available_width())
                            .selected_text(self.engine.settings.profile.chain.label())
                            .show_ui(&mut cols[0], |ui| {
                                for chain in crate::chains::Chain::ALL {
                                    if owner_creation
                                        && crate::chains::Profile::new(chain, None).is_ok_and(|p| {
                                            p.key_family() == crate::chains::KeyFamily::Ed25519
                                        })
                                    {
                                        continue;
                                    }
                                    if ui
                                        .selectable_value(
                                            &mut self.engine.settings.profile.chain,
                                            chain,
                                            chain.label(),
                                        )
                                        .changed()
                                    {
                                        self.engine.settings.profile.address_type =
                                            chain.types()[0];
                                    }
                                }
                            });
                        section_label(
                            &mut cols[1],
                            "Address type",
                            "Select the address format for the blockchain.",
                        );
                        egui::ComboBox::from_id_salt("address-type-select")
                            .width(cols[1].available_width())
                            .selected_text(self.engine.settings.profile.address_type.label())
                            .show_ui(&mut cols[1], |ui| {
                                for ty in self.engine.settings.profile.chain.types() {
                                    ui.selectable_value(
                                        &mut self.engine.settings.profile.address_type,
                                        *ty,
                                        ty.label(),
                                    );
                                }
                            });
                    });
                    if previous != self.engine.settings.profile {
                        self.prefix.clear();
                        self.engine.settings.benchmark_per_second = None;
                        if self.engine.settings.profile.key_family()
                            == crate::chains::KeyFamily::Ed25519
                        {
                            self.engine.settings.mode = Mode::Cpu;
                        }
                        let result = self.engine.save_preferences(self.engine.settings.clone());
                        self.fault(result);
                    }
                })
                .response
                .on_disabled_hover_text(text::PROFILE_LOCK);
                // Re-read the profile after a selection changes in this frame.
                let profile = self
                    .engine
                    .session
                    .as_ref()
                    .map(|s| s.job.profile())
                    .unwrap_or(self.engine.settings.profile);
                ui.add_space(12.0);
                section_label(ui, "Address prefix", text::PREFIX);
                ui.add_enabled_ui(editable, |ui| {
                    ui.horizontal(|ui| {
                        if profile.is_evm() {
                            ui.label(
                                RichText::new(profile.fixed_prefix())
                                    .monospace()
                                    .size(23.0)
                                    .color(p.accent),
                            );
                        }
                        let response = ui
                            .add(
                                egui::TextEdit::singleline(&mut self.prefix)
                                    .id_salt("desired-prefix")
                                    .font(egui::FontId::monospace(23.0))
                                    .hint_text(
                                        if profile.is_evm()
                                            || profile.chain == crate::chains::Chain::Warthog
                                        {
                                            "00000"
                                        } else {
                                            "Address prefix"
                                        },
                                    )
                                    .char_limit(128)
                                    .desired_width(ui.available_width()),
                            )
                            .help_text(text::PREFIX);
                        response.widget_info(|| {
                            egui::WidgetInfo::labeled(
                                egui::WidgetType::TextEdit,
                                true,
                                "Address prefix",
                            )
                        });
                        if response.changed() && profile.is_evm() {
                            let trimmed = self.prefix.trim();
                            self.prefix = trimmed
                                .strip_prefix("0x")
                                .or_else(|| trimmed.strip_prefix("0X"))
                                .unwrap_or(trimmed)
                                .to_ascii_lowercase();
                        } else if response.changed()
                            && profile.chain == crate::chains::Chain::Warthog
                        {
                            self.prefix = self.prefix.trim().to_ascii_lowercase();
                        }
                    });
                })
                .response
                .on_disabled_hover_text(text::PROFILE_LOCK);
                note(ui, prefix_rules(profile));
                let pattern = self
                    .engine
                    .session
                    .as_ref()
                    .map(|session| Ok(session.job.pattern.clone()))
                    .unwrap_or_else(|| {
                        crate::crypto::Pattern::for_profile(profile, self.prefix.trim(), "")
                    });
                if let Err(error) = &pattern
                    && !self.prefix.is_empty()
                {
                    ui.colored_label(ui.visuals().error_fg_color, error.to_string());
                }
                if let Ok(pattern) = &pattern {
                    self.probability_panel(ui, pattern);
                }
                ui.add_space(8.0);
                ui.separator();
                if !owner {
                    section_label(ui, "Compute mode", text::AUTO);
                    ui.add_enabled_ui(self.available(), |ui| {
                        if profile.key_family() == crate::chains::KeyFamily::Ed25519 {
                            self.engine.settings.mode = Mode::Cpu;
                            ui.label("CPU only · Ed25519").help_text(text::ED25519);
                        } else {
                            ui.horizontal_wrapped(|ui| {
                                for (mode, label, help) in [
                                    (Mode::Auto, "Automatic", text::AUTO),
                                    (Mode::Cpu, "CPU only", text::CPU),
                                    (Mode::Opencl, "OpenCL GPU only", text::GPU),
                                ] {
                                    ui.selectable_value(
                                        &mut self.engine.settings.mode,
                                        mode,
                                        label,
                                    )
                                    .help_text(help);
                                }
                            });
                        }
                    });
                }
                let details = profile_details(profile);
                section_label(ui, "Address and export details", &details);
                if self.engine.session.is_none() {
                    ui.add_space(12.0);
                    if owner_creation {
                        ui.colored_label(ui.visuals().warn_fg_color, text::SPLIT_SHARE);
                    }
                    if ui
                        .add_enabled(
                            self.available() && pattern.is_ok(),
                            primary(
                                ui,
                                if owner_creation {
                                    "Create request"
                                } else {
                                    "Find address"
                                },
                            )
                            .min_size(egui::vec2(ui.available_width(), 42.0)),
                        )
                        .help_text(if owner_creation {
                            text::SPLIT_SHARE_PASSWORD
                        } else {
                            text::GENERATE
                        })
                        .clicked()
                    {
                        self.passwords = Some(PasswordForm::new(if owner_creation {
                            PasswordStep::Owner
                        } else {
                            PasswordStep::Seed
                        }));
                    }
                    note(
                        ui,
                        if owner_creation {
                            "A private share password is necessary for the next step."
                        } else {
                            "A session password is necessary for the next step."
                        },
                    );
                }
            };
            if selected {
                ui.collapsing("Search configuration", configuration);
            } else {
                configuration(ui);
            }
        });
        if self.engine.session.is_some() {
            ui.add_space(16.0);
            self.dashboard(ui);
        }
        self.calibration_controls(ui);
        if self.engine.busy() && self.engine.state != State::Searching {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(if self.closing {
                    "Save in progress. Wait for the application to close."
                } else {
                    self.engine.state.label()
                });
            });
        }
        self.messages(ui);
    }
    fn delete_session_button(&mut self, ui: &mut egui::Ui, session: &desktop::Session) {
        if ui
            .add_enabled(
                self.available() && self.engine.state != State::Finalizing,
                egui::Button::new("Delete session…"),
            )
            .on_disabled_hover_text(text::DELETE_WAIT)
            .help_text(text::DELETE)
            .clicked()
        {
            self.delete = Some(session.directory.clone());
            self.delete_kind = session.kind;
            self.delete_text.clear();
        }
    }
    pub(super) fn calibration_controls(&mut self, ui: &mut egui::Ui) {
        if !self.engine.calibrating() {
            return;
        }
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new("Calibrating hardware").strong());
            });
            note(ui, &self.engine.notice);
            ui.horizontal(|ui| {
                if ui.button("Skip tuning").help_text("Continue with the self-tested incumbent. Incomplete measurements are not cached.").clicked() {
                    self.engine.skip_calibration();
                }
                if self.engine.state != State::Searching && ui.button("Stop").help_text("Cancel calibration and the pending operation.").clicked() {
                    self.engine.stop_calibration();
                }
            });
        });
    }
    fn dashboard(&mut self, ui: &mut egui::Ui) {
        let Some(session) = self.engine.session.clone() else {
            return;
        };
        let estimate = if session.kind == crate::split::SessionKind::Owner {
            None
        } else {
            self.probability_estimate(&session.job.pattern)
        };
        let estimated_probability = estimate
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .and_then(|estimate| estimate.probability)
            .map(|probability| {
                -(session.candidates.parse::<f64>().unwrap_or(0.0) * (-probability).ln_1p())
                    .exp_m1()
            })
            .unwrap_or(f64::NAN);
        let p = palette(ui);
        if session.kind == crate::split::SessionKind::Owner {
            card(ui).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.heading(session.kind.label());
                ui.colored_label(ui.visuals().warn_fg_color, text::SPLIT_SHARE);
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .add_enabled(self.available(), egui::Button::new("Save public request"))
                        .help_text(text::SPLIT_REQUEST)
                        .clicked()
                    {
                        let result = self.pick(Pick::SplitRequestExport);
                        self.fault(result);
                    }
                    if ui
                        .add_enabled(self.available(), egui::Button::new("Import search result"))
                        .help_text(text::SPLIT_RESULT)
                        .clicked()
                    {
                        let result = self.pick(Pick::SplitResultImport);
                        self.fault(result);
                    }
                    self.delete_session_button(ui, &session);
                });
                if session.address.is_none() {
                    note(
                        ui,
                        "Import the search result from the helper to save the wallet.",
                    );
                }
            });
        } else {
            card(ui).show(ui, |ui| {
                note(ui, session.kind.label());
                ui.set_width(ui.available_width());
                ui.horizontal_wrapped(|ui| {
                    if self.engine.state == State::Searching {
                        ui.spinner();
                    }
                    ui.label(
                        RichText::new(self.engine.state.label())
                            .strong()
                            .color(p.accent),
                    );
                    if ui
                        .add_enabled(
                            self.engine.state == State::Searching && !self.engine.calibrating(),
                            egui::Button::new("Pause"),
                        )
                        .help_text(text::PAUSE)
                        .clicked()
                    {
                        let result = self.engine.pause(false);
                        self.fault(result);
                    }
                    if ui
                        .add_enabled(
                            self.available()
                                && matches!(self.engine.state, State::Paused | State::Error)
                                && session.address.is_none(),
                            egui::Button::new("Resume"),
                        )
                        .help_text(text::RESUME)
                        .clicked()
                    {
                        if session.job.profile().key_family() == crate::chains::KeyFamily::Ed25519 {
                            self.passwords = Some(PasswordForm::new(PasswordStep::Resume));
                        } else {
                            let result = self.engine.search();
                            self.fault(result);
                        }
                    }
                    if ui
                        .add_enabled(
                            self.engine.state == State::Searching,
                            egui::Button::new("Stop"),
                        )
                        .help_text(text::STOP)
                        .clicked()
                    {
                        if self.engine.calibrating() {
                            self.engine.stop_calibration();
                        } else {
                            let result = self.engine.pause(true);
                            self.fault(result);
                        }
                    }
                    self.delete_session_button(ui, &session);
                    if session.kind == crate::split::SessionKind::Worker
                        && session.address.is_some()
                        && ui
                            .add_enabled(self.available(), primary(ui, "Save search result"))
                            .help_text(text::SPLIT_WORKER)
                            .clicked()
                    {
                        let result = self.pick(Pick::SplitResultExport);
                        self.fault(result);
                    }
                });
                let (rate, candidates, elapsed, probability) = self
                    .engine
                    .progress
                    .as_ref()
                    .map(|p| {
                        (
                            p.candidates_per_second,
                            p.candidates_exact.clone(),
                            p.elapsed_seconds,
                            p.success_probability,
                        )
                    })
                    .unwrap_or_else(|| {
                        (
                            0.0,
                            session.candidates.clone(),
                            session.elapsed,
                            estimated_probability,
                        )
                    });
                ui.add_space(12.0);
                ui.columns(3, |cols| {
                    metric(&mut cols[0], "Search speed", &speed(rate));
                    metric(&mut cols[1], "Attempts", &candidates);
                    metric(&mut cols[2], "Elapsed time", &duration(elapsed));
                });
                ui.add_space(12.0);
                if probability.is_finite() {
                    ui.label(format!(
                        "Match probability after this effort: {:.2}%",
                        probability * 100.0
                    ))
                    .help_text(text::PROBABILITY);
                    ui.add(
                        egui::ProgressBar::new(probability as f32)
                            .desired_height(5.0)
                            .fill(p.accent),
                    )
                    .help_text(text::PROBABILITY);
                } else {
                    note(
                        ui,
                        match &estimate {
                            None => text::ESTIMATE_PENDING,
                            Some(Err(error)) => error,
                            Some(Ok(value)) if !value.exact_model && value.samples == 0 => {
                                text::SAMPLE_UNAVAILABLE
                            }
                            _ => text::NO_SAMPLE,
                        },
                    );
                }
                note(
                    ui,
                    "This value is a probability. It does not show search completion.",
                );
                ui.add_space(6.0);
                ui.collapsing("Device details", |ui| {
                    if !self.engine.execution_origin.is_empty() {
                        note(
                            ui,
                            &format!("Configuration: {}", self.engine.execution_origin),
                        );
                        note(ui, &self.engine.execution_diagnostics);
                    }
                    if let Some(progress) = &self.engine.progress {
                        for worker in &progress.workers {
                            ui.label(RichText::new(&worker.name).strong());
                            ui.label(format!(
                                "{} · Batches: {} · {}",
                                speed(worker.candidates as f64 / worker.seconds.max(1e-9)),
                                worker.batches,
                                worker.status
                            ));
                            note(ui, &worker.diagnostics.to_string());
                        }
                        for error in &progress.errors {
                            ui.colored_label(ui.visuals().error_fg_color, error);
                        }
                        note(ui, &format!("Checkpoint: {}", progress.checkpoint));
                    } else {
                        note(ui, "No active device measurements.");
                    }
                });
            });
        }
        if let Some(address) = &session.address {
            if session.kind == crate::split::SessionKind::Worker {
                ui.add_space(16.0);
                card(ui).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.heading("Public search result");
                    ui.add(egui::Label::new(RichText::new(address).monospace().size(16.0)).wrap());
                    note(ui, text::SPLIT_WORKER_MATCH);
                });
            } else {
                ui.add_space(16.0);
                card(ui).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.heading(
                        if self.engine.state == State::Completed && self.engine.verified_this_run {
                            "Saved wallet"
                        } else if self.engine.state == State::Completed {
                            "Saved export record"
                        } else {
                            "Match found"
                        },
                    );
                    ui.add(egui::Label::new(RichText::new(address).monospace().size(16.0)).wrap());
                    note(
                        ui,
                        &format!("Address prefix: {}", session.job.pattern.prefix),
                    );
                    if !self.engine.verified_this_run {
                        note(
                            ui,
                            if session.receipt.is_some() {
                                text::EXPORT_RECORD
                            } else if session.kind == crate::split::SessionKind::Owner {
                                text::SPLIT_OWNER_MATCH
                            } else {
                                text::MATCH
                            },
                        );
                    }
                    if ui
                        .add_enabled(
                            self.engine.verified_this_run,
                            egui::Button::new("Copy address"),
                        )
                        .help_text(text::COPY)
                        .clicked()
                    {
                        ui.ctx().copy_text(address.clone());
                    }
                    if let Some(receipt) = &session.receipt {
                        ui.label(
                            RichText::new(if self.engine.verified_this_run {
                                "Wallet check: correct."
                            } else {
                                "A wallet check is necessary."
                            })
                            .color(p.accent),
                        );
                        ui.add(egui::Label::new(receipt.wallet.display().to_string()).wrap());
                        ui.horizontal_wrapped(|ui| {
                            if ui
                                .add_enabled(self.available(), egui::Button::new("Do wallet check"))
                                .help_text(text::CHECK)
                                .clicked()
                            {
                                self.passwords = Some(PasswordForm::new(PasswordStep::Verify));
                            }
                            if ui
                                .add_enabled(
                                    self.available(),
                                    egui::Button::new("Save new encrypted copy"),
                                )
                                .help_text(if session.kind == crate::split::SessionKind::Owner {
                                    text::SPLIT_ANOTHER_COPY
                                } else {
                                    text::ANOTHER_COPY
                                })
                                .clicked()
                            {
                                self.passwords = Some(PasswordForm::new(PasswordStep::Unlock));
                            }
                            if ui.button("Open wallet folder").clicked()
                                && let Some(path) = receipt.wallet.parent()
                            {
                                self.fault(open_folder(path));
                            }
                        });
                        ui.collapsing("Native import file", |ui| {
                            ui.colored_label(ui.visuals().warn_fg_color, text::NATIVE);
                            ui.label(format!("Format: {}", native_format(session.job.profile())));
                            if ui
                                .add_enabled(
                                    self.available(),
                                    egui::Button::new("Export native import file"),
                                )
                                .help_text(text::NATIVE)
                                .clicked()
                            {
                                self.passwords = Some(PasswordForm::new(PasswordStep::Native));
                            }
                        });
                    } else if ui
                        .add_enabled(
                            self.available() && self.engine.state == State::MatchFound,
                            primary(
                                ui,
                                if session.kind == crate::split::SessionKind::Owner {
                                    "Combine and save wallet"
                                } else {
                                    "Save wallet"
                                },
                            )
                            .min_size(egui::vec2(ui.available_width(), 40.0)),
                        )
                        .help_text(text::SAVE)
                        .clicked()
                    {
                        self.passwords = Some(PasswordForm::new(PasswordStep::Unlock));
                    }
                });
            }
        }
        ui.add_space(12.0);
        ui.collapsing("Recovery files", |ui| match session.kind {
            crate::split::SessionKind::Owner => note(ui, text::SPLIT_OWNER_RECOVERY),
            crate::split::SessionKind::Worker => note(ui, text::SPLIT_WORKER_RECOVERY),
            crate::split::SessionKind::Local => {
                note(ui, text::RECOVERY);
                ui.label("Session files: job.json and seed.keystore.json");
                if session.job.profile().key_family() == crate::chains::KeyFamily::Ed25519 {
                    ui.label("Ed25519 match file: hit.keystore.json");
                }
                ui.label("Also keep checkpoint.json and results.json if present.");
            }
        });
        ui.collapsing("Session details and actions", |ui| {
            note(ui, &format!("Session ID: {}", session.job.session_id));
            note(ui, &format!("Session date: {}", date(session.created)));
            ui.add(egui::Label::new(session.directory.display().to_string()).wrap());
            ui.horizontal_wrapped(|ui| {
                if ui.button("Open session folder").clicked() {
                    self.fault(open_folder(&session.directory));
                }
                if ui
                    .add_enabled(self.available(), egui::Button::new("Read session log"))
                    .help_text(text::LOGS)
                    .clicked()
                {
                    let result = self.engine.logs();
                    self.fault(result);
                    self.diagnostics = true;
                }
            });
        });
    }
    pub(super) fn help_dialog(&mut self, ctx: &egui::Context) {
        egui::Window::new("Help")
            .open(&mut self.help)
            .default_width(600.0)
            .max_height(620.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.heading("Find an address and save the wallet");
                    for (i, step) in text::HELP_STEPS.iter().enumerate() {
                        ui.label(format!("{}. {step}", i + 1));
                    }
                    ui.separator();
                    ui.heading("Split-key search");
                    for (i, step) in text::SPLIT_HELP_STEPS.iter().enumerate() {
                        ui.label(format!("{}. {step}", i + 1));
                    }
                    ui.colored_label(ui.visuals().warn_fg_color, text::SPLIT_SHARE);
                    ui.separator();
                    ui.heading("Recovery");
                    note(ui, text::RECOVERY);
                    ui.label("Keep job.json and seed.keystore.json in the session folder.");
                    ui.label("For an Ed25519 match, also keep hit.keystore.json.");
                    ui.label("Keep checkpoint.json and results.json if present.");
                    ui.separator();
                    ui.heading("Terms");
                    for (term, description) in [
                        ("Session", "The files and settings for one address search."),
                        (
                            "Address prefix",
                            "The first characters that the address must contain.",
                        ),
                        (
                            "Mainnet",
                            "The production blockchain network. Test networks are not available.",
                        ),
                        ("Expected attempts", text::EXPECTED),
                        ("Mean search time", text::MEAN_TIME),
                        ("Match probability", text::PROBABILITY),
                        (
                            "Encrypted wallet",
                            "A wallet file that requires a password to read its private key.",
                        ),
                        ("Native import file", text::NATIVE),
                    ] {
                        ui.label(RichText::new(term).strong());
                        note(ui, description);
                    }
                });
            });
    }
    pub(super) fn diagnostics_dialog(&mut self, ctx: &egui::Context) {
        if !self.diagnostics {
            return;
        }
        let mut open = true;
        egui::Window::new("Diagnostics")
            .open(&mut open)
            .default_width(660.0)
            .max_height(640.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("diagnostics-content")
                    .show(ui, |ui| {
                        ui.heading("Hardware and measurements");
                        let profile = self.engine.settings.profile;
                        note(
                            ui,
                            &format!(
                                "Profile: {} · {}",
                                profile.chain.label(),
                                profile.address_type.label()
                            ),
                        );
                        if let Some(hardware) = &self.engine.hardware {
                            ui.label(&hardware.cpu);
                            for device in &hardware.devices {
                                ui.label(format!(
                                    "GPU {}: {} · {}",
                                    device.index, device.name, device.vendor
                                ));
                                note(ui, &format!("Driver: {}", device.driver));
                                note(
                                    ui,
                                    if device.suitable {
                                        "OpenCL device available."
                                    } else {
                                        "The search engine cannot use this device."
                                    },
                                );
                            }
                            if let Some(warning) = &hardware.warning {
                                ui.colored_label(ui.visuals().warn_fg_color, warning);
                            }
                        } else {
                            note(ui, "Select Detect hardware to read the available devices.");
                        }
                        ui.add_enabled_ui(self.available(), |ui| {
                            ui.horizontal_wrapped(|ui| {
                                if ui
                                    .button("Detect hardware")
                                    .help_text("Read the CPU and OpenCL device information.")
                                    .clicked()
                                {
                                    let result = self.engine.detect_hardware();
                                    self.fault(result);
                                }
                                if ui
                                    .button("Do benchmark")
                                    .help_text(text::BENCHMARK)
                                    .clicked()
                                {
                                    let result =
                                        self.engine.benchmark(self.engine.settings.config());
                                    self.fault(result);
                                }
                            });
                        });
                        self.calibration_controls(ui);
                        if self.engine.busy() && !self.engine.calibrating() {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(self.engine.state.label());
                                // Do not cancel a wallet or search task through the diagnostic window.
                                if matches!(
                                    self.engine.state,
                                    State::Idle
                                        | State::Paused
                                        | State::Completed
                                        | State::MatchFound
                                        | State::Error
                                ) && ui.button("Cancel diagnostic operation").clicked()
                                {
                                    self.engine.cancel_diagnostic();
                                }
                            });
                        }
                        ui.separator();
                        note(
                            ui,
                            "Diagnostic output contains technical data and device messages.",
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(&self.engine.diagnostic)
                                    .monospace()
                                    .size(12.0),
                            )
                            .wrap(),
                        );
                        if let Some(error) = &self.engine.error {
                            ui.colored_label(ui.visuals().error_fg_color, error);
                        }
                        ui.separator();
                        note(
                            ui,
                            &format!(
                                "Vanity Pro {} · {}",
                                env!("CARGO_PKG_VERSION"),
                                std::env::consts::ARCH
                            ),
                        );
                    });
            });
        self.diagnostics = open;
    }
}

fn display_prefix(profile: crate::chains::Profile, prefix: &str) -> String {
    if profile.is_evm() {
        format!("0x{prefix}")
    } else {
        prefix.to_owned()
    }
}

fn profile_details(profile: crate::chains::Profile) -> String {
    let mut details = format!(
        "Mainnet. Native import format: {}. ",
        native_format(profile)
    );
    if profile.is_evm() {
        details.push_str(text::EVM);
    }
    if profile.key_family() == crate::chains::KeyFamily::Ed25519 {
        details.push_str(text::ED25519);
    }
    if profile.chain == crate::chains::Chain::Xrp {
        details.push_str(text::XRP);
    }
    if profile.chain == crate::chains::Chain::Warthog {
        details.push_str(text::WARTHOG);
        details.push(' ');
        details.push_str(text::WARTHOG_IMPORT);
    }
    details
}

fn prefix_rules(profile: crate::chains::Profile) -> &'static str {
    use crate::chains::{Chain, Encoding};
    if profile.is_evm() {
        return "Use 0-9 and A-F. The match ignores letter case. You can paste 0x.";
    }
    if profile.chain == Chain::Warthog {
        return "Use 0-9 and A-F. Do not enter 0x. The application changes letters to lowercase.";
    }
    match profile.encoding() {
        Encoding::Bech32 { .. } | Encoding::Cashaddr => {
            "Use the full address prefix. Use lowercase Bech32 characters. Do not use b, i, o, or 1 in the payload."
        }
        Encoding::Base58 { .. } | Encoding::Solana => {
            "Use the full address prefix. Letter case must agree. Do not use 0, O, I, or lowercase l."
        }
        Encoding::StrKey | Encoding::Algorand => {
            "Use the full address prefix. Use uppercase A-Z and digits 2-7."
        }
        _ => {
            "Use the full address prefix. Use the character set and letter case for this address type."
        }
    }
}

fn native_format(profile: crate::chains::Profile) -> &'static str {
    if profile.is_evm() {
        "Raw private key in hexadecimal"
    } else {
        profile.info().export
    }
}
