//! Native presentation only. Secret fields are ephemeral, never serialized or logged.
use crate::coordinator::Mode;
use crate::desktop::{self, Controller, Settings, State, Theme};
use anyhow::{Context, Result, ensure};
use eframe::egui::{self, Color32, RichText};
use std::{
    path::{Path, PathBuf},
    sync::mpsc,
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

#[path = "gui_text.rs"]
mod text;
#[path = "gui_views.rs"]
mod views;

/// Supplemental help is available through pointer hover and keyboard focus.
trait TooltipHelp {
    fn help_text(self, text: impl Into<egui::WidgetText>) -> Self;
}
impl TooltipHelp for egui::Response {
    fn help_text(self, text: impl Into<egui::WidgetText>) -> Self {
        let text = text.into();
        if self.has_focus() {
            if self.ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
                self.surrender_focus();
            } else {
                egui::Tooltip::for_widget(&self).show(|ui| {
                    ui.label(text);
                });
            }
            self
        } else {
            self.on_hover_text(text)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Generate,
    Split,
    Sessions,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum PasswordStep {
    Seed,
    Owner,
    Unlock,
    Wallet,
    Verify,
    Resume,
    Native,
}
struct PasswordForm {
    step: PasswordStep,
    password: Zeroizing<String>,
    confirmation: Zeroizing<String>,
    show: bool,
    focus: bool,
    error: Option<String>,
}
impl PasswordForm {
    fn new(step: PasswordStep) -> Self {
        Self {
            step,
            password: Zeroizing::new(String::new()),
            confirmation: Zeroizing::new(String::new()),
            show: false,
            focus: true,
            error: None,
        }
    }
}
#[derive(Clone, Copy)]
enum Pick {
    Sessions,
    Wallets,
    Export,
    NativeExport,
    SplitRequestImport,
    SplitRequestExport,
    SplitResultImport,
    SplitResultExport,
}
type PickerResult = Result<(Pick, Option<PathBuf>)>;
type EstimateResult = std::result::Result<crate::chains::difficulty::Estimate, String>;
struct App {
    engine: Controller,
    view: View,
    help: bool,
    prefix: String,
    split_create: bool,
    split_preview: Option<crate::split::SplitRequest>,
    estimate: Option<(crate::crypto::Pattern, EstimateResult)>,
    estimate_task: Option<(crate::crypto::Pattern, mpsc::Receiver<EstimateResult>)>,
    estimate_pending: Option<crate::crypto::Pattern>,
    passwords: Option<PasswordForm>,
    settings: Option<Settings>,
    diagnostics: bool,
    picker: Option<mpsc::Receiver<PickerResult>>,
    delete: Option<PathBuf>,
    delete_kind: crate::split::SessionKind,
    delete_text: String,
    close_confirm: bool,
    closing: bool,
    startup_history: bool,
    startup_hardware: bool,
    #[cfg(test)]
    test_export_path: Option<PathBuf>,
}
impl App {
    fn new(cc: &eframe::CreationContext<'_>, data: PathBuf) -> Self {
        // Use the installed Windows font. Retain bundled fonts as a fallback.
        if let Some(windows) = std::env::var_os("WINDIR") {
            let fonts = PathBuf::from(windows).join("Fonts");
            if let Ok(bytes) = std::fs::read(fonts.join("segoeui.ttf")) {
                let mut definitions = egui::FontDefinitions::default();
                definitions.font_data.insert(
                    "windows-ui".into(),
                    egui::FontData::from_owned(bytes).into(),
                );
                definitions
                    .families
                    .entry(egui::FontFamily::Proportional)
                    .or_default()
                    .insert(0, "windows-ui".into());
                cc.egui_ctx.set_fonts(definitions);
            }
        }
        views::configure_style(&cc.egui_ctx);
        Self {
            engine: Controller::new(data),
            view: View::Generate,
            help: false,
            prefix: String::new(),
            split_create: false,
            split_preview: None,
            estimate: None,
            estimate_task: None,
            estimate_pending: None,
            passwords: None,
            settings: None,
            diagnostics: false,
            picker: None,
            delete: None,
            delete_kind: crate::split::SessionKind::Local,
            delete_text: String::new(),
            close_confirm: false,
            closing: false,
            startup_history: true,
            startup_hardware: true,
            #[cfg(test)]
            test_export_path: None,
        }
    }
    fn fault(&mut self, result: Result<()>) {
        if let Err(e) = result {
            self.engine.error = Some(format!("{e:#}"));
        }
    }
    fn available(&self) -> bool {
        !self.engine.busy() && self.picker.is_none() && !self.closing
    }
    /// At most one public-only probability task runs. Input changes retain only the latest pending pattern.
    fn probability_estimate(&mut self, pattern: &crate::crypto::Pattern) -> Option<EstimateResult> {
        if let Some((saved, result)) = &self.estimate
            && saved == pattern
        {
            self.estimate_pending = None;
            return Some(result.clone());
        }
        self.estimate_pending = Some(pattern.clone());
        if self.estimate_task.is_none()
            && let Some(pattern) = self.estimate_pending.take()
        {
            let (sender, receiver) = mpsc::channel();
            let public_pattern = pattern.clone();
            match std::thread::Builder::new()
                .name("address-probability".into())
                .spawn(move || {
                    let result = public_pattern
                        .estimate()
                        .map_err(|error| format!("{error:#}"));
                    let _ = sender.send(result);
                }) {
                Ok(_) => self.estimate_task = Some((pattern, receiver)),
                Err(error) => {
                    self.estimate = Some((
                        pattern,
                        Err(format!("Probability estimate unavailable: {error}")),
                    ))
                }
            }
        }
        None
    }
    fn clear_passwords(&mut self, ctx: &egui::Context) {
        self.passwords = None;
        ctx.data_mut(|d| {
            d.remove::<egui::text_edit::TextEditState>(egui::Id::new("secret-password"));
            d.remove::<egui::text_edit::TextEditState>(egui::Id::new("secret-confirmation"));
        });
    }
    fn pick(&mut self, kind: Pick) -> Result<()> {
        ensure!(self.picker.is_none(), "a file dialog is already open");
        #[cfg(test)]
        if !matches!(kind, Pick::Sessions | Pick::Wallets)
            && let Some(path) = self.test_export_path.take()
        {
            let (tx, rx) = mpsc::channel();
            tx.send(Ok((kind, Some(path))))?;
            self.picker = Some(rx);
            return Ok(());
        }
        let settings = self
            .settings
            .as_ref()
            .unwrap_or(&self.engine.settings)
            .clone();
        let suggested = self
            .engine
            .session
            .as_ref()
            .map(|s| {
                format!("{:?}-{}.json", s.job.profile().chain, s.job.session_id)
                    .to_ascii_lowercase()
            })
            .unwrap_or_else(|| "vanity-wallet.json".into());
        let (tx, rx) = mpsc::channel();
        self.picker = Some(rx);
        std::thread::spawn(move || {
            let result = (|| -> Result<_> {
                let selected = match kind {
                    Pick::Sessions => rfd::FileDialog::new()
                        .set_title("Select session storage folder")
                        .set_directory(&settings.sessions_root)
                        .pick_folder(),
                    Pick::Wallets => rfd::FileDialog::new()
                        .set_title("Select default wallet export folder")
                        .set_directory(&settings.wallets_root)
                        .pick_folder(),
                    Pick::NativeExport => {
                        desktop::create_root(&settings.wallets_root)?;
                        rfd::FileDialog::new()
                            .set_title("Save unencrypted native wallet import file")
                            .add_filter("Native wallet file", &["json", "txt"])
                            .set_directory(&settings.wallets_root)
                            .set_file_name(format!("native-{suggested}"))
                            .save_file()
                    }
                    Pick::Export => {
                        desktop::create_root(&settings.wallets_root)?;
                        rfd::FileDialog::new()
                            .set_title("Save encrypted wallet")
                            .add_filter("Encrypted wallet", &["json"])
                            .set_directory(&settings.wallets_root)
                            .set_file_name(&suggested)
                            .save_file()
                    }
                    Pick::SplitRequestImport => rfd::FileDialog::new()
                        .set_title("Open public search request")
                        .add_filter("Public search request", &["json"])
                        .set_directory(&settings.wallets_root)
                        .pick_file(),
                    Pick::SplitResultImport => rfd::FileDialog::new()
                        .set_title("Open public search result")
                        .add_filter("Public search result", &["json"])
                        .set_directory(&settings.wallets_root)
                        .pick_file(),
                    Pick::SplitRequestExport | Pick::SplitResultExport => {
                        desktop::create_root(&settings.wallets_root)?;
                        let request = matches!(kind, Pick::SplitRequestExport);
                        rfd::FileDialog::new()
                            .set_title(if request {
                                "Save public search request"
                            } else {
                                "Save public search result"
                            })
                            .add_filter("Public search file", &["json"])
                            .set_directory(&settings.wallets_root)
                            .set_file_name(format!(
                                "{}-{suggested}",
                                if request { "request" } else { "result" }
                            ))
                            .save_file()
                    }
                };
                Ok((kind, selected))
            })();
            let _ = tx.send(result);
        });
        Ok(())
    }
    fn poll(&mut self, ctx: &egui::Context) {
        self.engine.poll();
        if let Some((pattern, receiver)) = &self.estimate_task {
            let result = match receiver.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err("Probability estimate unavailable.".into()))
                }
            };
            if let Some(result) = result {
                self.estimate = Some((pattern.clone(), result));
                self.estimate_task = None;
            }
        }
        let picked = self.picker.as_ref().and_then(|rx| match rx.try_recv() {
            Ok(r) => Some(r),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => {
                Some(Err(anyhow::anyhow!("File dialog closed unexpectedly")))
            }
        });
        if let Some(picked) = picked {
            self.picker = None;
            match picked {
                Ok((kind, Some(path))) => match kind {
                    Pick::Sessions => {
                        if let Some(s) = &mut self.settings {
                            s.sessions_root = path
                        }
                    }
                    Pick::Wallets => {
                        if let Some(s) = &mut self.settings {
                            s.wallets_root = path
                        }
                    }
                    Pick::NativeExport => {
                        if let Some(f) = &mut self.passwords {
                            let password =
                                std::mem::replace(&mut f.password, Zeroizing::new(String::new()));
                            match self.engine.export_native_wallet(path, password) {
                                Err(e) => f.error = Some(format!("{e:#}")),
                                Ok(()) => self.clear_passwords(ctx),
                            }
                        }
                    }
                    Pick::Export => {
                        if let Some(f) = &mut self.passwords {
                            let password =
                                std::mem::replace(&mut f.password, Zeroizing::new(String::new()));
                            let result = self.engine.export(path, password, &f.confirmation);
                            if let Err(e) = result {
                                f.error = Some(format!("{e:#}"));
                            } else {
                                self.clear_passwords(ctx);
                            }
                        }
                    }
                    Pick::SplitRequestImport => match crate::split::read_request(&path) {
                        Ok(request) => {
                            self.reset_search();
                            self.engine.settings.profile = request.job.profile();
                            self.engine.settings.benchmark_per_second = None;
                            self.split_preview = Some(request);
                            self.view = View::Split;
                        }
                        Err(error) => self.engine.error = Some(format!("{error:#}")),
                    },
                    Pick::SplitRequestExport => {
                        let result = self.engine.save_split_request(path);
                        self.fault(result);
                    }
                    Pick::SplitResultImport => {
                        let result = self.engine.import_split_result(path);
                        self.fault(result);
                    }
                    Pick::SplitResultExport => {
                        let result = self.engine.save_split_result(path);
                        self.fault(result);
                    }
                },
                Ok((_, None)) => {}
                Err(e) => self.engine.error = Some(format!("{e:#}")),
            }
        }
        if self.engine.unlocked_password.is_some() && self.passwords.is_none() && !self.closing {
            self.passwords = Some(PasswordForm::new(PasswordStep::Wallet));
        }
        if !self.engine.busy() && !self.closing {
            if self.startup_history {
                self.startup_history = false;
                let r = self.engine.refresh_history();
                self.fault(r);
            } else if self.startup_hardware {
                self.startup_hardware = false;
                if self.engine.settings.detect_hardware {
                    let r = self.engine.detect_hardware();
                    self.fault(r);
                }
            }
        }
        if self.closing {
            self.engine.shutdown();
            if !self.engine.busy() && self.picker.is_none() {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }
    fn password_dialog(&mut self, ctx: &egui::Context) {
        let Some(mut form) = self.passwords.take() else {
            return;
        };
        let owner = self
            .engine
            .session
            .as_ref()
            .is_some_and(|session| session.kind == crate::split::SessionKind::Owner);
        let title = match form.step {
            PasswordStep::Seed => "Set session password",
            PasswordStep::Owner => "Set private share password",
            PasswordStep::Unlock => {
                if owner {
                    "Unlock private share"
                } else {
                    "Unlock session"
                }
            }
            PasswordStep::Wallet => "Set wallet password",
            PasswordStep::Verify => "Do wallet check",
            PasswordStep::Resume => "Resume CPU search",
            PasswordStep::Native => "Export native import file",
        };
        let mut submit = false;
        let mut cancel = false;
        let response = egui::Modal::new(egui::Id::new("password-dialog")).show(ctx, |ui| {
            ui.set_width(430.0);
            ui.heading(title);
            ui.label(match form.step {
                PasswordStep::Native => text::NATIVE,
                PasswordStep::Resume => text::RESUME_PASSWORD,
                PasswordStep::Seed => text::SEED_PASSWORD,
                PasswordStep::Owner => text::SPLIT_SHARE_PASSWORD,
                PasswordStep::Unlock => {
                    if self
                        .engine
                        .session
                        .as_ref()
                        .is_some_and(|s| s.kind == crate::split::SessionKind::Owner)
                    {
                        text::SPLIT_UNLOCK
                    } else {
                        text::UNLOCK_PASSWORD
                    }
                }
                PasswordStep::Wallet => text::WALLET_PASSWORD,
                PasswordStep::Verify => text::CHECK_PASSWORD,
            });
            ui.add_space(8.0);
            let label = ui.label(if form.step == PasswordStep::Unlock {
                if owner {
                    "Private share password"
                } else {
                    "Session password"
                }
            } else if matches!(form.step, PasswordStep::Verify | PasswordStep::Native) {
                "Wallet password"
            } else {
                "Password"
            });
            let mut field = egui::TextEdit::singleline(&mut *form.password)
                .id(egui::Id::new("secret-password"))
                .password(!form.show)
                .char_limit(1024)
                .desired_width(ui.available_width())
                .show(ui);
            egui::Response::clone(&field.response).labelled_by(label.id);
            if form.focus {
                field.response.request_focus();
                form.focus = false;
            }
            // egui otherwise retains plaintext undo snapshots even for masked fields.
            field.state.clear_undoer();
            field.state.store(ctx, field.response.id);
            if !matches!(
                form.step,
                PasswordStep::Unlock
                    | PasswordStep::Verify
                    | PasswordStep::Resume
                    | PasswordStep::Native
            ) {
                let label = ui.label("Confirm password");
                let mut field = egui::TextEdit::singleline(&mut *form.confirmation)
                    .id(egui::Id::new("secret-confirmation"))
                    .password(!form.show)
                    .char_limit(1024)
                    .desired_width(ui.available_width())
                    .show(ui);
                egui::Response::clone(&field.response).labelled_by(label.id);
                field.state.clear_undoer();
                field.state.store(ctx, field.response.id);
                ui.label(RichText::new(text::PASSWORD_LENGTH).weak().small());
            }
            ui.checkbox(&mut form.show, "Show passwords");
            if let Some(error) = &form.error {
                ui.colored_label(ui.visuals().error_fg_color, error);
            }
            let valid = if matches!(
                form.step,
                PasswordStep::Unlock
                    | PasswordStep::Verify
                    | PasswordStep::Resume
                    | PasswordStep::Native
            ) {
                !form.password.is_empty()
            } else {
                desktop::validate_password(&form.password, &form.confirmation).is_ok()
            };
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(self.available(), egui::Button::new("Cancel"))
                    .clicked()
                {
                    cancel = true;
                }
                let text = match form.step {
                    PasswordStep::Native => "Select file and export private key",
                    PasswordStep::Resume => "Unlock and resume",
                    PasswordStep::Seed => "Save session and start search",
                    PasswordStep::Owner => "Save private share",
                    PasswordStep::Unlock => {
                        if owner {
                            "Unlock private share"
                        } else {
                            "Unlock session"
                        }
                    }
                    PasswordStep::Wallet => "Select file and save wallet",
                    PasswordStep::Verify => "Decrypt wallet and do check",
                };
                if ui
                    .add_enabled(valid && self.available(), views::primary(ui, text))
                    .clicked()
                {
                    submit = true;
                }
            });
            if self.picker.is_some() {
                ui.label("Select a file in the Windows save dialog.");
            }
        });
        if response.should_close() && self.available() {
            cancel = true;
        }
        if cancel {
            form.password.zeroize();
            form.confirmation.zeroize();
            self.engine.cancel_finalization();
            self.clear_passwords(ctx);
            return;
        }
        if submit {
            match form.step {
                PasswordStep::Native => {
                    if let Err(e) = self.pick(Pick::NativeExport) {
                        form.error = Some(format!("{e:#}"));
                    }
                }
                PasswordStep::Resume => {
                    let pw = std::mem::replace(&mut form.password, Zeroizing::new(String::new()));
                    match self.engine.search_with_password(pw) {
                        Ok(()) => {
                            self.clear_passwords(ctx);
                            return;
                        }
                        Err(e) => form.error = Some(format!("{e:#}")),
                    }
                }
                PasswordStep::Seed => {
                    let pw = std::mem::replace(&mut form.password, Zeroizing::new(String::new()));
                    match self.engine.create(&self.prefix, pw, &form.confirmation) {
                        Ok(()) => {
                            self.clear_passwords(ctx);
                            return;
                        }
                        Err(e) => form.error = Some(format!("{e:#}")),
                    }
                }
                PasswordStep::Owner => {
                    let password =
                        std::mem::replace(&mut form.password, Zeroizing::new(String::new()));
                    match self.engine.create_split_request(
                        &self.prefix,
                        password,
                        &form.confirmation,
                    ) {
                        Ok(()) => {
                            self.split_create = false;
                            self.clear_passwords(ctx);
                            return;
                        }
                        Err(error) => form.error = Some(format!("{error:#}")),
                    }
                }
                PasswordStep::Unlock => {
                    let pw = std::mem::replace(&mut form.password, Zeroizing::new(String::new()));
                    match self.engine.unlock(pw) {
                        Ok(()) => {
                            self.clear_passwords(ctx);
                            return;
                        }
                        Err(e) => form.error = Some(format!("{e:#}")),
                    }
                }
                PasswordStep::Wallet => {
                    let r = self.pick(Pick::Export);
                    if let Err(e) = r {
                        form.error = Some(format!("{e:#}"));
                    }
                }
                PasswordStep::Verify => {
                    let pw = std::mem::replace(&mut form.password, Zeroizing::new(String::new()));
                    match self.engine.verify_saved_wallet(pw) {
                        Ok(()) => {
                            self.clear_passwords(ctx);
                            return;
                        }
                        Err(e) => form.error = Some(format!("{e:#}")),
                    }
                }
            }
        }
        self.passwords = Some(form);
    }
    fn settings_dialog(&mut self, ctx: &egui::Context) {
        let Some(mut settings) = self.settings.take() else {
            return;
        };
        let mut open = true;
        let mut save = false;
        egui::Window::new("Settings")
            .open(&mut open)
            .collapsible(false)
            .default_width(560.0)
            .max_height(620.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("settings-content")
                    .show(ui, |ui| {
                        ui.heading("Storage");
                        ui.label("Session folder").help_text(text::STORAGE);
                        ui.add(
                            egui::Label::new(settings.sessions_root.display().to_string()).wrap(),
                        );
                        if ui
                            .add_enabled(
                                self.available(),
                                egui::Button::new("Select session folder"),
                            )
                            .help_text(text::STORAGE)
                            .clicked()
                        {
                            let r = self.pick(Pick::Sessions);
                            self.fault(r);
                        }
                        ui.label("Default wallet folder").help_text(text::STORAGE);
                        ui.add(
                            egui::Label::new(settings.wallets_root.display().to_string()).wrap(),
                        );
                        if ui
                            .add_enabled(
                                self.available(),
                                egui::Button::new("Select wallet folder"),
                            )
                            .help_text(text::STORAGE)
                            .clicked()
                        {
                            let r = self.pick(Pick::Wallets);
                            self.fault(r);
                        }
                        ui.separator();
                        ui.heading("Appearance");
                        egui::ComboBox::from_id_salt("theme")
                            .selected_text(format!("Theme: {:?}", settings.theme))
                            .show_ui(ui, |ui| {
                                for theme in [Theme::System, Theme::Light, Theme::Dark] {
                                    ui.selectable_value(
                                        &mut settings.theme,
                                        theme,
                                        format!("{theme:?}"),
                                    );
                                }
                            })
                            .response
                            .help_text("Use the Windows theme, a light theme, or a dark theme.");
                        ui.checkbox(
                            &mut settings.detect_hardware,
                            "Detect hardware at application start",
                        )
                        .help_text("Read the CPU and GPU information when the application starts.");
                        ui.separator();
                        ui.heading("Compute preferences");
                        if settings.profile.key_family() == crate::chains::KeyFamily::Ed25519 {
                            settings.mode = Mode::Cpu;
                            ui.label("CPU only · Ed25519").help_text(text::ED25519);
                        } else {
                            mode_combo(ui, "settings-mode", &mut settings.mode);
                        }
                        performance(ui, &mut settings, self.engine.hardware.as_ref());
                        let standard_ed25519 = settings.profile.key_family()
                            == crate::chains::KeyFamily::Ed25519
                            && !cfg!(feature = "developer-tools");
                        if standard_ed25519 {
                            ui.label(text::ED25519_NO_CALIBRATION);
                        } else {
                            if ui
                                .add_enabled(
                                    self.available(),
                                    egui::Button::new("Recalibrate hardware"),
                                )
                                .help_text(text::RECALIBRATE)
                                .clicked()
                            {
                                let result = self.engine.recalibrate(&settings);
                                self.fault(result);
                            }
                            if !self.engine.busy() && !self.engine.execution_origin.is_empty() {
                                ui.label(format!(
                                    "Hardware configuration: {}",
                                    self.engine.execution_origin
                                ))
                                .help_text(&self.engine.execution_diagnostics);
                            }
                        }
                        self.calibration_controls(ui);
                        ui.separator();
                        ui.label(RichText::new(text::SETTINGS).weak().small());
                        if let Some(error) = &self.engine.error {
                            ui.colored_label(ui.visuals().error_fg_color, error);
                        }
                        if ui
                            .add_enabled(self.available(), views::primary(ui, "Save settings"))
                            .help_text(text::SETTINGS)
                            .clicked()
                        {
                            save = true;
                        }
                    });
            });
        if save {
            let refresh = settings.sessions_root != self.engine.settings.sessions_root;
            let result = self.engine.save_preferences(settings.clone());
            if result.is_ok() {
                open = false;
                if refresh {
                    self.startup_history = true;
                }
            }
            self.fault(result);
        }
        if open {
            self.settings = Some(settings);
        }
    }

    fn confirmations(&mut self, ctx: &egui::Context) {
        if let Some(path) = self.delete.clone() {
            let mut cancel = false;
            let mut remove = false;
            egui::Modal::new(egui::Id::new("delete-confirmation")).show(ctx, |ui| {
                ui.set_width(440.0);
                ui.heading("Delete session?");
                ui.colored_label(
                    ui.visuals().warn_fg_color,
                    if self.delete_kind == crate::split::SessionKind::Owner {
                        text::SPLIT_DELETE
                    } else {
                        text::DELETE
                    },
                );
                ui.label(path.display().to_string());
                let label = ui.label("Type DELETE to confirm");
                ui.text_edit_singleline(&mut self.delete_text)
                    .labelled_by(label.id);
                ui.horizontal(|ui| {
                    if ui.button("Keep session").clicked() {
                        cancel = true;
                    }
                    if ui
                        .add_enabled(
                            self.available() && self.delete_text == "DELETE",
                            egui::Button::new("Delete session"),
                        )
                        .clicked()
                    {
                        remove = true;
                    }
                });
            });
            if cancel {
                self.delete = None;
                self.delete_kind = crate::split::SessionKind::Local;
                self.delete_text.clear();
            }
            if remove {
                let r = self.engine.delete(path, &self.delete_text);
                self.fault(r);
                self.delete = None;
                self.delete_kind = crate::split::SessionKind::Local;
                self.delete_text.clear();
            }
        }
        if self.close_confirm {
            let mut keep = false;
            let mut close = false;
            egui::Modal::new(egui::Id::new("close-confirmation")).show(ctx, |ui| {
                ui.set_width(440.0);
                ui.heading("Close Vanity Pro?");
                ui.label(if self.engine.state == State::Finalizing {
                    text::CLOSE_EXPORT
                } else {
                    text::CLOSE
                });
                ui.horizontal(|ui| {
                    if ui.button("Keep open").clicked() {
                        keep = true;
                    }
                    if ui.button("Save progress and close").clicked() {
                        close = true;
                    }
                });
            });
            if keep {
                self.close_confirm = false;
            }
            if close {
                self.close_confirm = false;
                self.closing = true;
                self.engine.shutdown();
                self.clear_passwords(ctx);
            }
        }
    }
}
impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);
        ctx.request_repaint_after(Duration::from_millis(200));
    }
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        ctx.set_theme(match self.engine.settings.theme {
            Theme::System => egui::ThemePreference::System,
            Theme::Dark => egui::ThemePreference::Dark,
            Theme::Light => egui::ThemePreference::Light,
        });
        if ctx.input(|i| i.viewport().close_requested())
            && !self.closing
            && (self.engine.busy() || self.picker.is_some() || self.passwords.is_some())
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.close_confirm = true;
        }
        views::configure_style(&ctx);
        let palette = views::palette(ui);
        egui::Panel::bottom("status")
            .frame(
                egui::Frame::new()
                    .fill(palette.surface)
                    .inner_margin(egui::Margin::symmetric(16, 8)),
            )
            .resizable(false)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(self.engine.state.label())
                            .size(12.0)
                            .color(palette.accent),
                    );
                    ui.separator();
                    ui.label(
                        RichText::new("18 networks · 21 address profiles · Mainnet")
                            .size(12.0)
                            .color(palette.muted),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!("Vanity Pro {}", env!("CARGO_PKG_VERSION")))
                                .size(12.0)
                                .color(palette.muted),
                        );
                    });
                });
            });
        egui::Panel::left("navigation")
            .resizable(false)
            .exact_size(220.0)
            .frame(egui::Frame::new().fill(palette.surface).inner_margin(16))
            .show(ui, |ui| {
                self.sidebar(ui);
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(palette.canvas).inner_margin(24))
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("workspace")
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        match self.view {
                            View::Generate => self.main_view(ui),
                            View::Split => self.split_view(ui),
                            View::Sessions => self.sessions_view(ui),
                        }
                    });
            });
        self.settings_dialog(&ctx);
        self.diagnostics_dialog(&ctx);
        if self.help {
            self.help_dialog(&ctx);
        }
        self.password_dialog(&ctx);
        self.confirmations(&ctx);
    }
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.engine.shutdown();
        self.passwords = None;
    }
}
fn metric(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(RichText::new(label).weak().size(12.0));
    ui.label(RichText::new(value).strong().size(22.0));
}
pub fn speed(rate: f64) -> String {
    if rate >= 1e9 {
        format!("{:.2} G/s", rate / 1e9)
    } else if rate >= 1e6 {
        format!("{:.2} M/s", rate / 1e6)
    } else if rate >= 1e3 {
        format!("{:.1} K/s", rate / 1e3)
    } else {
        format!("{rate:.0}/s")
    }
}
pub fn duration(seconds: f64) -> String {
    if !seconds.is_finite() || seconds > 3.15e15 {
        "No finite estimate".into()
    } else if seconds >= 31_536_000.0 {
        format!("{:.1} years", seconds / 31_536_000.0)
    } else if seconds >= 86400.0 {
        format!("{:.1} days", seconds / 86400.0)
    } else if seconds >= 3600.0 {
        format!("{:.1} hours", seconds / 3600.0)
    } else if seconds >= 60.0 {
        format!("{:.1} min", seconds / 60.0)
    } else {
        format!("{seconds:.1} s")
    }
}
fn number(value: f64) -> String {
    if value >= 1e15 {
        format!("{value:.3e}")
    } else {
        let s = format!("{value:.0}");
        let mut result = String::new();
        for (i, c) in s.chars().enumerate() {
            if i > 0 && (s.len() - i).is_multiple_of(3) {
                result.push(',');
            }
            result.push(c);
        }
        result
    }
}
fn date(seconds: u64) -> String {
    // Gregorian civil-date conversion, UTC; history timestamps are explicitly labelled.
    let days = (seconds / 86400) as i64 + 719468;
    let era = days / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let y = y + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        seconds / 3600 % 24,
        seconds / 60 % 60
    )
}
fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Auto => "Automatic",
        Mode::Cpu => "CPU only",
        Mode::Opencl => "OpenCL GPU only",
    }
}
fn mode_combo(ui: &mut egui::Ui, id: &str, mode: &mut Mode) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(mode_name(*mode))
        .show_ui(ui, |ui| {
            for m in [Mode::Auto, Mode::Cpu, Mode::Opencl] {
                ui.selectable_value(mode, m, mode_name(m));
            }
        })
        .response
        .help_text(text::AUTO);
}
fn performance(ui: &mut egui::Ui, s: &mut Settings, hardware: Option<&desktop::Hardware>) {
    let mut automatic_tuning = s.tuning == crate::backend::calibration::TuningMode::Auto;
    if ui.checkbox(&mut automatic_tuning, "Calibrate hardware automatically")
        .help_text("Measure this hardware before its first search and reuse validated settings. Turning this off reuses a validated cache when available and otherwise keeps the self-tested incumbent.")
        .changed() {
        s.tuning = if automatic_tuning { crate::backend::calibration::TuningMode::Auto } else { crate::backend::calibration::TuningMode::Off };
    }
    ui.horizontal(|ui| {
        ui.label("CPU workers").help_text(text::THREADS);
        ui.add(egui::DragValue::new(&mut s.threads).range(1..=256))
            .help_text(text::THREADS);
    });
    ui.horizontal(|ui| {
        ui.label("Maximum batch size").help_text(text::BATCH);
        ui.add(
            egui::DragValue::new(&mut s.batch_size)
                .range(1..=crate::backend::MAX_BATCH)
                .speed(1024),
        )
        .help_text(text::BATCH);
    });
    let mut limited = s.max_seconds.is_some();
    if ui
        .checkbox(&mut limited, "Pause after a time limit")
        .help_text(text::TIME_LIMIT)
        .changed()
    {
        s.max_seconds = if limited { Some(60.0) } else { None };
    }
    if let Some(seconds) = &mut s.max_seconds {
        ui.horizontal(|ui| {
            ui.add(egui::DragValue::new(seconds).range(0.1..=86400.0))
                .help_text(text::TIME_LIMIT);
            ui.label("seconds");
        });
    }
    let gpu_profile = s.profile.key_family() != crate::chains::KeyFamily::Ed25519;
    ui.add_enabled_ui(gpu_profile, |ui| {
        if let Some(h) = hardware {
            if !h.devices.is_empty() {
                ui.label("Enabled OpenCL devices").help_text(text::DEVICES);
            }
            for d in &h.devices {
                let mut enabled = !s.excluded_devices.contains(&d.index);
                if ui
                    .checkbox(&mut enabled, format!("{}: {}", d.index, d.name))
                    .help_text(text::DEVICES)
                    .changed()
                {
                    s.excluded_devices.retain(|i| *i != d.index);
                    if !enabled {
                        s.excluded_devices.push(d.index);
                    }
                }
            }
        }
    });
}
fn open_folder(path: &Path) -> Result<()> {
    let path_guard = crate::storage::read_guard(path)?;
    let path = path_guard.path();
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL};
    ensure!(path.is_dir(), "folder is unavailable");
    let folder: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let verb: Vec<u16> = "open".encode_utf16().chain(Some(0)).collect();
    // SAFETY: NUL-terminated folder/verb buffers live through the synchronous call.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            folder.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    ensure!(result as isize > 32, "Windows could not open the folder");
    Ok(())
}
pub fn icon() -> egui::IconData {
    let width = 64;
    let mut rgba = vec![0u8; width * width * 4];
    for y in 0..width {
        for x in 0..width {
            let i = (y * width + x) * 4;
            let v = y > 14
                && y < 51
                && ((x as i32 - (18 + (y - 14) / 3) as i32).abs() < 5
                    || (x as i32 - (46 - (y - 14) / 3) as i32).abs() < 5);
            let inside = (6..58).contains(&x) && (6..58).contains(&y);
            let pixel = if v {
                [224, 255, 246, 255]
            } else if inside {
                [20, 150, 154, 255]
            } else {
                [0, 0, 0, 0]
            };
            rgba[i..i + 4].copy_from_slice(&pixel);
        }
    }
    egui::IconData {
        rgba,
        width: width as u32,
        height: width as u32,
    }
}
pub fn run() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let data = match args.next() {
        Some(a) if a == "--data-dir" => {
            let path = PathBuf::from(args.next().context("--data-dir requires a folder")?);
            ensure!(path.is_absolute(), "--data-dir must be absolute");
            path
        }
        Some(_) => anyhow::bail!(
            "Only the optional --data-dir folder argument is supported; no password arguments are accepted"
        ),
        None => desktop::default_data_directory()?,
    };
    ensure!(args.next().is_none(), "unexpected GUI arguments");
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1060.0, 760.0])
            .with_min_inner_size([880.0, 640.0])
            .with_icon(icon())
            .with_app_id("VanityPro"),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native(
        "Vanity Pro",
        options,
        Box::new(move |cc| Ok(Box::new(App::new(cc, data)))),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui::accesskit::Role;
    use egui_kittest::{
        Harness,
        kittest::{NodeT, Queryable},
    };
    use std::time::Instant;

    fn harness(data: PathBuf) -> Harness<'static, App> {
        harness_at_size(data, egui::vec2(1060.0, 1100.0))
    }
    fn harness_at_size(data: PathBuf, size: egui::Vec2) -> Harness<'static, App> {
        Harness::builder().with_size(size).build_eframe(move |cc| {
            let mut app = App::new(cc, data);
            app.engine.settings.mode = Mode::Cpu;
            app.engine.settings.threads = 2;
            app.engine.settings.tuning = crate::backend::calibration::TuningMode::Off;
            app.startup_hardware = false;
            app
        })
    }
    fn wait(h: &mut Harness<'_, App>, condition: impl Fn(&App) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            h.step();
            if condition(h.state()) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "GUI workflow timed out: {:?}: {:?}",
                h.state().engine.state,
                h.state().engine.error
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn input(h: &mut Harness<'_, App>, role: Role, label: &str, text: &str) {
        h.get_by_role_and_label(role, label).focus();
        h.step();
        h.get_by_role_and_label(role, label).type_text(text);
        h.step();
    }
    fn click(h: &mut Harness<'_, App>, label: &str) {
        h.get_by_role_and_label(Role::Button, label).click();
        // Settle modal layout before targeting the next control.
        h.run_steps(3);
    }

    fn saved_session(h: &Harness<'_, App>, prefix: &str) -> desktop::Session {
        desktop::create_session(
            &h.state().engine.settings.sessions_root,
            desktop::validate_prefix(prefix).unwrap(),
            "throwaway seed password",
            Mode::Cpu,
        )
        .unwrap()
    }

    #[test]
    fn gui_probability_queue_keeps_latest_input_and_does_not_block_controls() {
        let temp = tempfile::tempdir().unwrap();
        let mut h = harness(temp.path().to_owned());
        wait(&mut h, |app| !app.engine.busy());
        let profile = crate::chains::Profile::new(crate::chains::Chain::Solana, None).unwrap();
        let pattern = crate::crypto::Pattern::for_profile(profile, "A", "").unwrap();
        let (_hold_task, receiver) = mpsc::channel::<EstimateResult>();
        h.state_mut().engine.settings.profile = profile;
        h.state_mut().prefix = "A".into();
        // A pending public task must not block text input or unrelated controls.
        h.state_mut().estimate_task = Some((pattern, receiver));
        h.run_steps(3);
        assert!(h.query_by_label(text::ESTIMATE_PENDING).is_some());
        input(&mut h, Role::TextInput, "Address prefix", "B");
        assert_eq!(h.state().prefix, "AB");
        assert_eq!(h.state().estimate_pending.as_ref().unwrap().prefix, "AB");
        assert!(h.state().available());
        click(&mut h, "Settings");
        assert!(h.state().settings.is_some());
    }

    #[test]
    fn gui_stale_probability_completion_does_not_replace_the_edited_pattern() {
        let temp = tempfile::tempdir().unwrap();
        let mut h = harness(temp.path().to_owned());
        wait(&mut h, |app| !app.engine.busy());
        let first = crate::crypto::Pattern::for_profile(crate::chains::Profile::default(), "a", "")
            .unwrap();
        let (sender, receiver) = mpsc::channel::<EstimateResult>();
        h.state_mut().prefix = "a".into();
        h.state_mut().engine.settings.benchmark_per_second = Some(1.0);
        h.state_mut().estimate_task = Some((first, receiver));
        h.run_steps(3);
        h.get_by_role_and_label(Role::TextInput, "Address prefix")
            .focus();
        h.step();
        h.key_press_modifiers(
            egui::Modifiers {
                ctrl: true,
                command: true,
                ..Default::default()
            },
            egui::Key::A,
        );
        h.step();
        h.get_by_role_and_label(Role::TextInput, "Address prefix")
            .type_text("ab");
        h.step();
        assert_eq!(
            h.get_by_role_and_label(Role::TextInput, "Address prefix")
                .value()
                .as_deref(),
            Some("ab")
        );
        sender
            .send(Ok(crate::chains::difficulty::Estimate {
                probability: Some(1.0 / 16.0),
                lower_95: 1.0 / 16.0,
                upper_95: 1.0 / 16.0,
                samples: 0,
                matches: 0,
                exact_model: true,
                model: "controlled exact estimate",
            }))
            .unwrap();
        h.step();
        assert_eq!(
            h.get_by_role_and_label(Role::TextInput, "Address prefix")
                .value()
                .as_deref(),
            Some("ab")
        );
        assert!(h.query_by_label("16").is_none());
        assert!(h.query_by_label("16.0 s").is_none());
        let deadline = Instant::now() + Duration::from_secs(10);
        while h.query_by_label("256").is_none() {
            assert!(
                Instant::now() < deadline,
                "The edited pattern did not get its own estimate"
            );
            h.step();
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(h.query_by_label("4.3 min").is_some());
        assert!(
            !h.get_by_role_and_label(Role::Button, "Find address")
                .accesskit_node()
                .is_disabled()
        );
    }

    #[test]
    fn gui_unavailable_sampling_has_no_eta_and_search_remains_available() {
        let temp = tempfile::tempdir().unwrap();
        let mut h = harness(temp.path().to_owned());
        wait(&mut h, |app| !app.engine.busy());
        let profile = crate::chains::Profile::new(crate::chains::Chain::Solana, None).unwrap();
        let pattern = crate::crypto::Pattern::for_profile(profile, "A", "").unwrap();
        let (sender, receiver) = mpsc::channel::<EstimateResult>();
        h.state_mut().engine.settings.profile = profile;
        h.state_mut().engine.settings.benchmark_per_second = Some(1_000.0);
        h.state_mut().prefix = "A".into();
        h.state_mut().estimate_task = Some((pattern, receiver));
        h.run_steps(3);
        sender
            .send(Ok(crate::chains::difficulty::Estimate {
                probability: None,
                lower_95: 0.0,
                upper_95: 1.0,
                samples: 0,
                matches: 0,
                exact_model: false,
                model: "public sampling unavailable",
            }))
            .unwrap();
        h.run_steps(3);
        assert!(h.query_by_label(text::SAMPLE_UNAVAILABLE).is_some());
        assert_eq!(h.get_all_by_label("No estimate").count(), 2);
        assert!(h.query_by_label(text::NO_RATE).is_none());
        assert!(h.query_by_label(text::NO_SAMPLE).is_none());
        assert!(
            !h.get_by_role_and_label(Role::Button, "Find address")
                .accesskit_node()
                .is_disabled()
        );
        click(&mut h, "Find address");
        assert!(h.query_by_label("Set session password").is_some());
    }

    #[test]
    fn gui_estimate_completion_keeps_first_action_click_at_the_same_position() {
        for (owner, profile, prefix) in [
            (false, crate::chains::Profile::default(), "a"),
            (
                false,
                crate::chains::Profile::new(crate::chains::Chain::Solana, None).unwrap(),
                "A",
            ),
            (true, crate::chains::Profile::default(), "a"),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let mut h = harness_at_size(temp.path().to_owned(), egui::vec2(1060.0, 760.0));
            wait(&mut h, |app| !app.engine.busy());
            let pattern = crate::crypto::Pattern::for_profile(profile, prefix, "").unwrap();
            let (sender, receiver) = mpsc::channel::<EstimateResult>();
            h.state_mut().engine.settings.profile = profile;
            h.state_mut().prefix = prefix.into();
            h.state_mut().estimate = None;
            h.state_mut().estimate_task = Some((pattern.clone(), receiver));
            if owner {
                h.state_mut().view = View::Split;
                h.state_mut().split_create = true;
            }
            h.run_steps(3);
            let action = if owner {
                "Create request"
            } else {
                "Find address"
            };
            let form = if owner {
                "Set private share password"
            } else {
                "Set session password"
            };
            let pending = h.get_by_role_and_label(Role::Button, action).rect();
            assert!(
                egui::Rect::from_min_max(egui::pos2(220.0, 0.0), egui::pos2(1060.0, 720.0))
                    .contains_rect(pending),
                "{action}: {pending:?}"
            );
            click(&mut h, action);
            assert!(h.query_by_label(form).is_some());
            click(&mut h, "Cancel");
            // Deliver completion after the pointer target was read, before its event frame.
            h.get_by_role_and_label(Role::Button, action).click();
            sender
                .send(Ok(crate::chains::difficulty::Estimate {
                    probability: Some(1.0 / 16.0),
                    lower_95: 0.06,
                    upper_95: 0.07,
                    samples: 32768,
                    matches: 2048,
                    exact_model: false,
                    model: "controlled public sample",
                }))
                .unwrap();
            h.run_steps(3);
            assert!(h.query_by_label(form).is_some());
            click(&mut h, "Cancel");
            assert_eq!(
                h.get_by_role_and_label(Role::Button, action).rect(),
                pending
            );
            h.get_by_role_and_label(Role::Button, "Expected attempts help")
                .focus();
            h.run_steps(3);
            assert!(
                h.query_by_label_contains("Sample matches: 2048 / 32768")
                    .is_some()
            );
            h.key_press(egui::Key::Escape);
            h.run_steps(3);
            let (sender, receiver) = mpsc::channel::<EstimateResult>();
            h.state_mut().estimate_task = Some((pattern, receiver));
            h.get_by_role_and_label(Role::Button, action).click();
            sender
                .send(Ok(crate::chains::difficulty::Estimate {
                    probability: None,
                    lower_95: 0.0,
                    upper_95: 1.0,
                    samples: 0,
                    matches: 0,
                    exact_model: false,
                    model: "public sampling unavailable",
                }))
                .unwrap();
            h.run_steps(3);
            assert!(h.query_by_label(form).is_some());
            click(&mut h, "Cancel");
            assert!(h.query_by_label(text::SAMPLE_UNAVAILABLE).is_some());
            assert_eq!(
                h.get_by_role_and_label(Role::Button, action).rect(),
                pending
            );
        }
    }

    #[test]
    fn gui_split_key_file_exchange_and_owner_wallet_flow() {
        use crate::split::SessionKind;
        let temp = tempfile::tempdir().unwrap();
        let mut h = harness(temp.path().to_owned());
        wait(&mut h, |app| !app.engine.busy());
        click(&mut h, "Split-key search");
        assert!(h.state().view == View::Split);
        click(&mut h, "Create request");
        assert!(h.query_by_label(text::SPLIT_SHARE).is_some());
        assert!(h.query_by_label("Compute mode help").is_none());
        input(&mut h, Role::TextInput, "Address prefix", "0xAB");
        click(&mut h, "Create request");
        assert!(h.state().passwords.as_ref().unwrap().step == PasswordStep::Owner);
        input(
            &mut h,
            Role::PasswordInput,
            "Password",
            "throwaway owner password",
        );
        input(
            &mut h,
            Role::PasswordInput,
            "Confirm password",
            "throwaway owner password",
        );
        click(&mut h, "Save private share");
        wait(&mut h, |app| {
            !app.engine.busy()
                && app
                    .engine
                    .session
                    .as_ref()
                    .is_some_and(|s| s.kind == SessionKind::Owner)
        });
        let owner_directory = h.state().engine.session.as_ref().unwrap().directory.clone();
        assert!(!h.state().engine.calibrating());
        assert!(h.query_by_label(text::SPLIT_SHARE).is_some());
        assert!(h.query_by_role_and_label(Role::Button, "Resume").is_none());
        assert!(
            h.query_by_role_and_label(Role::Button, "Delete session…")
                .is_some()
        );
        let request_file = temp.path().join("public-request.json");
        h.state_mut().test_export_path = Some(request_file.clone());
        click(&mut h, "Save public request");
        wait(&mut h, |app| !app.engine.busy() && request_file.exists());
        let request = crate::split::read_request(&request_file).unwrap();
        h.state_mut().test_export_path = Some(request_file);
        click(&mut h, "Import search request");
        assert!(h.query_by_label("Public search request").is_some());
        assert!(h.query_by_label("Address prefix: 0xab").is_some());
        assert!(
            h.query_by_role_and_label(Role::TextInput, "Address prefix")
                .is_none()
        );
        click(&mut h, "Start search");
        assert!(h.state().passwords.is_none());
        wait(&mut h, |app| {
            !app.engine.busy() && app.engine.state == State::MatchFound
        });
        let worker = h.state().engine.session.as_ref().unwrap();
        assert_eq!(worker.kind, SessionKind::Worker);
        assert!(!worker.directory.join("seed.keystore.json").exists());
        assert_eq!(worker.job.pattern, request.job.pattern);
        assert!(
            h.query_by_role_and_label(Role::Button, "Copy address")
                .is_none()
        );
        assert!(
            h.query_by_role_and_label(Role::Button, "Save wallet")
                .is_none()
        );
        assert!(
            h.query_by_role_and_label(Role::Button, "Combine and save wallet")
                .is_none()
        );
        let result_file = temp.path().join("public-result.json");
        h.state_mut().test_export_path = Some(result_file.clone());
        click(&mut h, "Save search result");
        wait(&mut h, |app| !app.engine.busy() && result_file.exists());
        h.state_mut()
            .open_session(desktop::load_session(&owner_directory).unwrap());
        h.run_steps(3);
        h.state_mut().test_export_path = Some(result_file);
        click(&mut h, "Import search result");
        wait(&mut h, |app| {
            !app.engine.busy() && app.engine.state == State::MatchFound
        });
        assert!(h.query_by_label(text::SPLIT_SHARE).is_some());
        assert!(
            h.get_by_role_and_label(Role::Button, "Copy address")
                .accesskit_node()
                .is_disabled()
        );
        click(&mut h, "Combine and save wallet");
        input(
            &mut h,
            Role::PasswordInput,
            "Private share password",
            "throwaway owner password",
        );
        click(&mut h, "Unlock private share");
        wait(&mut h, |app| {
            app.passwords
                .as_ref()
                .is_some_and(|p| p.step == PasswordStep::Wallet)
        });
        input(
            &mut h,
            Role::PasswordInput,
            "Password",
            "throwaway wallet password",
        );
        input(
            &mut h,
            Role::PasswordInput,
            "Confirm password",
            "throwaway wallet password",
        );
        let wallet = temp.path().join("split-wallet.json");
        h.state_mut().test_export_path = Some(wallet.clone());
        click(&mut h, "Select file and save wallet");
        wait(&mut h, |app| {
            !app.engine.busy() && app.engine.state == State::Completed
        });
        assert!(h.state().engine.verified_this_run);
        assert!(
            !h.get_by_role_and_label(Role::Button, "Copy address")
                .accesskit_node()
                .is_disabled()
        );
        assert_eq!(
            crate::verify_wallet(&wallet, "throwaway wallet password", None).unwrap(),
            h.state()
                .engine
                .session
                .as_ref()
                .unwrap()
                .address
                .as_ref()
                .unwrap()
                .to_owned()
        );
    }

    #[test]
    fn gui_split_request_creation_excludes_ed25519_profiles() {
        let temp = tempfile::tempdir().unwrap();
        let mut h = harness(temp.path().to_owned());
        wait(&mut h, |app| !app.engine.busy());
        h.state_mut().engine.settings.profile =
            crate::chains::Profile::new(crate::chains::Chain::Solana, None).unwrap();
        click(&mut h, "Split-key search");
        click(&mut h, "Create request");
        assert_eq!(
            h.state().engine.settings.profile.chain,
            crate::chains::Chain::Ethereum
        );
        h.get_by_value("Ethereum").click();
        h.run_steps(3);
        for chain in ["Solana", "Stellar", "Algorand"] {
            assert!(h.query_by_label(chain).is_none());
        }
    }

    #[test]
    fn gui_split_request_suffix_is_visible_and_retained_in_worker() {
        let temp = tempfile::tempdir().unwrap();
        let owner = temp.path().join("owner-with-suffix");
        let pattern =
            crate::crypto::Pattern::for_profile(crate::chains::Profile::default(), "a", "b")
                .unwrap();
        crate::split::create_request(&owner, pattern.clone(), "throwaway owner password").unwrap();
        let request_file = temp.path().join("request-with-suffix.json");
        crate::split::export_request(&owner, &request_file).unwrap();
        let mut h = harness(temp.path().join("app-data"));
        wait(&mut h, |app| !app.engine.busy());
        click(&mut h, "Split-key search");
        h.state_mut().test_export_path = Some(request_file);
        click(&mut h, "Import search request");
        assert!(h.query_by_label("Address suffix: b").is_some());
        click(&mut h, "Start search");
        wait(&mut h, |app| {
            !app.engine.busy() && app.engine.state == State::MatchFound
        });
        assert_eq!(
            h.state().engine.session.as_ref().unwrap().job.pattern,
            pattern
        );
        assert_eq!(h.state().prefix, "a");
        assert!(h.query_by_label("Address suffix: b").is_some());
        h.state_mut()
            .open_session(desktop::load_session(&owner).unwrap());
        h.run_steps(3);
        assert!(h.query_by_label("Address suffix: b").is_some());
        assert!(h.query_by_label(text::SPLIT_SHARE).is_some());
    }

    #[test]
    fn gui_split_primary_actions_fit_default_window_height() {
        let temp = tempfile::tempdir().unwrap();
        let owner = temp.path().join("owner");
        let request = crate::split::create_request(
            &owner,
            crate::crypto::Pattern::for_profile(crate::chains::Profile::default(), "a", "")
                .unwrap(),
            "throwaway owner password",
        )
        .unwrap();
        let mut h = harness_at_size(temp.path().join("app-data"), egui::vec2(1060.0, 760.0));
        wait(&mut h, |app| !app.engine.busy());
        h.state_mut()
            .open_session(desktop::load_session(&owner).unwrap());
        h.run_steps(3);
        let workspace = egui::Rect::from_min_max(egui::pos2(220.0, 0.0), egui::pos2(1060.0, 720.0));
        for label in [
            "Save public request",
            "Import search result",
            "Delete session…",
        ] {
            let rect = h.get_by_role_and_label(Role::Button, label).rect();
            assert!(workspace.contains_rect(rect), "{label}: {rect:?}");
        }
        h.state_mut().engine.start_split_worker(request).unwrap();
        wait(&mut h, |app| {
            !app.engine.busy() && app.engine.state == State::MatchFound
        });
        for label in ["Save search result", "Delete session…"] {
            let rect = h.get_by_role_and_label(Role::Button, label).rect();
            assert!(workspace.contains_rect(rect), "{label}: {rect:?}");
        }
        assert!(
            h.query_by_role_and_label(Role::Button, "Copy address")
                .is_none()
        );
    }

    #[test]
    fn gui_past_owner_deletion_names_private_share_recovery() {
        let temp = tempfile::tempdir().unwrap();
        let mut h = harness(temp.path().join("app-data"));
        wait(&mut h, |app| !app.engine.busy());
        let selected = saved_session(&h, "0xab");
        let owner = temp.path().join("past-owner");
        crate::split::create_request(
            &owner,
            crate::crypto::Pattern::for_profile(crate::chains::Profile::default(), "a", "")
                .unwrap(),
            "throwaway owner password",
        )
        .unwrap();
        h.state_mut().open_session(selected.clone());
        h.state_mut().engine.history =
            vec![desktop::load_session(&owner).unwrap(), selected.clone()];
        h.run_steps(3);
        click(&mut h, "Sessions");
        h.get_all_by_role_and_label(Role::Button, "Delete session…")
            .next()
            .unwrap()
            .click();
        h.run_steps(3);
        assert_eq!(h.state().delete_kind, crate::split::SessionKind::Owner);
        assert!(h.query_by_label(text::SPLIT_DELETE).is_some());
        click(&mut h, "Keep session");
        assert!(owner.exists());
        assert_eq!(
            h.state().engine.session.as_ref().unwrap().job.session_id,
            selected.job.session_id
        );
        assert_eq!(h.state().delete_kind, crate::split::SessionKind::Local);
    }

    #[test]
    fn gui_invalid_split_request_keeps_selected_session() {
        let temp = tempfile::tempdir().unwrap();
        let mut h = harness(temp.path().to_owned());
        wait(&mut h, |app| !app.engine.busy());
        let selected = saved_session(&h, "0xab");
        h.state_mut().open_session(selected.clone());
        let malformed = temp.path().join("invalid-request.json");
        crate::storage::write_bytes(&malformed, b"{}", false).unwrap();
        click(&mut h, "Split-key search");
        h.state_mut().test_export_path = Some(malformed);
        click(&mut h, "Import search request");
        assert!(h.state().engine.error.is_some());
        assert!(h.state().split_preview.is_none());
        assert_eq!(
            h.state().engine.session.as_ref().unwrap().job.session_id,
            selected.job.session_id
        );
    }

    #[test]
    fn gui_selected_session_deletion_is_visible_and_requires_confirmation() {
        let temp = tempfile::tempdir().unwrap();
        let mut h = harness(temp.path().to_owned());
        wait(&mut h, |a| !a.engine.busy());
        let session = saved_session(&h, "0xab");
        let directory = session.directory.clone();
        h.state_mut().engine.select_session(session).unwrap();
        h.run_steps(3);
        assert!(h.query_by_label_contains("Session ID:").is_none());
        click(&mut h, "Delete session…");
        assert!(h.query_by_label(text::DELETE).is_some());
        assert!(h.query_by_label(&directory.display().to_string()).is_some());
        assert!(
            h.get_by_role_and_label(Role::Button, "Delete session")
                .accesskit_node()
                .is_disabled()
        );
        input(&mut h, Role::TextInput, "Type DELETE to confirm", "delete");
        assert!(
            h.get_by_role_and_label(Role::Button, "Delete session")
                .accesskit_node()
                .is_disabled()
        );
        click(&mut h, "Keep session");
        assert!(directory.exists());
        assert!(h.state().engine.session.is_some());
        assert!(h.state().delete_text.is_empty());
        click(&mut h, "Delete session…");
        input(&mut h, Role::TextInput, "Type DELETE to confirm", "DELETE");
        click(&mut h, "Delete session");
        wait(&mut h, |a| !a.engine.busy());
        assert!(h.state().engine.error.is_none());
        assert!(!directory.exists());
        assert!(h.state().engine.session.is_none());
        assert!(h.state().engine.history.is_empty());
        assert!(h.state().engine.progress.is_none());
        assert!(!h.state().engine.verified_this_run);
        assert_eq!(h.state().engine.state, State::Idle);
    }

    #[test]
    fn gui_past_session_deletion_keeps_selected_session_and_progress() {
        let temp = tempfile::tempdir().unwrap();
        let mut h = harness(temp.path().to_owned());
        wait(&mut h, |a| !a.engine.busy());
        let selected = saved_session(&h, &format!("0x{}", "a".repeat(25)));
        let past = saved_session(&h, "0xab");
        h.state_mut()
            .engine
            .select_session(selected.clone())
            .unwrap();
        h.state_mut().engine.search().unwrap();
        wait(&mut h, |a| {
            a.engine.state == State::Searching
                && a.engine
                    .progress
                    .as_ref()
                    .is_some_and(|p| p.candidates > 0.0)
        });
        assert!(
            h.get_by_role_and_label(Role::Button, "Delete session…")
                .accesskit_node()
                .is_disabled()
        );
        assert!(
            h.state_mut()
                .engine
                .delete(past.directory.clone(), "DELETE")
                .is_err()
        );
        click(&mut h, "Pause");
        wait(&mut h, |a| !a.engine.busy());
        let attempts = h
            .state()
            .engine
            .progress
            .as_ref()
            .unwrap()
            .candidates_exact
            .clone();
        h.state_mut().engine.history = vec![past.clone(), selected.clone()];
        click(&mut h, "Sessions");
        assert_eq!(
            h.get_all_by_role_and_label(Role::Button, "Delete session…")
                .count(),
            2
        );
        h.get_all_by_role_and_label(Role::Button, "Delete session…")
            .next()
            .unwrap()
            .click();
        h.run_steps(3);
        assert_eq!(h.state().delete.as_ref(), Some(&past.directory));
        click(&mut h, "Keep session");
        assert!(past.directory.exists());
        assert_eq!(
            h.state().engine.session.as_ref().unwrap().job.session_id,
            selected.job.session_id
        );
        h.get_all_by_role_and_label(Role::Button, "Delete session…")
            .next()
            .unwrap()
            .click();
        h.run_steps(3);
        input(&mut h, Role::TextInput, "Type DELETE to confirm", "DELETE");
        click(&mut h, "Delete session");
        wait(&mut h, |a| !a.engine.busy());
        assert!(h.state().engine.error.is_none());
        assert!(!past.directory.exists());
        assert!(selected.directory.exists());
        assert_eq!(
            h.state().engine.session.as_ref().unwrap().job.session_id,
            selected.job.session_id
        );
        assert_eq!(h.state().engine.state, State::Paused);
        assert_eq!(
            h.state().engine.progress.as_ref().unwrap().candidates_exact,
            attempts
        );
        assert_eq!(h.state().engine.history.len(), 1);
        assert_eq!(
            h.state().engine.history[0].job.session_id,
            selected.job.session_id
        );
    }

    #[test]
    fn gui_navigation_and_keyboard_help_are_available() {
        let temp = tempfile::tempdir().unwrap();
        let mut h = harness(temp.path().to_owned());
        wait(&mut h, |a| !a.engine.busy());
        click(&mut h, "Sessions");
        assert!(h.state().view == View::Sessions);
        assert!(h.query_by_label(text::EMPTY_SESSIONS).is_some());
        click(&mut h, "Search");
        h.get_by_role_and_label(Role::Button, "Compute mode help")
            .focus();
        h.run_steps(3);
        assert!(h.query_by_label(text::AUTO).is_some());
        click(&mut h, "Address prefix help");
        assert!(h.query_by_label(text::PREFIX).is_some());
        click(&mut h, "Settings");
        assert!(h.state().settings.is_some());
        assert!(h.query_by_label("Session folder").is_some());
        assert!(
            h.query_by_role_and_label(Role::Button, "Recalibrate hardware")
                .is_some()
        );
        assert!(h.query_by_label("Use optimized batching").is_none());
        h.state_mut().settings = None;
        h.run_steps(3);
        click(&mut h, "Diagnostics");
        assert!(
            h.get_by_role_and_label(Role::Button, "Do benchmark")
                .accesskit_node()
                .role()
                == Role::Button
        );
        for label in [
            "Do self-tests",
            "Tune CPU",
            "Tune enabled GPUs",
            "Clear kernel cache",
            "Read session log",
        ] {
            assert!(h.query_by_role_and_label(Role::Button, label).is_none());
        }
        h.state_mut().diagnostics = false;
        h.run_steps(3);
        click(&mut h, "Help");
        assert!(h.query_by_label("1. Select New search.").is_some());
    }

    #[test]
    fn gui_has_every_mainnet_profile_and_forces_ed25519_cpu() {
        let temp = tempfile::tempdir().unwrap();
        let mut h = harness(temp.path().to_owned());
        wait(&mut h, |a| !a.engine.busy());
        let mut count = 0;
        for chain in crate::chains::Chain::ALL {
            for ty in chain.types() {
                let profile = crate::chains::Profile::new(chain, Some(*ty)).unwrap();
                h.state_mut().engine.settings.profile = profile;
                h.state_mut().engine.settings.mode = Mode::Opencl;
                h.step();
                assert!(
                    h.query_by_value(chain.label()).is_some(),
                    "{}",
                    chain.label()
                );
                assert!(h.query_by_value(ty.label()).is_some(), "{}", ty.label());
                if profile.key_family() == crate::chains::KeyFamily::Ed25519 {
                    assert_eq!(h.state().engine.settings.mode, Mode::Cpu);
                }
                count += 1;
            }
        }
        assert_eq!(count, 21);
    }

    #[test]
    fn gui_chain_selection_is_remembered_and_resets_benchmark() {
        let temp = tempfile::tempdir().unwrap();
        let mut h = harness(temp.path().to_owned());
        wait(&mut h, |a| !a.engine.busy());
        h.state_mut().engine.settings.benchmark_per_second = Some(123.0);
        h.get_by_value("Ethereum").click();
        h.run_steps(3);
        h.get_by_label("BNB Smart Chain").click();
        h.run_steps(3);
        wait(&mut h, |a| !a.engine.busy());
        let saved = desktop::read_settings(temp.path()).unwrap();
        assert_eq!(saved.profile.chain, crate::chains::Chain::Bnb);
        assert!(saved.benchmark_per_second.is_none());
        let reopened = harness(temp.path().to_owned());
        assert_eq!(reopened.state().engine.settings.profile, saved.profile);
    }

    #[test]
    fn gui_prefix_and_password_controls_reject_invalid_input() {
        let temp = tempfile::tempdir().unwrap();
        let mut h = harness(temp.path().to_owned());
        wait(&mut h, |a| !a.engine.busy());
        assert!(
            h.get_by_role_and_label(Role::Button, "Find address")
                .accesskit_node()
                .is_disabled()
        );
        input(&mut h, Role::TextInput, "Address prefix", "0xGG");
        assert!(
            h.get_by_role_and_label(Role::Button, "Find address")
                .accesskit_node()
                .is_disabled()
        );
        h.state_mut().prefix = "0x00000".into();
        wait(&mut h, |app| {
            app.estimate
                .as_ref()
                .is_some_and(|(pattern, result)| pattern.prefix == "00000" && result.is_ok())
        });
        assert!(h.query_by_label_contains("1,048,576").is_some());
        click(&mut h, "Find address");
        input(
            &mut h,
            Role::PasswordInput,
            "Password",
            "throwaway seed password",
        );
        input(
            &mut h,
            Role::PasswordInput,
            "Confirm password",
            "mismatched confirmation",
        );
        assert!(
            h.get_by_role_and_label(Role::Button, "Save session and start search")
                .accesskit_node()
                .is_disabled()
        );
        assert!(h.query_by_value("throwaway seed password").is_none());
        click(&mut h, "Cancel");
        assert!(h.state().passwords.is_none());
        assert!(!temp.path().join("Sessions").exists());
    }

    /// Drives the production App and actual widgets. Only OS file selection is adapted:
    /// the returned filename enters the same channel/poll/export path as native rfd.
    #[test]
    fn gui_wallet_flow_through_password_dialogs_and_verified_export() {
        for chain in [
            crate::chains::Chain::Ethereum,
            crate::chains::Chain::Solana,
            crate::chains::Chain::Warthog,
        ] {
            let temp = tempfile::tempdir().unwrap();
            let mut h = harness(temp.path().to_owned());
            wait(&mut h, |a| !a.engine.busy());
            h.state_mut().engine.settings.profile =
                crate::chains::Profile::new(chain, None).unwrap();
            let prefix = if chain == crate::chains::Chain::Ethereum {
                "0xAB"
            } else {
                "A"
            };
            input(&mut h, Role::TextInput, "Address prefix", prefix);
            click(&mut h, "Find address");
            input(
                &mut h,
                Role::PasswordInput,
                "Password",
                "throwaway seed password",
            );
            input(
                &mut h,
                Role::PasswordInput,
                "Confirm password",
                "throwaway seed password",
            );
            click(&mut h, "Save session and start search");
            assert!(h.state().passwords.is_none());
            wait(&mut h, |a| {
                !a.engine.busy() && a.engine.state == State::MatchFound
            });
            let directory = h.state().engine.session.as_ref().unwrap().directory.clone();
            let address = h
                .state()
                .engine
                .session
                .as_ref()
                .unwrap()
                .address
                .clone()
                .unwrap();
            assert!(if chain == crate::chains::Chain::Ethereum {
                address.to_lowercase().starts_with("0xab")
            } else if chain == crate::chains::Chain::Warthog {
                address.starts_with('a') && address.len() == 48
            } else {
                address.starts_with('A')
            });
            assert!(h.query_by_label(&address).is_some());
            assert!(
                h.get_by_role_and_label(Role::Button, "Copy address")
                    .accesskit_node()
                    .is_disabled()
            );
            click(&mut h, "Save wallet");
            input(
                &mut h,
                Role::PasswordInput,
                "Session password",
                "throwaway seed password",
            );
            click(&mut h, "Unlock session");
            wait(&mut h, |a| {
                a.passwords
                    .as_ref()
                    .is_some_and(|p| p.step == PasswordStep::Wallet)
            });
            input(
                &mut h,
                Role::PasswordInput,
                "Password",
                "throwaway wallet password",
            );
            input(
                &mut h,
                Role::PasswordInput,
                "Confirm password",
                "throwaway wallet password",
            );
            let output = temp.path().join("wallet.json");
            h.state_mut().test_export_path = Some(output.clone());
            click(&mut h, "Select file and save wallet");
            wait(&mut h, |a| {
                !a.engine.busy() && a.engine.state == State::Completed
            });
            assert!(h.state().passwords.is_none());
            assert!(h.state().engine.unlocked_password.is_none());
            assert!(h.query_by_label("Saved wallet").is_some());
            assert_eq!(
                crate::verify_wallet(&output, "throwaway wallet password", None).unwrap(),
                address
            );
            assert!(h.query_by_value("throwaway seed password").is_none());
            assert!(h.query_by_value("throwaway wallet password").is_none());
            h.state_mut()
                .engine
                .select_session(desktop::load_session(&directory).unwrap())
                .unwrap();
            h.step();
            assert!(!h.state().engine.verified_this_run);
            assert!(h.query_by_label("Saved export record").is_some());
            assert!(
                h.get_by_role_and_label(Role::Button, "Copy address")
                    .accesskit_node()
                    .is_disabled()
            );
            click(&mut h, "Do wallet check");
            input(
                &mut h,
                Role::PasswordInput,
                "Wallet password",
                "throwaway wallet password",
            );
            click(&mut h, "Decrypt wallet and do check");
            wait(&mut h, |a| !a.engine.busy() && a.engine.verified_this_run);
            assert!(
                !h.get_by_role_and_label(Role::Button, "Copy address")
                    .accesskit_node()
                    .is_disabled()
            );
            assert!(h.query_by_label("Saved wallet").is_some());
            let native = temp.path().join("native-import.json");
            h.get_by_label("Native import file").click();
            h.run_steps(3);
            click(&mut h, "Export native import file");
            input(
                &mut h,
                Role::PasswordInput,
                "Wallet password",
                "throwaway wallet password",
            );
            h.state_mut().test_export_path = Some(native.clone());
            click(&mut h, "Select file and export private key");
            wait(&mut h, |a| !a.engine.busy() && a.passwords.is_none());
            assert!(native.exists(), "{:?}", h.state().engine.error);
            assert!(h.state().engine.notice.contains("unencrypted private key"));
            if chain == crate::chains::Chain::Ethereum
                && let Some(root) = std::env::var_os("VANITY_GUI_FIXTURE_DIR")
            {
                let root = PathBuf::from(root);
                std::fs::create_dir_all(root.join("session")).unwrap();
                for name in [
                    "job.json",
                    "results.json",
                    "checkpoint.json",
                    "seed.keystore.json",
                ] {
                    crate::storage::write_bytes(
                        &root.join("session").join(name),
                        &crate::storage::read_bytes(&directory.join(name)).unwrap(),
                        true,
                    )
                    .unwrap();
                }
                crate::storage::write_bytes(
                    &root.join("wallet.json"),
                    &crate::storage::read_bytes(&output).unwrap(),
                    true,
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn gui_ed25519_resume_requires_password_and_cancel_keeps_pause() {
        let temp = tempfile::tempdir().unwrap();
        let mut h = harness(temp.path().to_owned());
        wait(&mut h, |a| !a.engine.busy());
        h.state_mut().engine.settings.profile =
            crate::chains::Profile::new(crate::chains::Chain::Solana, None).unwrap();
        h.state_mut().prefix = "SoLabcdefgh".into();
        h.step();
        assert_eq!(h.state().prefix, "SoLabcdefgh");
        click(&mut h, "Find address");
        input(
            &mut h,
            Role::PasswordInput,
            "Password",
            "throwaway seed password",
        );
        input(
            &mut h,
            Role::PasswordInput,
            "Confirm password",
            "throwaway seed password",
        );
        click(&mut h, "Save session and start search");
        wait(&mut h, |a| {
            a.engine.state == State::Searching
                && a.engine
                    .progress
                    .as_ref()
                    .is_some_and(|p| p.candidates > 0.0)
        });
        click(&mut h, "Pause");
        wait(&mut h, |a| !a.engine.busy());
        assert_eq!(h.state().engine.state, State::Paused);
        click(&mut h, "Resume");
        assert!(h.state().passwords.as_ref().unwrap().step == PasswordStep::Resume);
        click(&mut h, "Cancel");
        assert_eq!(h.state().engine.state, State::Paused);
        click(&mut h, "Resume");
        input(
            &mut h,
            Role::PasswordInput,
            "Password",
            "throwaway seed password",
        );
        click(&mut h, "Unlock and resume");
        wait(&mut h, |a| {
            a.engine.state == State::Searching
                && a.engine
                    .progress
                    .as_ref()
                    .is_some_and(|p| p.candidates > 0.0)
        });
        click(&mut h, "Pause");
        wait(&mut h, |a| !a.engine.busy());
        assert_eq!(h.state().engine.state, State::Paused);
        assert!(h.state().engine.error.is_none());
    }
}
