use eframe::egui;
use std::sync::{Arc, Mutex};
use tokio::runtime::{Runtime, Handle};
use walkdir::WalkDir;
use anyhow::Result;
use chrono::Local;
use humansize::{format_size, BINARY};
use std::fs::File;
use csv::Writer;
use rfd::FileDialog;
use std::os::windows::fs::MetadataExt;
use std::time::Instant;
use std::collections::VecDeque;
use std::process::Command;

#[derive(Clone)]
struct FileEntry {
    path: String,
    name: String,
    size: u64,
    modified: chrono::DateTime<Local>,
    extension: String,
    is_hidden: bool,
    is_system: bool,
}

#[derive(Default)]
struct ColumnState {
    focused_path_index: Option<usize>,
}

struct FileScannerApp {
    files: Arc<Mutex<Vec<FileEntry>>>,
    filtered_files: Arc<Mutex<Vec<FileEntry>>>,
    scanning: bool,
    scan_complete: bool,
    current_file: Arc<Mutex<String>>,
    runtime_handle: Handle,
    start_directory: String,
    status_message: Arc<Mutex<String>>,
    scan_log: Arc<Mutex<VecDeque<String>>>,
    column_state: ColumnState,
    extension_filter: String,
}

impl Default for FileScannerApp {
    fn default() -> Self {
        let runtime = Runtime::new().unwrap();
        let handle = runtime.handle().clone();
        std::thread::spawn(move || {
            runtime.block_on(async {
                tokio::time::sleep(tokio::time::Duration::from_secs(u64::MAX)).await;
            });
        });

        Self {
            files: Arc::new(Mutex::new(Vec::new())),
            filtered_files: Arc::new(Mutex::new(Vec::new())),
            scanning: false,
            scan_complete: false,
            current_file: Arc::new(Mutex::new(String::new())),
            runtime_handle: handle,
            start_directory: "C:\\".to_string(),
            status_message: Arc::new(Mutex::new(String::new())),
            scan_log: Arc::new(Mutex::new(VecDeque::with_capacity(1000))),
            column_state: ColumnState {
                focused_path_index: None,
            },
            extension_filter: String::new(),
        }
    }
}

impl FileScannerApp {
    fn export_to_csv(&self) -> Result<()> {
        if let Some(path) = FileDialog::new()
            .add_filter("CSV Files", &["csv"])
            .set_directory(".")
            .save_file() 
        {
            let mut writer = Writer::from_writer(File::create(path)?);
            writer.write_record(&["Name", "Path", "Size", "Modified", "Extension", "Hidden", "System"])?;

            let files = self.filtered_files.lock().unwrap();
            for file in files.iter() {
                writer.write_record(&[
                    &file.name,
                    &file.path,
                    &format_size(file.size, BINARY),
                    &file.modified.format("%Y-%m-%d %H:%M:%S").to_string(),
                    &file.extension,
                    &file.is_hidden.to_string(),
                    &file.is_system.to_string(),
                ])?;
            }
            writer.flush()?;
            Ok(())
        } else {
            Ok(())
        }
    }

    fn select_directory(&mut self) {
        if let Some(path) = FileDialog::new()
            .set_directory(&self.start_directory)
            .pick_folder() 
        {
            self.start_directory = path.to_string_lossy().into_owned();
        }
    }

    fn open_file(&self, path: &str) {
        if let Err(e) = Command::new("cmd")
            .args(["/C", "start", "", path])
            .spawn() 
        {
            *self.status_message.lock().unwrap() = format!("Failed to open file: {}", e);
        }
    }

    fn start_scanning(&mut self, ctx: &egui::Context) {
        self.scanning = true;
        self.scan_complete = false;
        self.files.lock().unwrap().clear();
        self.filtered_files.lock().unwrap().clear();
        self.scan_log.lock().unwrap().clear();
        *self.status_message.lock().unwrap() = "Scanning...".to_string();
        *self.current_file.lock().unwrap() = "Starting scan...".to_string();

        let files = Arc::clone(&self.files);
        let filtered_files = Arc::clone(&self.filtered_files);
        let status_message = Arc::clone(&self.status_message);
        let status_message_progress = Arc::clone(&status_message);
        let status_message_scan = Arc::clone(&status_message);
        let current_file = Arc::clone(&self.current_file);
        let scan_log = Arc::clone(&self.scan_log);
        
        // Create separate context clones for each task
        let ctx_progress_update = ctx.clone();
        let ctx_progress_scan = ctx.clone();
        let ctx_scan = ctx.clone();
        let ctx_ui = ctx.clone();
        
        let start_dir = self.start_directory.clone();
        let runtime_handle = self.runtime_handle.clone();

        // Create a channel for scanning state updates
        let (state_tx, mut state_rx) = tokio::sync::mpsc::channel::<ScanningStateUpdate>(1);
        let state_tx_clone = state_tx.clone();

        // Create a channel for UI updates
        let (ui_tx, mut ui_rx) = tokio::sync::mpsc::channel::<bool>(1);
        let ui_tx_clone = ui_tx.clone();

        // Spawn a task to handle state updates
        runtime_handle.spawn(async move {
            while let Some(update) = state_rx.recv().await {
                if update.is_complete {
                    let _ = ui_tx_clone.send(true).await;
                    break;
                }
            }
        });

        let (tx, mut rx) = tokio::sync::mpsc::channel::<ProgressUpdate>(1000);
        let current_file_clone = Arc::clone(&current_file);
        let scan_log_clone = Arc::clone(&scan_log);

        // Progress update task
        runtime_handle.spawn(async move {
            while let Some(progress) = rx.recv().await {
                if let Ok(mut status) = status_message_progress.lock() {
                    if !status.contains("Scan complete") {
                        *status = "Scanning...".to_string();
                    }
                }
                if let Ok(mut current) = current_file_clone.lock() {
                    *current = progress.current_file.clone();
                }
                if let Ok(mut log) = scan_log_clone.lock() {
                    if log.len() >= 1000 {
                        log.pop_front();
                    }
                    log.push_back(progress.current_file);
                }
                ctx_progress_update.request_repaint();
            }
        });

        let tx_clone = tx.clone();
        runtime_handle.spawn(async move {
            let start_time = Instant::now();
            let mut _processed_files = 0;
            let mut batch = Vec::with_capacity(5000);
            let mut last_update = Instant::now();
            let mut total_size = 0u64;

            let walker = WalkDir::new(&start_dir)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok());

            let _total_files = walker.count();
            let walker = WalkDir::new(&start_dir)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok());

            for entry in walker {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.is_file() {
                        let path = entry.path();
                        let path_str = path.to_string_lossy().into_owned();
                        
                        {
                            if let Ok(mut current) = current_file.lock() {
                                *current = path_str.clone();
                            }
                        }

                        let attributes = metadata.file_attributes();
                        let is_hidden = (attributes & 0x2) != 0;
                        let is_system = (attributes & 0x4) != 0;
                        let file_size = metadata.len();
                        total_size += file_size;

                        let file_entry = FileEntry {
                            path: path_str,
                            name: path.file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("Unknown")
                                .to_string(),
                            size: file_size,
                            modified: chrono::DateTime::from(metadata.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH)),
                            extension: path.extension()
                                .and_then(|e| e.to_str())
                                .unwrap_or("")
                                .to_string(),
                            is_hidden,
                            is_system,
                        };

                        batch.push(file_entry);
                        _processed_files += 1;

                        if batch.len() >= 5000 || last_update.elapsed() > std::time::Duration::from_millis(50) {
                            {
                                let mut files_guard = files.lock().unwrap();
                                files_guard.extend(batch.drain(..));
                            }

                            {
                                let mut filtered_guard = filtered_files.lock().unwrap();
                                *filtered_guard = files.lock().unwrap().clone();
                            }

                            let current_file_name = {
                                if let Ok(current) = current_file.lock() {
                                    current.clone()
                                } else {
                                    "Unknown".to_string()
                                }
                            };

                            let _ = tx_clone.send(ProgressUpdate {
                                current_file: current_file_name,
                            }).await;

                            last_update = Instant::now();
                            ctx_progress_scan.request_repaint();
                        }
                    }
                }
            }

            if !batch.is_empty() {
                {
                    let mut files_guard = files.lock().unwrap();
                    files_guard.extend(batch);
                }

                {
                    let mut filtered_guard = filtered_files.lock().unwrap();
                    *filtered_guard = files.lock().unwrap().clone();
                }
            }

            let duration = start_time.elapsed();
            if let Ok(mut status) = status_message_scan.lock() {
                let final_count = filtered_files.lock().unwrap().len();
                let duration_secs = duration.as_secs_f64();
                *status = format!(
                    "Scan complete. Found {} files ({} total size) in {:.3} seconds.",
                    final_count,
                    format_size(total_size, BINARY),
                    duration_secs
                );
            }
            if let Ok(mut current) = current_file.lock() {
                *current = "Scan complete".to_string();
            }

            // Send final progress update
            let _ = tx_clone.send(ProgressUpdate {
                current_file: "Scan complete".to_string(),
            }).await;

            // Send scanning complete state
            let _ = state_tx_clone.send(ScanningStateUpdate { is_complete: true }).await;

            ctx_scan.request_repaint();
        });

        // Set up a task to monitor UI updates
        runtime_handle.spawn(async move {
            while let Some(complete) = ui_rx.recv().await {
                if complete {
                    // Update UI state through the context
                    ctx_ui.request_repaint();
                    break;
                }
            }
        });
    }

    fn apply_extension_filter(&mut self) {
        if let Ok(mut filtered) = self.filtered_files.lock() {
            if let Ok(files) = self.files.lock() {
                if self.extension_filter.is_empty() {
                    // If filter is empty, show all files
                    *filtered = files.clone();
                } else {
                    // Split the filter string by commas and trim whitespace
                    let extensions: Vec<String> = self.extension_filter
                        .split(',')
                        .map(|s| s.trim().trim_start_matches('.').to_lowercase())
                        .collect();

                    // Filter files based on extensions
                    *filtered = files.iter()
                        .filter(|file| {
                            if extensions.is_empty() {
                                true
                            } else {
                                let file_ext = file.extension.to_lowercase();
                                extensions.iter().any(|ext| file_ext == *ext)
                            }
                        })
                        .cloned()
                        .collect();
                }
            }
        }
    }

    fn clear_files(&mut self) {
        self.files.lock().unwrap().clear();
        self.filtered_files.lock().unwrap().clear();
        self.scan_log.lock().unwrap().clear();
        self.extension_filter.clear();
        *self.status_message.lock().unwrap() = "Files cleared".to_string();
        self.column_state.focused_path_index = None;
        self.scan_complete = false;
    }
}

#[derive(Clone)]
struct ProgressUpdate {
    current_file: String,
}

// Add a new struct for scanning state updates
#[derive(Clone)]
struct ScanningStateUpdate {
    is_complete: bool,
}

impl eframe::App for FileScannerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Check if scanning is complete
        if self.scanning {
            if let Ok(status) = self.status_message.lock() {
                if status.contains("Scan complete") {
                    self.scanning = false;
                    self.scan_complete = true;
                }
            }
            ctx.request_repaint();
        }

        // Handle arrow key navigation
        if ctx.input(|i| i.key_pressed(egui::Key::ArrowDown)) {
            if let Ok(files) = self.filtered_files.lock() {
                let current = self.column_state.focused_path_index.unwrap_or(0);
                if current < files.len() - 1 {
                    self.column_state.focused_path_index = Some(current + 1);
                }
            }
        } else if ctx.input(|i| i.key_pressed(egui::Key::ArrowUp)) {
            if let Some(current) = self.column_state.focused_path_index {
                if current > 0 {
                    self.column_state.focused_path_index = Some(current - 1);
                }
            } else if let Ok(files) = self.filtered_files.lock() {
                if !files.is_empty() {
                    self.column_state.focused_path_index = Some(0);
                }
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.push_id("main_panel", |ui| {
                // Header section with buttons and filter
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    
                    // Directory selection
                    if ui.button("📁 Browse").clicked() {
                        self.select_directory();
                    }
                    ui.text_edit_singleline(&mut self.start_directory);
                    
                    ui.separator();

                    // Extension filter
                    ui.label("Extensions:");
                    let filter_response = ui.text_edit_singleline(&mut self.extension_filter);
                    if filter_response.changed() {
                        self.apply_extension_filter();
                    }
                    if ui.button("Apply").clicked() {
                        self.apply_extension_filter();
                    }

                    // Add tooltip for the extension filter
                    if filter_response.hovered() {
                        egui::show_tooltip_for(
                            ctx,
                            egui::LayerId::new(egui::Order::Tooltip, filter_response.id),
                            filter_response.id,
                            &filter_response.rect,
                            |ui| {
                                ui.label("Enter file extensions separated by commas (e.g., txt,pdf,doc)");
                                ui.label("Leave empty to show all files");
                            },
                        );
                    }
                    
                    ui.separator();
                    
                    // Action buttons
                    if !self.scanning {
                        if ui.button("Scan").clicked() {
                            self.start_scanning(ctx);
                        }
                        
                        if ui.button("Clear").clicked() {
                            self.clear_files();
                        }
                        
                        if ui.button("Save").clicked() {
                            if let Err(e) = self.export_to_csv() {
                                *self.status_message.lock().unwrap() = format!("Export failed: {}", e);
                            } else {
                                *self.status_message.lock().unwrap() = "Export successful".to_string();
                            }
                        }
                    } else {
                        ui.add_enabled(false, egui::Button::new("Scanning..."));
                    }
                });

                // Status message - only show if not empty and not scanning
                if let Ok(status) = self.status_message.lock() {
                    if !status.is_empty() && !self.scanning {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(status.as_str())
                                .color(egui::Color32::from_rgb(0, 150, 0))
                                .strong());
                        });
                    }
                }

                ui.separator();

                // Column headers
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    
                    // Serial number header
                    ui.add_sized([50.0, 20.0], egui::Label::new(
                        egui::RichText::new("#").strong().size(13.0)
                    ));
                    
                    // Path header
                    ui.add_sized([800.0, 20.0], egui::Label::new(
                        egui::RichText::new("Path").strong().size(13.0)
                    ));
                });

                ui.separator();

                // File list
                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        if let Ok(files) = self.filtered_files.lock() {
                            for (idx, file) in files.iter().enumerate() {
                                ui.push_id(format!("file_entry_{}", idx), |ui| {
                                    ui.horizontal(|ui| {
                                        ui.spacing_mut().item_spacing.x = 8.0;
                                        
                                        // Serial number
                                        ui.add_sized([50.0, 20.0], egui::Label::new(
                                            egui::RichText::new(format!("{}.", idx + 1))
                                                .color(egui::Color32::from_rgb(150, 150, 150))
                                                .size(13.0)
                                        ));
                                        
                                        // Path with tooltip
                                        let is_focused = self.column_state.focused_path_index == Some(idx);
                                        let path_response = ui.add_sized([800.0, 20.0], |ui: &mut egui::Ui| {
                                            let text = egui::RichText::new(&file.path)
                                                .size(13.0)
                                                .underline();
                                            
                                            ui.horizontal(|ui| {
                                                ui.spacing_mut().item_spacing.x = 0.0;
                                                ui.add_space(4.0);
                                                ui.label(text)
                                            }).inner
                                        });

                                        // Show tooltip with file size on hover or focus
                                        if path_response.hovered() || is_focused {
                                            let tooltip_text = format!("Size: {}", format_size(file.size, BINARY));
                                            egui::show_tooltip_for(
                                                ctx,
                                                egui::LayerId::new(egui::Order::Tooltip, path_response.id),
                                                path_response.id,
                                                &path_response.rect,
                                                |ui: &mut egui::Ui| {
                                                    ui.label(tooltip_text);
                                                },
                                            );
                                        }

                                        if path_response.clicked() {
                                            self.open_file(&file.path);
                                        }

                                        // Handle Enter key to open focused file
                                        if is_focused && ctx.input(|i| i.key_pressed(egui::Key::Enter)) {
                                            self.open_file(&file.path);
                                        }
                                    });
                                });
                            }
                        }
                    });
            });
        });
    }
}

fn main() -> Result<()> {
    println!("Starting File Path Extractor application...");
    
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1024.0, 768.0]),
        centered: true,
        ..Default::default()
    };

    println!("Attempting to launch window...");
    
    if let Err(e) = eframe::run_native(
        "File Path Extractor",
        native_options,
        Box::new(|_cc| {
            println!("Initializing application...");
            Ok(Box::new(FileScannerApp::default()))
        }),
    ) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    println!("Application closed.");
    Ok(())
} 