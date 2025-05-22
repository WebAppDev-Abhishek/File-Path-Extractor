# File Path Extractor

A modern, efficient file scanning and management tool built with Rust and egui. This application provides a clean, user-friendly interface for scanning directories, filtering files, and exporting file information.

## Features

- 🚀 **Fast Directory Scanning**: Efficiently scans directories using Rust's async capabilities
- 📁 **Smart File Management**: 
  - Browse and select directories
  - View files with serial numbers and paths
  - Click to open files directly
  - Keyboard navigation support (arrow keys + Enter)
- 🔍 **Extension Filtering**: 
  - Filter files by extension (e.g., "txt,pdf,doc")
  - Real-time filtering as you type
  - Case-insensitive matching
- 💾 **Data Export**: Export file information to CSV format
- 🎯 **User-Friendly Interface**:
  - Clean, modern UI with egui
  - Status messages for operations
  - Tooltips for better usability
  - File size display on hover

## Usage

1. **Scanning Files**:
   - Click "Browse" to select a directory
   - Click "Scan" to start scanning
   - Use "Clear" to reset the file list

2. **Filtering**:
   - Enter file extensions in the filter field (comma-separated)
   - Filter updates automatically
   - Click "Apply" to manually trigger filtering

3. **File Operations**:
   - Click on file paths to open them
   - Use arrow keys to navigate
   - Press Enter to open selected file
   - Hover over files to see size information

4. **Export**:
   - Click "Save" to export file list to CSV
   - Includes file name, path, size, and attributes

## Technical Details

- Built with Rust and egui
- Uses tokio for async operations
- Implements efficient file system traversal
- Supports Windows file attributes
- Handles large directories with batch processing

## Requirements

- Rust 1.70 or higher
- Windows OS (uses Windows-specific file attributes)
- 4GB RAM recommended for large directories 