#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Akamai Clean IP Scanner
PyQt5 GUI Version
"""

import ipaddress
import random
import threading
import time
import socket
import ssl
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from pathlib import Path
import csv
import json
import sys

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QTabWidget, QGroupBox, QLabel, QLineEdit, QPushButton, QTextEdit,
    QTableWidget, QTableWidgetItem, QProgressBar, QSpinBox, QDoubleSpinBox,
    QComboBox, QFileDialog, QMessageBox, QHeaderView, QCheckBox,
    QListWidget, QListWidgetItem, QSplitter, QPlainTextEdit
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor, QBrush


# ==================== Akamai IP Ranges Database ====================
AKAMAI_BULK_DATABASE = [
    "2.16.0.0/13", "2.16.0.0/24", "2.16.1.0/24", "2.16.2.0/24", "2.16.3.0/24", "2.16.4.0/23",
    "2.16.6.0/24", "2.16.7.0/24", "2.16.8.0/24", "2.16.10.0/24", "2.16.11.0/24", "2.16.12.0/23",
    "2.16.14.0/24", "2.16.15.0/24", "2.16.16.0/24", "2.16.18.0/24", "2.16.22.0/24", "2.16.23.0/24",
    "2.16.24.0/23", "2.16.26.0/24", "2.16.27.0/24", "2.16.28.0/24", "2.16.29.0/24", "2.16.30.0/23",
    "204.2.211.0/26", "204.2.211.192/26", "204.2.255.0/25", "204.8.48.0/22", "204.8.48.0/24",
    "204.10.28.0/22", "204.10.28.0/24", "204.10.29.0/24", "204.93.38.0/23", "204.93.46.0/23",
    "204.93.48.0/24", "204.141.239.0/24", "204.237.134.0/25", "204.237.142.0/23", "204.237.182.0/25",
    "204.237.201.0/26", "204.237.229.0/25", "204.245.23.0/24", "204.245.143.0/25", "204.246.230.0/24",
    "206.55.4.128/25", "206.57.28.0/24", "206.132.122.0/24", "206.239.100.0/23"
]

PRESET_RANGES = {
    "2.16.0.0/16": "Akamai EU",
    "2.17.0.0/16": "Akamai EU",
    "2.18.0.0/16": "Akamai EU",
    "23.32.0.0/16": "Akamai US",
    "23.72.0.0/16": "Akamai US",
    "23.192.0.0/16": "Akamai US",
    "23.193.0.0/16": "Akamai US",
    "104.64.0.0/16": "Akamai",
    "104.65.0.0/16": "Akamai",
    "104.103.0.0/16": "Akamai",
    "184.24.0.0/16": "Akamai",
    "184.84.0.0/16": "Akamai",
    "184.86.0.0/16": "Akamai",
}


@dataclass
class ScanResult:
    ip: str
    alive: bool
    latency: float
    reason: str = ""


@dataclass
class ScanState:
    running: bool = False
    stop_requested: bool = False
    results: List[ScanResult] = field(default_factory=list)
    total: int = 0
    tested: int = 0
    alive: int = 0
    dead: int = 0


class ScanWorker(QThread):
    progress_updated = pyqtSignal(int, int, int, int)
    result_found = pyqtSignal(str, float, str)
    scan_finished = pyqtSignal()
    
    def __init__(self, ips: List[str], concurrency: int, timeout: float, use_http: bool):
        super().__init__()
        self.ips = ips
        self.concurrency = concurrency
        self.timeout = timeout
        self.use_http = use_http
        self.stop_requested = False
        self.results = []
        self._lock = threading.Lock()
        
    def stop(self):
        self.stop_requested = True
    
    def test_ip_http(self, ip: str) -> Tuple[bool, float]:
        start_time = time.time()
        urls = [
            f"https://{ip}/favicon.ico",
            f"http://{ip}/favicon.ico",
            f"https://{ip}/",
        ]
        
        for url in urls:
            try:
                req = urllib.request.Request(
                    url,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
                with urllib.request.urlopen(req, timeout=self.timeout):
                    latency = (time.time() - start_time) * 1000
                    return True, latency
            except (urllib.error.URLError, socket.timeout, ssl.SSLError, ConnectionError):
                continue
            except Exception:
                continue
        
        return False, (time.time() - start_time) * 1000
    
    def test_ip_tcp(self, ip: str) -> Tuple[bool, float]:
        ports = [80, 443, 8080, 8443]
        start_time = time.time()
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    latency = (time.time() - start_time) * 1000
                    return True, latency
            except Exception:
                continue
        
        return False, (time.time() - start_time) * 1000
    
    def test_ip(self, ip: str) -> ScanResult:
        if self.use_http:
            alive, latency = self.test_ip_http(ip)
            if alive:
                return ScanResult(ip=ip, alive=True, latency=latency, reason="http")
        
        alive, latency = self.test_ip_tcp(ip)
        return ScanResult(ip=ip, alive=alive, latency=latency, reason="tcp" if alive else "failed")
    
    def run(self):
        tested = 0
        alive = 0
        dead = 0
        total = len(self.ips)
        
        def scan_one(ip: str) -> ScanResult:
            if self.stop_requested:
                return ScanResult(ip=ip, alive=False, latency=0, reason="stopped")
            return self.test_ip(ip)
        
        def update_progress(result: ScanResult):
            nonlocal tested, alive, dead
            tested += 1
            if result.alive:
                alive += 1
            else:
                dead += 1
            
            self.results.append(result)
            self.progress_updated.emit(tested, total, alive, dead)
            
            if result.alive:
                self.result_found.emit(result.ip, result.latency, result.reason)
        
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {executor.submit(scan_one, ip): ip for ip in self.ips}
            
            for future in as_completed(futures):
                if self.stop_requested:
                    for f in futures:
                        f.cancel()
                    break
                
                result = future.result()
                update_progress(result)
        
        self.scan_finished.emit()


class AkamaiScannerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.scan_worker = None
        self.scan_results: List[ScanResult] = []
        self.preset_selected = []
        self.current_mode = "manual"
        self.generated_ips = []
        self.settings = {
            "concurrency": 20,
            "timeout": 3.0,
            "max_ips": 1000,
            "use_http": True
        }
        self.load_settings()
        self.init_ui()
        
    def load_settings(self):
        config_file = Path("scanner_config.json")
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    saved = json.load(f)
                    self.settings.update(saved)
            except:
                pass
    
    def save_settings(self):
        config_file = Path("scanner_config.json")
        try:
            with open(config_file, 'w') as f:
                json.dump(self.settings, f, indent=2)
        except:
            pass
    
    def init_ui(self):
        self.setWindowTitle("Akamai Clean IP Scanner")
        self.setGeometry(100, 100, 1200, 800)
        
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1a1a2e;
            }
            QWidget {
                background-color: #1a1a2e;
                color: #e0e0e0;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            QTabWidget::pane {
                border: 1px solid #16213e;
                background-color: #0f0f1a;
                border-radius: 8px;
            }
            QTabBar::tab {
                background-color: #16213e;
                color: #e0e0e0;
                padding: 10px 20px;
                margin: 2px;
                border-radius: 6px;
            }
            QTabBar::tab:selected {
                background-color: #e94560;
                color: white;
            }
            QGroupBox {
                border: 1px solid #16213e;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QPushButton {
                background-color: #e94560;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #ff6b6b;
            }
            QPushButton:disabled {
                background-color: #555;
            }
            QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QDoubleSpinBox {
                background-color: #0f0f1a;
                border: 1px solid #16213e;
                border-radius: 4px;
                padding: 6px;
                color: #e0e0e0;
            }
            QTableWidget {
                background-color: #0f0f1a;
                border: 1px solid #16213e;
                border-radius: 4px;
                alternate-background-color: #16213e;
            }
            QHeaderView::section {
                background-color: #16213e;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
            QProgressBar {
                border: 1px solid #16213e;
                border-radius: 4px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #e94560;
                border-radius: 3px;
            }
            QListWidget {
                background-color: #0f0f1a;
                border: 1px solid #16213e;
                border-radius: 4px;
            }
        """)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        header_label = QLabel("⚡ Akamai Clean IP Scanner")
        header_label.setAlignment(Qt.AlignCenter)
        header_label.setStyleSheet("font-size: 24px; font-weight: bold; color: #e94560; padding: 10px;")
        main_layout.addWidget(header_label)
        
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        self.input_tab = QWidget()
        self.tab_widget.addTab(self.input_tab, "Input")
        self.setup_input_tab()
        
        self.scan_tab = QWidget()
        self.tab_widget.addTab(self.scan_tab, "Scan")
        self.setup_scan_tab()
        
        self.results_tab = QWidget()
        self.tab_widget.addTab(self.results_tab, "Results")
        self.setup_results_tab()
        
        self.statusBar().showMessage("Ready")
        
    def setup_input_tab(self):
        layout = QVBoxLayout(self.input_tab)
        
        mode_group = QGroupBox("Input Mode")
        mode_layout = QHBoxLayout()
        
        self.manual_btn = QPushButton("Manual")
        self.manual_btn.setCheckable(True)
        self.manual_btn.setChecked(True)
        self.manual_btn.clicked.connect(lambda: self.switch_mode("manual"))
        
        self.preset_btn = QPushButton("Preset")
        self.preset_btn.setCheckable(True)
        self.preset_btn.clicked.connect(lambda: self.switch_mode("preset"))
        
        self.auto_btn = QPushButton("Auto")
        self.auto_btn.setCheckable(True)
        self.auto_btn.clicked.connect(lambda: self.switch_mode("auto"))
        
        mode_layout.addWidget(self.manual_btn)
        mode_layout.addWidget(self.preset_btn)
        mode_layout.addWidget(self.auto_btn)
        mode_layout.addStretch()
        mode_group.setLayout(mode_layout)
        layout.addWidget(mode_group)
        
        # Manual mode
        self.manual_widget = QWidget()
        manual_layout = QVBoxLayout(self.manual_widget)
        
        manual_label = QLabel("Enter IPs, CIDRs (e.g., 23.72.0.0/24) or ranges (2.16.0.1-2.16.0.50):")
        manual_layout.addWidget(manual_label)
        
        self.manual_text = QPlainTextEdit()
        self.manual_text.setPlaceholderText("23.72.0.0/24\n2.16.0.1-2.16.0.50\n104.64.0.5")
        manual_layout.addWidget(self.manual_text)
        
        file_btn = QPushButton("Load from File")
        file_btn.clicked.connect(self.load_from_file)
        manual_layout.addWidget(file_btn)
        
        layout.addWidget(self.manual_widget)
        
        # Preset mode
        self.preset_widget = QWidget()
        self.preset_widget.setVisible(False)
        preset_layout = QVBoxLayout(self.preset_widget)
        
        preset_label = QLabel("Select Akamai Ranges:")
        preset_layout.addWidget(preset_label)
        
        self.preset_list = QListWidget()
        self.preset_list.setSelectionMode(QListWidget.MultiSelection)
        self.preset_list.itemSelectionChanged.connect(self.update_preset_selection)
        for cidr, desc in PRESET_RANGES.items():
            item = QListWidgetItem(f"{cidr} - {desc}")
            item.setData(Qt.UserRole, cidr)
            self.preset_list.addItem(item)
        
        preset_layout.addWidget(self.preset_list)
        
        preset_buttons = QHBoxLayout()
        select_all_btn = QPushButton("Select All")
        select_all_btn.clicked.connect(self.select_all_presets)
        clear_all_btn = QPushButton("Clear All")
        clear_all_btn.clicked.connect(self.clear_all_presets)
        preset_buttons.addWidget(select_all_btn)
        preset_buttons.addWidget(clear_all_btn)
        preset_layout.addLayout(preset_buttons)
        
        self.selected_preset_label = QLabel("Selected: 0 ranges")
        preset_layout.addWidget(self.selected_preset_label)
        
        layout.addWidget(self.preset_widget)
        
        # Auto mode
        self.auto_widget = QWidget()
        self.auto_widget.setVisible(False)
        auto_layout = QVBoxLayout(self.auto_widget)
        
        scan_type_layout = QHBoxLayout()
        scan_type_layout.addWidget(QLabel("Scan Type:"))
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Light Scan (Small ranges - faster)", "Deep Scan (Large ranges - slower)"])
        scan_type_layout.addWidget(self.scan_type_combo)
        scan_type_layout.addStretch()
        auto_layout.addLayout(scan_type_layout)
        
        range_count_layout = QHBoxLayout()
        range_count_layout.addWidget(QLabel("Number of ranges:"))
        self.range_count_spin = QSpinBox()
        self.range_count_spin.setRange(1, 50)
        self.range_count_spin.setValue(5)
        range_count_layout.addWidget(self.range_count_spin)
        range_count_layout.addStretch()
        auto_layout.addLayout(range_count_layout)
        
        generate_btn = QPushButton("Generate IPs from Auto Mode")
        generate_btn.clicked.connect(self.generate_auto_ips)
        auto_layout.addWidget(generate_btn)
        
        self.auto_preview = QPlainTextEdit()
        self.auto_preview.setReadOnly(True)
        self.auto_preview.setPlaceholderText("Generated IPs will appear here...")
        auto_layout.addWidget(self.auto_preview)
        
        layout.addWidget(self.auto_widget)
        
        # Settings
        settings_group = QGroupBox("Scan Settings")
        settings_layout = QGridLayout()
        
        settings_layout.addWidget(QLabel("Concurrency:"), 0, 0)
        self.concurrency_spin = QSpinBox()
        self.concurrency_spin.setRange(1, 200)
        self.concurrency_spin.setValue(self.settings["concurrency"])
        self.concurrency_spin.valueChanged.connect(lambda v: self.settings.update({"concurrency": v}))
        settings_layout.addWidget(self.concurrency_spin, 0, 1)
        
        settings_layout.addWidget(QLabel("Timeout (seconds):"), 0, 2)
        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(0.5, 30)
        self.timeout_spin.setValue(self.settings["timeout"])
        self.timeout_spin.valueChanged.connect(lambda v: self.settings.update({"timeout": v}))
        settings_layout.addWidget(self.timeout_spin, 0, 3)
        
        settings_layout.addWidget(QLabel("Max IPs to test:"), 1, 0)
        self.max_ips_spin = QSpinBox()
        self.max_ips_spin.setRange(100, 50000)
        self.max_ips_spin.setValue(self.settings["max_ips"])
        self.max_ips_spin.valueChanged.connect(lambda v: self.settings.update({"max_ips": v}))
        settings_layout.addWidget(self.max_ips_spin, 1, 1)
        
        self.use_http_check = QCheckBox("Use HTTP (more accurate, slower)")
        self.use_http_check.setChecked(self.settings["use_http"])
        self.use_http_check.toggled.connect(lambda v: self.settings.update({"use_http": v}))
        settings_layout.addWidget(self.use_http_check, 1, 2, 1, 2)
        
        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)
        
        # Action buttons
        action_layout = QHBoxLayout()
        self.start_btn = QPushButton("🚀 Start Scan")
        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn = QPushButton("⏹ Stop Scan")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_scan)
        action_layout.addWidget(self.start_btn)
        action_layout.addWidget(self.stop_btn)
        action_layout.addStretch()
        layout.addLayout(action_layout)
        
        layout.addStretch()
    
    def switch_mode(self, mode: str):
        self.current_mode = mode
        self.manual_widget.setVisible(mode == "manual")
        self.preset_widget.setVisible(mode == "preset")
        self.auto_widget.setVisible(mode == "auto")
        
        # Update button states
        self.manual_btn.setChecked(mode == "manual")
        self.preset_btn.setChecked(mode == "preset")
        self.auto_btn.setChecked(mode == "auto")
    
    def select_all_presets(self):
        for i in range(self.preset_list.count()):
            self.preset_list.item(i).setSelected(True)
    
    def clear_all_presets(self):
        self.preset_list.clearSelection()
    
    def update_preset_selection(self):
        selected = self.preset_list.selectedItems()
        self.preset_selected = [item.data(Qt.UserRole) for item in selected]
        self.selected_preset_label.setText(f"Selected: {len(self.preset_selected)} ranges")
    
    def load_from_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Text File", "", "Text Files (*.txt)")
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.manual_text.setPlainText(content)
                QMessageBox.information(self, "Success", f"Loaded {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load file: {e}")
    
    def generate_auto_ips(self):
        scan_type = "light" if self.scan_type_combo.currentIndex() == 0 else "deep"
        count = self.range_count_spin.value()
        max_ips = self.settings["max_ips"]
        
        if scan_type == "deep":
            candidates = [r for r in AKAMAI_BULK_DATABASE if int(r.split('/')[1]) <= 22]
        else:
            candidates = [r for r in AKAMAI_BULK_DATABASE if int(r.split('/')[1]) >= 23]
        
        if not candidates:
            candidates = AKAMAI_BULK_DATABASE.copy()
        
        selected = random.sample(candidates, min(count, len(candidates)))
        
        all_ips = []
        for cidr in selected:
            try:
                network = ipaddress.IPv4Network(cidr, strict=False)
                ips = [str(ip) for ip in network.hosts()]
                all_ips.extend(ips)
                if len(all_ips) > max_ips * 2:
                    break
            except:
                continue
        
        if len(all_ips) > max_ips:
            all_ips = random.sample(all_ips, max_ips)
        
        all_ips = sorted(all_ips, key=lambda x: [int(i) for i in x.split('.')])
        
        preview_text = "\n".join(all_ips[:100])
        if len(all_ips) > 100:
            preview_text += f"\n\n... and {len(all_ips) - 100} more IPs"
        
        self.auto_preview.setPlainText(preview_text)
        self.generated_ips = all_ips
        QMessageBox.information(self, "Generated", f"Generated {len(all_ips)} IPs from {len(selected)} ranges")
    
    def setup_scan_tab(self):
        layout = QVBoxLayout(self.scan_tab)
        
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)
        
        stats_group = QGroupBox("Statistics")
        stats_layout = QGridLayout()
        
        self.total_label = QLabel("Total: 0")
        self.tested_label = QLabel("Tested: 0")
        self.alive_label = QLabel("Alive: 0")
        self.dead_label = QLabel("Dead: 0")
        self.best_label = QLabel("Best: -- ms")
        self.avg_label = QLabel("Average: -- ms")
        
        stats_layout.addWidget(self.total_label, 0, 0)
        stats_layout.addWidget(self.tested_label, 0, 1)
        stats_layout.addWidget(self.alive_label, 0, 2)
        stats_layout.addWidget(self.dead_label, 1, 0)
        stats_layout.addWidget(self.best_label, 1, 1)
        stats_layout.addWidget(self.avg_label, 1, 2)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        self.status_text = QPlainTextEdit()
        self.status_text.setReadOnly(True)
        self.status_text.setMaximumHeight(100)
        layout.addWidget(self.status_text)
        
        layout.addStretch()
    
    def setup_results_tab(self):
        layout = QVBoxLayout(self.results_tab)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["#", "IP", "Latency (ms)", "Quality", "Reason"])
        self.results_table.setAlternatingRowColors(True)
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.results_table)
        
        export_layout = QHBoxLayout()
        export_txt_btn = QPushButton("Export TXT")
        export_txt_btn.clicked.connect(self.export_txt)
        export_csv_btn = QPushButton("Export CSV")
        export_csv_btn.clicked.connect(self.export_csv)
        export_json_btn = QPushButton("Export JSON")
        export_json_btn.clicked.connect(self.export_json)
        export_layout.addWidget(export_txt_btn)
        export_layout.addWidget(export_csv_btn)
        export_layout.addWidget(export_json_btn)
        export_layout.addStretch()
        layout.addLayout(export_layout)
    
    def parse_ips_from_input(self) -> List[str]:
        if self.current_mode == "preset":
            if not self.preset_selected:
                QMessageBox.warning(self, "Warning", "No ranges selected!")
                return []
            
            all_ips = []
            for cidr in self.preset_selected:
                try:
                    network = ipaddress.IPv4Network(cidr, strict=False)
                    ips = [str(ip) for ip in network.hosts()]
                    all_ips.extend(ips)
                    if len(all_ips) > self.settings["max_ips"] * 2:
                        break
                except:
                    continue
            
            if len(all_ips) > self.settings["max_ips"]:
                all_ips = random.sample(all_ips, self.settings["max_ips"])
            
            return sorted(all_ips, key=lambda x: [int(i) for i in x.split('.')])
        
        elif self.current_mode == "auto":
            if not self.generated_ips:
                QMessageBox.warning(self, "Warning", "Generate IPs first using Auto Mode!")
                return []
            return self.generated_ips
        
        else:
            text = self.manual_text.toPlainText()
            if not text.strip():
                QMessageBox.warning(self, "Warning", "Please enter IPs/CIDRs/ranges!")
                return []
            return self.parse_all_ips(text)
    
    def parse_all_ips(self, text: str) -> List[str]:
        lines = text.strip().split('\n')
        raw_ips = set()
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if '-' in line and '/' not in line:
                parts = line.split('-')
                if len(parts) == 2:
                    try:
                        start = int(ipaddress.IPv4Address(parts[0].strip()))
                        end = int(ipaddress.IPv4Address(parts[1].strip()))
                        if end >= start:
                            for i in range(start, end + 1):
                                raw_ips.add(str(ipaddress.IPv4Address(i)))
                    except:
                        pass
            
            elif '/' in line:
                try:
                    network = ipaddress.IPv4Network(line, strict=False)
                    for ip in network.hosts():
                        raw_ips.add(str(ip))
                except:
                    pass
            
            else:
                try:
                    ipaddress.IPv4Address(line)
                    raw_ips.add(line)
                except:
                    pass
        
        ips = sorted(raw_ips, key=lambda x: [int(i) for i in x.split('.')])
        if len(ips) > self.settings["max_ips"]:
            ips = random.sample(ips, self.settings["max_ips"])
        
        return ips
    
    def start_scan(self):
        ips = self.parse_ips_from_input()
        if not ips:
            return
        
        self.scan_results = []
        self.results_table.setRowCount(0)
        self.status_text.clear()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
        self.scan_worker = ScanWorker(
            ips=ips,
            concurrency=self.settings["concurrency"],
            timeout=self.settings["timeout"],
            use_http=self.settings["use_http"]
        )
        
        self.scan_worker.progress_updated.connect(self.update_progress)
        self.scan_worker.result_found.connect(self.add_result)
        self.scan_worker.scan_finished.connect(self.scan_finished)
        
        self.scan_worker.start()
        self.statusBar().showMessage("Scanning...")
        self.status_text.appendPlainText(f"Started scan on {len(ips)} IPs")
    
    def stop_scan(self):
        if self.scan_worker:
            self.scan_worker.stop()
            self.status_text.appendPlainText("Stopping scan...")
    
    def update_progress(self, tested: int, total: int, alive: int, dead: int):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(tested)
        
        self.total_label.setText(f"Total: {total}")
        self.tested_label.setText(f"Tested: {tested}")
        self.alive_label.setText(f"Alive: {alive}")
        self.dead_label.setText(f"Dead: {dead}")
        
        if alive > 0:
            latencies = [r.latency for r in self.scan_results if r.alive]
            if latencies:
                self.best_label.setText(f"Best: {min(latencies):.0f} ms")
                self.avg_label.setText(f"Average: {sum(latencies)/len(latencies):.0f} ms")
    
    def add_result(self, ip: str, latency: float, reason: str):
        self.scan_results.append(ScanResult(ip=ip, alive=True, latency=latency, reason=reason))
        
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        self.results_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
        self.results_table.setItem(row, 1, QTableWidgetItem(ip))
        self.results_table.setItem(row, 2, QTableWidgetItem(f"{latency:.0f}"))
        
        if latency < 200:
            quality = "Excellent"
            color = QColor(0, 255, 0)
        elif latency < 500:
            quality = "Good"
            color = QColor(100, 255, 100)
        elif latency < 1000:
            quality = "Medium"
            color = QColor(255, 200, 0)
        else:
            quality = "Slow"
            color = QColor(255, 100, 0)
        
        quality_item = QTableWidgetItem(quality)
        quality_item.setForeground(QBrush(color))
        self.results_table.setItem(row, 3, quality_item)
        self.results_table.setItem(row, 4, QTableWidgetItem(reason))
        
        self.results_table.sortItems(2, Qt.AscendingOrder)
    
    def scan_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        alive_count = len([r for r in self.scan_results if r.alive])
        self.statusBar().showMessage(f"Scan completed. Found {alive_count} alive IPs")
        self.status_text.appendPlainText(f"Scan completed. Found {alive_count} alive IPs")
        
        self.save_settings()
    
    def export_txt(self):
        if not self.scan_results:
            QMessageBox.warning(self, "Warning", "No scan results to export!")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(self, "Save TXT", "clean_ips.txt", "Text Files (*.txt)")
        if file_path:
            alive_ips = [r for r in self.scan_results if r.alive]
            alive_ips.sort(key=lambda x: x.latency)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                for r in alive_ips:
                    f.write(f"{r.ip}\n")
            
            QMessageBox.information(self, "Success", f"Saved {len(alive_ips)} IPs to {file_path}")
    
    def export_csv(self):
        if not self.scan_results:
            QMessageBox.warning(self, "Warning", "No scan results to export!")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "clean_ips.csv", "CSV Files (*.csv)")
        if file_path:
            alive_ips = [r for r in self.scan_results if r.alive]
            alive_ips.sort(key=lambda x: x.latency)
            
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['IP', 'Latency (ms)', 'Status', 'Reason'])
                for r in alive_ips:
                    writer.writerow([r.ip, f"{r.latency:.0f}", 'alive', r.reason])
            
            QMessageBox.information(self, "Success", f"Saved {len(alive_ips)} IPs to {file_path}")
    
    def export_json(self):
        if not self.scan_results:
            QMessageBox.warning(self, "Warning", "No scan results to export!")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(self, "Save JSON", "clean_ips.json", "JSON Files (*.json)")
        if file_path:
            alive_ips = [r for r in self.scan_results if r.alive]
            alive_ips.sort(key=lambda x: x.latency)
            
            data = {
                "scan_info": {
                    "total_scanned": len(self.scan_results),
                    "alive_count": len(alive_ips),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                },
                "results": [
                    {"ip": r.ip, "latency_ms": r.latency, "status": "alive", "reason": r.reason}
                    for r in alive_ips
                ]
            }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            QMessageBox.information(self, "Success", f"Saved {len(alive_ips)} IPs to {file_path}")


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = AkamaiScannerGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()