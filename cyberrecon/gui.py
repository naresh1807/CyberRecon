"""Desktop project, scan and observation browser."""
import json
import threading
import time

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, QUrl, Qt, QSize, QTimer, QCoreApplication, QEvent
from PySide6.QtGui import QDesktopServices, QIcon
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPushButton, QTabWidget, QTextEdit, QVBoxLayout, QWidget, QTableWidget, QTableWidgetItem,
    QAbstractItemView, QSpinBox, QScrollArea, QInputDialog, QListWidget, QStackedWidget, QProgressBar, QGridLayout, QTabBar, QListWidgetItem)

from .cli import doctor
from .scanner import scan
from .storage import KINDS, compare_snapshots
from .scope import host_of
from .gui_components import ResultsTable, ObservationTable, OverviewDashboard, SummaryCard, icon, label, ACCENTS


DASHBOARD_STYLE = """
QWidget { background: #031426; color: #afd4f5; font-family: 'Noto Sans'; font-size: 12px; }
QMainWindow, QWidget#root, QWidget#overviewContent { background: #020f20; }
QWidget#dashboardPanel, QWidget#summaryCard { background: #031a2d; border: 1px solid #07547a; border-radius: 5px; }
QWidget#dashboardPanel QLabel, QWidget#summaryCard QLabel { border: none; background: transparent; }
QLabel#panelTitle { color: #9ed6ff; font-size: 13px; font-weight: 600; }
QLabel#cardValue { font-size: 23px; font-weight: bold; color: #e7f3ff; }
QLabel#targetCardValue { font-size: 16px; font-weight: bold; color: #e7f3ff; }
QLabel#cardNote, QLabel#muted, QLabel#tableSummary { color: #80b4de; font-size: 11px; }
QLabel#cardIcon { background: #082c47; border-radius: 22px; }
QLineEdit, QComboBox, QTextEdit { background: #041b30; border: 1px solid #07547a; border-radius: 4px; padding: 7px; selection-background-color: #0869b9; }
QLineEdit:focus { border: 1px solid #20b3ff; }
QLineEdit#targetInput { font-size: 15px; padding: 12px; border: 1px solid #009fff; }
QPushButton { background: #072741; border: 1px solid #10557d; padding: 7px 12px; border-radius: 4px; color: #d1eaff; }
QPushButton:hover { background: #0a3b61; border-color: #1c9eff; }
QPushButton:disabled { color: #607e99; background: #061a2b; border-color: #12354e; }
QPushButton#analyzeButton, QPushButton#quickExport { background: #007cf4; border-color: #139cff; color: white; }
QPushButton#analyzeButton { font-weight: 600; font-size: 15px; padding: 12px 20px; }
QPushButton#pageButton { padding: 0; background: #062742; border: none; }
QListWidget { background: #021326; border: none; }
QListWidget::item { padding: 12px 8px; border-radius: 4px; margin: 2px 0; }
QListWidget::item:selected { background: #075bb4; color: #eff8ff; border-left: 3px solid #00a9ff; }
QListWidget::item:hover { background: #083355; }
QTableWidget { background: #041b2f; alternate-background-color: #052039; border: 1px solid #073b5b; selection-background-color: #0a4b79; selection-color: white; }
QTableWidget::item { padding: 3px; border-bottom: 1px solid #082c44; }
QTableWidget::item:hover { background: #0a3859; }
QHeaderView::section { background: #062540; color: #a4d7ff; padding: 5px; border: none; border-right: 1px solid #0a3855; font-weight: 500; }
QScrollArea, QStackedWidget { border: none; }
QScrollBar:vertical { background: #021326; width: 9px; }
QScrollBar::handle:vertical { background: #12517a; min-height: 25px; border-radius: 4px; }
QScrollBar:horizontal { background: #021326; height: 9px; }
QScrollBar::handle:horizontal { background: #12517a; min-width: 25px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }
QTableWidget QAbstractScrollArea::corner { background: #031a2d; }
QProgressBar { background: #06243a; border: none; }
QProgressBar::chunk { background: #00afff; }
QTabBar::tab { background: #031a2c; border: 1px solid #10405d; padding: 9px 13px; margin-right: 3px; border-radius: 3px; }
QTabBar::tab:selected { background: #007cec; color: white; border-color: #19a5ff; }
QTabBar::tab:hover { background: #0a3658; }
"""


class Signals(QObject):
    done = Signal(str)
    error = Signal(str)
    progress = Signal(str)


class Worker(QRunnable):
    def __init__(self, repo, project, target, settings, cancel):
        super().__init__()
        self.args = repo, project, target
        self.settings, self.cancel = settings, cancel
        self.signals = Signals()

    def run(self):
        try:
            self.signals.done.emit(scan(*self.args, **self.settings, cancel=self.cancel, progress=self.signals.progress.emit))
        except Exception as exc:
            self.signals.error.emit(str(exc))


class ProviderWorker(QRunnable):
    def __init__(self, repo, project, target, provider, cancel):
        super().__init__()
        self.args = repo, project, target, provider
        self.cancel = cancel
        self.signals = Signals()

    def run(self):
        try:
            from .providers import host_lookup
            self.signals.done.emit(host_lookup(*self.args, cancel=self.cancel))
        except Exception as exc:
            self.signals.error.emit(str(exc))


class LocalWorker(QRunnable):
    """Keep local diagnostics and potentially large report/graph work off the UI."""
    def __init__(self, operation):
        super().__init__()
        self.operation = operation
        self.signals = Signals()

    def run(self):
        try:
            self.signals.done.emit(self.operation())
        except Exception as exc:
            self.signals.error.emit(type(exc).__name__ + ": local operation failed.")


class Window(QMainWindow):
    def __init__(self, repo):
        super().__init__()
        self.repo, self.cancel, self.worker = repo, threading.Event(), None
        self.setWindowTitle("CyberRecon — Authorized Reconnaissance")
        from pathlib import Path
        self.setWindowIcon(QIcon(str(Path(__file__).parent / 'assets/cyberrecon.svg')))
        self.resize(1536, 1024)
        self.setMinimumSize(560, 520)
        self.setStyleSheet(DASHBOARD_STYLE)
        self.local_jobs = []
        self._closing = False
        self.advanced = QDialog(self)
        self.advanced.setWindowTitle("Authorization and advanced settings")
        self.advanced.resize(820, 720)
        advanced_layout = QVBoxLayout(self.advanced)
        form = QFormLayout()
        self.includes, self.excludes, self.authority = QLineEdit(), QLineEdit(), QLineEdit()
        self.includes.setPlaceholderText("Blank = exact target only; wildcard only if authorized")
        self.excludes.setPlaceholderText("Comma-separated exclusions; override allowed scope")
        self.authority.setPlaceholderText("Ownership or written authorization reference")
        self.passive, self.history = QComboBox(), QComboBox()
        self.passive.addItems(["None", "ct", "ct,dnsdumpster", "dnsdumpster", "ct,subfinder,assetfinder", "subfinder", "assetfinder", "amass"])
        self.passive.setCurrentText("ct")
        self.passive.setToolTip("Default: query public certificate-transparency services. DNSDumpster is optional and requires DNSDUMPSTER_API_KEY in the launch environment. Provider records are historical and unverified; child names outside Allowed scope are discarded. Add wildcard scope only when authorized.")
        self.history.addItems(["None", "gau", "waybackurls"])
        self.lifecycle, self.go_dns = QCheckBox("Upstream lifecycle lookup"), QCheckBox("Go DNS worker")
        self.enable_ports = QCheckBox("Nmap TCP inventory for explicitly authorized IP targets")
        self.enable_ports.setChecked(True)
        self.port_list = QLineEdit("22,80,443,8080,8443")
        self.udp, self.cve = QCheckBox("UDP (requires suitable privileges)"), QCheckBox("NVD candidates; not confirmed vulnerabilities")
        self.wordlist, self.ca_bundle, self.dns_wordlist = QLineEdit(), QLineEdit(), QLineEdit()
        self.nmap_profile = QComboBox(); self.nmap_profile.addItems(["service", "quick", "full"])
        self.nmap_timing = QSpinBox(); self.nmap_timing.setRange(0, 4); self.nmap_timing.setValue(3)
        self.nmap_timeout = QSpinBox(); self.nmap_timeout.setRange(10, 600); self.nmap_timeout.setValue(180)
        self.nmap_host_timeout = QSpinBox(); self.nmap_host_timeout.setRange(10, 600); self.nmap_host_timeout.setValue(120)
        self.nmap_rate = QSpinBox(); self.nmap_rate.setRange(1, 1000); self.nmap_rate.setValue(2)
        self.nmap_os = QCheckBox("Opt-in OS detection; requires privileges")
        self.nmap_scripts = QCheckBox("Opt-in default AND safe NSE scripts")
        self.check_wildcard = QCheckBox("Opt-in DNS controls; wildcard scope required")
        self.crawl = QCheckBox("Bounded crawl: 30 pages, depth 2")
        self.crawl.setChecked(True)
        for field_label, widget in (("Allowed scope", self.includes), ("Exclusions", self.excludes),
                ("Authorization", self.authority), ("Passive discovery (public CT lookup by default)", self.passive),
                ("Historical URLs", self.history), ("Lifecycle", self.lifecycle), ("DNS worker", self.go_dns),
                ("Ports", self.enable_ports), ("Nmap profile", self.nmap_profile), ("TCP port selection", self.port_list), ("Timing", self.nmap_timing), ("Nmap timeout (s)", self.nmap_timeout), ("Host timeout (s)", self.nmap_host_timeout), ("Probe rate", self.nmap_rate), ("OS hints", self.nmap_os), ("NSE", self.nmap_scripts), ("UDP", self.udp), ("DNS wordlist", self.dns_wordlist), ("Wildcard controls", self.check_wildcard),
                ("CVE lookup", self.cve), ("Content wordlist", self.wordlist), ("Trusted lab CA", self.ca_bundle),
                ("Web discovery", self.crawl)):
            form.addRow(field_label, widget)
        form_widget = QWidget(); form_widget.setLayout(form)
        form_scroll = QScrollArea(); form_scroll.setWidgetResizable(True); form_scroll.setWidget(form_widget)
        advanced_layout.addWidget(form_scroll, 2)
        self.tabs, self.views = QTabWidget(), {}
        for name in ("scope", "settings", "doctor", "comparison"):
            view = QTextEdit()
            view.setReadOnly(True)
            self.views[name] = view
            self.tabs.addTab(view, name.title())
        advanced_layout.addWidget(self.tabs)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.advanced.reject)
        advanced_layout.addWidget(buttons)
        self.views["settings"].setPlainText(
            "Bounded profile: exact authorized target; 30 hosts, 30 pages, depth 2, 100 HTTP requests, 2 requests/second.\n"
            "TLS verification and exclusions apply to every request. Discovered IPs/subdomains do not expand authorization.\n"
            "Nmap is IP-only. Full profile selects ports 1–65535; bounded timeouts can leave partial coverage. UDP/OS/NSE require opt-in; no privilege elevation.\n"
            "GUI Start Recon defaults to scoped DNS, HTTP/TLS, technology checks, a bounded crawl and public CT lookup. "
            "Subdomains outside Allowed scope are discarded; include a wildcard only when authorized.\n"
            "DNSDumpster is optional and needs DNSDUMPSTER_API_KEY in the environment; its records are provider observations, not current verification. "
            "External history, lifecycle/NVD, active DNS wordlists, OS/UDP/NSE remain opt-in. "
            "Host intelligence uses configured environment credentials; keys are never saved here.")
        root = QWidget(); root.setObjectName("root")
        layout = QVBoxLayout(root); layout.setContentsMargins(16, 16, 16, 10); layout.setSpacing(10)
        header = QGridLayout(); header.setHorizontalSpacing(18)
        self.brand = QWidget(); brand_layout = QHBoxLayout(self.brand); brand_layout.setContentsMargins(0, 0, 0, 0)
        logo = QLabel(); logo.setFixedSize(56, 56); logo.setPixmap(self.windowIcon().pixmap(52, 52)); brand_layout.addWidget(logo)
        title = QLabel("<b style='font-size:24px;color:#eef7ff'>CyberRecon</b><br><span style='color:#83caff'>Automated Security Reconnaissance</span>")
        brand_layout.addWidget(title, 1)
        header.addWidget(self.brand, 0, 0, 2, 1)
        self.target_row = QWidget(); target_layout = QHBoxLayout(self.target_row); target_layout.setContentsMargins(0, 0, 0, 0)
        self.target = QLineEdit(); self.target.setObjectName("targetInput")
        self.target.addAction(icon('link'), QLineEdit.LeadingPosition)
        self.target.setPlaceholderText("Enter an authorized URL, domain, or IP address")
        self.target.returnPressed.connect(self.start_scan); target_layout.addWidget(self.target, 1)
        self.start = QPushButton("Start Recon"); self.start.setIcon(icon('play', '#ffffff')); self.start.setObjectName("analyzeButton")
        self.start.clicked.connect(self.start_scan); target_layout.addWidget(self.start)
        self.stop = QPushButton("Cancel"); self.stop.setEnabled(False); self.stop.clicked.connect(self.cancel_scan)
        target_layout.addWidget(self.stop)
        header.addWidget(self.target_row, 0, 1)
        self.description = label("Start Recon runs bounded DNS, HTTP/TLS, technology checks, web discovery and a public CT lookup. Extra providers and active probes remain opt-in.", 'muted')
        self.description.setWordWrap(True); header.addWidget(self.description, 1, 1)
        header.setColumnStretch(1, 1); layout.addLayout(header)
        self.header_layout = header
        self.status = label("Ready • bounded reconnaissance • authorization required before active requests", 'muted')
        self.status.setWordWrap(True); layout.addWidget(self.status)
        self.progress = QProgressBar(); self.progress.setRange(0, 1); self.progress.setValue(0)
        self.progress.setTextVisible(False); self.progress.setMaximumHeight(3); layout.addWidget(self.progress)
        body = QHBoxLayout(); body.setSpacing(14)
        self.sidebar = QWidget(); sidebar_layout = QVBoxLayout(self.sidebar); sidebar_layout.setContentsMargins(0, 0, 0, 0)
        self.navigation, self.pages = QListWidget(), QStackedWidget(); self.navigation.setIconSize(QSize(23, 23))
        self.navigation.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.sidebar.setFixedWidth(190); sidebar_layout.addWidget(self.navigation, 1)
        self.current_state = 'Ready'
        self.application_state = label("● Ready", 'muted'); sidebar_layout.addWidget(self.application_state)
        from . import __version__
        self.version_label = label("CyberRecon v" + __version__, 'muted'); sidebar_layout.addWidget(self.version_label)
        settings = QPushButton("Scope && settings"); settings.setIcon(icon('scope')); settings.clicked.connect(self.advanced.show)
        sidebar_layout.addWidget(settings); self.settings_button = settings
        about = QPushButton("About"); about.clicked.connect(self.about); sidebar_layout.addWidget(about); self.about_button = about
        body.addWidget(self.sidebar)
        workspace = QWidget(); workspace_layout = QVBoxLayout(workspace); workspace_layout.setContentsMargins(0, 0, 0, 0); workspace_layout.setSpacing(12)
        self.cards_layout = QGridLayout(); self.cards_layout.setSpacing(10); self.cards = {}
        for key, title, glyph, accent in (('target', 'Target', 'target', '#00b9f6'),
                ('domains', 'Subdomains', 'domains', '#25d9ba'), ('ips', 'IP Addresses', 'ips', '#438fff'),
                ('ports', 'Open Ports', 'ports', '#25d9ba'), ('findings', 'Vulnerabilities', 'findings', '#ff596d'),
                ('technologies', 'Technologies', 'technologies', '#718fff')):
            self.cards[key] = SummaryCard(title, glyph, accent)
        workspace_layout.addLayout(self.cards_layout)
        self.dashboard_tabs = QTabBar(); self.dashboard_tabs.setExpanding(False); self.dashboard_tabs.setUsesScrollButtons(True)
        self.tab_keys = ['overview', 'domains', 'ips', 'nmap', 'technologies', 'findings', 'dns', 'tls', 'web', 'screenshots', 'export', 'evidence', 'history', 'urls', 'apis', 'frontend', 'backend', 'results', 'dnsdumpster']
        for text in ('Overview', 'Subdomains', 'IPs', 'Nmap', 'Technologies', 'Vulnerabilities', 'DNS', 'SSL/TLS', 'HTTP Headers', 'Screenshots', 'Report', 'Coverage', 'History', 'URLs', 'APIs', 'Frontend', 'Backend', 'All Results', 'DNSDumpster'):
            self.dashboard_tabs.addTab(text)
        workspace_layout.addWidget(self.dashboard_tabs); workspace_layout.addWidget(self.pages, 1)
        body.addWidget(workspace, 1); layout.addLayout(body, 1)
        from .dashboard import SECTIONS
        self.section_keys = [key for key, _ in SECTIONS]; self.result_views = {}
        for key, text in SECTIONS:
            item = QListWidgetItem(icon(key), text); item.setToolTip(text); self.navigation.addItem(item)
            if key == "overview":
                view = OverviewDashboard(self.export_format, self.navigate); self.overview = view
            elif key == "history":
                view = QWidget(); history_layout = QVBoxLayout(view)
                self.projects, self.scans = QComboBox(), QComboBox()
                self.projects.currentIndexChanged.connect(self.refresh_scans); self.scans.currentIndexChanged.connect(self.show_scan)
                history_layout.addWidget(label("Saved authorization scopes")); history_layout.addWidget(self.projects); history_layout.addWidget(self.scans)
                self.views["scan_history"] = ObservationTable(); history_layout.addWidget(self.views["scan_history"])
                for text, action in (("Edit scope", self.edit_scope), ("Compare previous scan", self.compare)):
                    button = QPushButton(text); button.clicked.connect(action); history_layout.addWidget(button)
            elif key == "export":
                view = QWidget(); exports = QVBoxLayout(view)
                info = label("Export the selected scan with recorded scope, timestamps, settings, evidence and errors. JSON, CSV, HTML, PDF and relationship graph are supported. These are observations requiring validation.")
                info.setWordWrap(True); exports.addWidget(info)
                for text, action in (("Export reports", self.export), ("Open relationship graph", self.open_graph), ("Configured host intelligence", self.host_intelligence)):
                    button = QPushButton(text); button.clicked.connect(action); exports.addWidget(button)
                self.report_preview = QTextEdit(); self.report_preview.setReadOnly(True)
                self.report_preview.setPlaceholderText('Select a persisted scan to view its full report, scope and original observations.')
                exports.addWidget(self.report_preview, 1)
            elif key == "results":
                view = ResultsTable(self.repo); self.result_views[key] = view
            elif key == "screenshots":
                view = QWidget(); empty = QVBoxLayout(view)
                notice = label("Screenshot collection is not supported by the scan engine. No target screenshots have been collected. Use HTTP Headers, Technologies and Reports for the available observations.")
                notice.setWordWrap(True); empty.addWidget(notice); empty.addStretch()
            else:
                view = ObservationTable(); self.result_views[key] = view
            self.pages.addWidget(view)
        from .dashboard import VIEW_ALIASES
        for name, key in VIEW_ALIASES.items(): self.views[name] = self.result_views[key]
        self.views["dashboard"] = self.overview
        self.navigation.currentRowChanged.connect(self.select_section)
        self.dashboard_tabs.currentChanged.connect(lambda index: self.navigate(self.tab_keys[index]))
        self.navigation.setCurrentRow(0)
        footer = label("CyberRecon · Scope enforced  |  Authorized reconnaissance only  |  Discovered assets do not expand permission", 'muted')
        footer.setWordWrap(True); footer.setAlignment(Qt.AlignCenter); layout.addWidget(footer)
        self.setCentralWidget(root); self.reflow()
        self.refresh_projects()
        self.views["doctor"].setPlainText("Checking local dependencies and tool versions…")
        self.doctor_worker = LocalWorker(lambda: json.dumps(doctor(repo.home), indent=2))
        self.doctor_worker.signals.done.connect(self.views["doctor"].setPlainText)
        self.doctor_worker.signals.error.connect(self.views["doctor"].setPlainText)
        # Diagnostics also own queued signals: include them in closeEvent's drain.
        self.local_jobs.append(self.doctor_worker)
        self.doctor_worker.signals.done.connect(lambda _: self.local_jobs.remove(self.doctor_worker))
        self.doctor_worker.signals.error.connect(lambda _: self.local_jobs.remove(self.doctor_worker))
        QThreadPool.globalInstance().start(self.doctor_worker)

    def about(self):
        from . import __version__
        QMessageBox.information(self, 'About CyberRecon',
            f'CyberRecon {__version__}\nAuthorized, scope-controlled reconnaissance.\nMIT License • CyberRecon contributors\nDesktop and production release gates are documented in the repository.')

    def refresh_projects(self, preferred=None):
        self.projects.blockSignals(True)
        self.projects.clear()
        for item in self.repo.projects():
            self.projects.addItem(item["name"], item["id"])
        self.projects.addItem("New scan", None)
        if preferred:
            self.projects.setCurrentIndex(self.projects.findData(preferred))
        self.projects.blockSignals(False)
        self.refresh_scans()

    def refresh_scans(self):
        self.scans.blockSignals(True)
        self.scans.clear()
        project = self.projects.currentData()
        if project:
            scope = self.repo.scope(project)
            self.includes.setText(", ".join(scope.include))
            self.excludes.setText(", ".join(scope.exclude))
            self.authority.setText(self.repo.project(project)["authority"])
            self.views["scope"].setPlainText(json.dumps(self.repo.scope(project).to_dict(), indent=2))
            for item in self.repo.scans(project):
                self.scans.addItem(item["started_at"] + " • " + item["status"] + " • " + item["target"], item["id"])
            self.views["scan_history"].setPlainText(json.dumps(self.repo.scans(project)))
        else:
            self.includes.clear()
            self.excludes.clear()
            self.authority.clear()
            self.views["scope"].clear()
            self.views["scan_history"].clear()
        self.scans.blockSignals(False)
        self.show_scan()

    def navigate(self, key):
        self.navigation.setCurrentRow(self.section_keys.index(key))

    def select_section(self, index):
        if index < 0: return
        self.pages.setCurrentIndex(index)
        key = self.section_keys[index]
        self.dashboard_tabs.blockSignals(True)
        self.dashboard_tabs.setCurrentIndex(self.tab_keys.index(key) if key in self.tab_keys else -1)
        self.dashboard_tabs.blockSignals(False)

    def set_application_state(self, state):
        self.current_state = state
        color = (ACCENTS['danger'] if state.casefold() in ('failed', 'error') else
                 ACCENTS['warning'] if state.casefold() in ('partial', 'cancelled', 'cancelling') else
                 ACCENTS['cyan'] if state.casefold() in ('scanning', 'running', 'provider lookup') else ACCENTS['success'])
        self.application_state.setText('●' if self.width() < 900 else '● ' + state.title())
        self.application_state.setToolTip(state.title())
        self.application_state.setStyleSheet('color: ' + color + ';')

    def reflow(self):
        if not hasattr(self, 'cards'): return
        narrow = self.width() < 900
        self.sidebar.setFixedWidth(54 if narrow else 190)
        from .dashboard import SECTIONS
        for index, (_, text) in enumerate(SECTIONS): self.navigation.item(index).setText('' if narrow else text)
        self.version_label.setText('v' + __import__('cyberrecon').__version__ if narrow else 'CyberRecon v' + __import__('cyberrecon').__version__)
        self.settings_button.setText('' if narrow else 'Scope && settings')
        self.about_button.setText('?' if narrow else 'About')
        self.settings_button.setToolTip('Authorization, scope and settings')
        self.header_layout.removeWidget(self.brand); self.header_layout.removeWidget(self.target_row); self.header_layout.removeWidget(self.description)
        if narrow:
            self.header_layout.addWidget(self.brand, 0, 0, 1, 2)
            self.header_layout.addWidget(self.target_row, 1, 0, 1, 2)
            self.header_layout.addWidget(self.description, 2, 0, 1, 2)
        else:
            self.header_layout.addWidget(self.brand, 0, 0, 2, 1)
            self.header_layout.addWidget(self.target_row, 0, 1)
            self.header_layout.addWidget(self.description, 1, 1)
        columns = 6 if self.width() >= 1400 else 3 if self.width() >= 850 else 2
        for widget in self.cards.values(): self.cards_layout.removeWidget(widget)
        for index, widget in enumerate(self.cards.values()): self.cards_layout.addWidget(widget, index // columns, index % columns)
        for index in range(6): self.cards_layout.setColumnStretch(index, 1 if index < columns else 0)
        self.application_state.setMaximumWidth(50 if narrow else 185)
        self.set_application_state(self.current_state)
        self.start.setText('Start' if self.width() < 650 else 'Start Recon')

    def resizeEvent(self, event):
        super().resizeEvent(event); self.reflow()

    def show_scan(self):
        from .dashboard import dashboard_rows, overview_data
        from .scope import host_of
        identifier = self.scans.currentData()
        snapshot = self.repo.snapshot(identifier) if identifier else None
        self.display_snapshot(snapshot)

    def display_snapshot(self, snapshot):
        from .dashboard import dashboard_rows, overview_data
        if snapshot:
            for key, rows in dashboard_rows(snapshot).items():
                if key in self.result_views: self.result_views[key].set_records(rows)
            self.result_views["results"].set_records(snapshot.get("results", []))
            data = overview_data(snapshot)
            for key, columns in (('domains', ['subdomain', 'ip_address', 'status']),
                                 ('ips', ['address', 'hostnames', 'location', 'asn'])):
                self.result_views[key].set_records(data[key], columns)
        else:
            for view in self.result_views.values(): view.clear()
        self.overview.set_snapshot(snapshot)
        self.report_preview.setPlainText(json.dumps(snapshot, indent=2, ensure_ascii=False) if snapshot else '')
        if not self.worker:
            status = snapshot['scan']['status'] if snapshot else ''
            warnings = snapshot['scan'].get('warnings', []) if snapshot else []
            self.overview.set_message(
                f'Incomplete coverage ({status}): ' + ('; '.join(warnings) or
                    'Inspect Progress & Coverage for stage results; collected observations are retained.')
                if status in ('partial', 'cancelled', 'failed') else '')
        data = overview_data(snapshot)
        self.cards['target'].set_value(host_of(data['target']) if snapshot else data['target'], data['status'])
        self.cards['target'].value.setToolTip(data['target'])
        for key in ('domains', 'ips', 'technologies'):
            self.cards[key].set_value(len(data[key]) if snapshot else '—', 'Observed' if data[key] else 'No observations')
        self.cards['ports'].set_value(sum(row['state'] == 'open' for row in data['ports']) if snapshot else '—', 'Observed open services' if data['ports'] else 'No port observations')
        severe = any(row['severity'].casefold() in ('critical', 'high') for row in data['findings'])
        self.cards['findings'].set_value(len(data['findings']) if snapshot else '—', 'Potential issues · review required', ACCENTS['danger'] if severe else ACCENTS['warning'])
        if not self.worker:
            state = data['status'] if snapshot else 'Ready'
            self.set_application_state(state)

    def export_format(self, format_name):
        """Generate the existing report bundle and identify the requested artifact."""
        identifier = self.scans.currentData()
        if not identifier or self.local_jobs: return
        destination = QFileDialog.getExistingDirectory(self, 'Export ' + format_name + ' report bundle')
        if not destination: return
        from .reporting import export_reports
        filenames = {'JSON': 'scan.json', 'HTML': 'report.html', 'PDF': 'report.pdf'}
        self.status.setText('Generating ' + format_name + ' report…')
        from pathlib import Path
        self.local_task(lambda: export_reports(self.repo, identifier, destination),
                        lambda path: self.status.setText('Exported ' + format_name + ': ' + str(Path(path) / filenames[format_name])))

    def scan_context(self):
        """Create/reuse the internal history context directly from scan inputs."""
        from .scope import Scope, host_of
        from .dashboard import normalize_target
        target = normalize_target(self.target.text())
        self.target.setText(target)
        split = lambda text: [value.strip() for value in text.split(",") if value.strip()]
        scope = Scope(tuple(split(self.includes.text()) or [host_of(target)]), tuple(split(self.excludes.text())))
        host = scope.require(target, passive=True)
        authority = self.authority.text().strip()
        if not authority:
            raise ValueError("Enter an authorization reference, such as My own system or the program scope URL.")
        for project in self.repo.projects():
            if project["authority"] == authority and json.loads(project["scope"]) == scope.to_dict():
                identifier = project["id"]
                break
        else:
            identifier = self.repo.create_project(host, scope.include, scope.exclude, authority)
        self.refresh_projects(identifier)
        return identifier

    def start_scan(self):
        if self.worker:
            return
        from .dashboard import normalize_target, applicable_ports
        try:
            self.target.setText(normalize_target(self.target.text()))
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid target", str(exc))
            return
        if not self.authority.text().strip():
            reference, accepted = QInputDialog.getText(self, "Authorize target", "Ownership or written authorization reference for this target:")
            if not accepted or not reference.strip():
                self.status.setText("Scan not started: authorization reference required.")
                return
            self.authority.setText(reference.strip())
        self.cancel.clear()
        settings = {"crawl": self.crawl.isChecked(), "passive": self.passive.currentText() if self.passive.currentIndex() else None,
                    "history": self.history.currentText() if self.history.currentIndex() else None,
                    "lifecycle": self.lifecycle.isChecked(), "go_dns": self.go_dns.isChecked(),
                    "ports": applicable_ports(self.target.text(), ("" if self.nmap_profile.currentText() == "full" else self.port_list.text())) if self.enable_ports.isChecked() else None,
                    "udp": self.udp.isChecked() and applicable_ports(self.target.text(), self.port_list.text()) is not None, "cve": self.cve.isChecked(), "ca_bundle": self.ca_bundle.text() or None, "nmap_unprivileged": not self.udp.isChecked() and not self.nmap_os.isChecked(),
                    "nmap_profile": self.nmap_profile.currentText(), "nmap_timing": self.nmap_timing.value(), "nmap_timeout": self.nmap_timeout.value(), "nmap_host_timeout": self.nmap_host_timeout.value(), "nmap_rate": self.nmap_rate.value(), "nmap_os": self.nmap_os.isChecked(), "nmap_scripts": self.nmap_scripts.isChecked(), "check_wildcard": self.check_wildcard.isChecked()}
        if self.wordlist.text():
            from pathlib import Path
            try:
                path = Path(self.wordlist.text())
                if path.stat().st_size > 64 * 1024:
                    raise ValueError("Wordlist exceeds 64 KiB.")
                settings["words"] = path.read_text().splitlines()
            except (ValueError, OSError) as exc:
                QMessageBox.warning(self, "Wordlist failed", str(exc))
                return
        try:
            project = self.scan_context()
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Check scan scope", str(exc))
            return
        if self.dns_wordlist.text():
            from pathlib import Path
            try:
                path = Path(self.dns_wordlist.text())
                if path.stat().st_size > 64 * 1024:
                    raise ValueError("DNS wordlist exceeds 64 KiB.")
                settings["dns_words"] = path.read_text().splitlines()
            except (ValueError, OSError):
                self.status.setText("Invalid DNS wordlist; check labels, size and scope."); return
        self.worker = Worker(self.repo, project, self.target.text(), settings, self.cancel)
        self.worker.signals.done.connect(self.finished)
        self.worker.signals.error.connect(self.failed)
        self.running_scan_id = None; self.last_live_refresh = 0
        self.worker.signals.progress.connect(self.scan_progress)
        self.projects.setEnabled(False)
        self.scans.setEnabled(False)
        self.start.setEnabled(False)
        self.target.setEnabled(False)
        self.stop.setEnabled(True)
        self.progress.setRange(0, 0)
        self.overview.set_snapshot(None)
        self.overview.set_message('Collecting authorized observations… Saved results refresh as stages progress.', loading=True)
        for key, card in self.cards.items():
            if key != 'target': card.set_value('…', 'Collection in progress')
        self.set_application_state("Scanning")
        self.cards["target"].set_value(host_of(self.target.text()), "Scan in progress")
        self.status.setText("Scanning; rate 2 requests/second, bounded requests, scope checked before requests.")
        QThreadPool.globalInstance().start(self.worker)

    def scan_progress(self, message):
        """Render only this worker's persisted job, throttled on real progress."""
        import time
        if not self.worker:
            return
        self.status.setText(message)
        if message.startswith("Scan job: "):
            identifier = message.removeprefix("Scan job: ")
            snapshot = self.repo.snapshot(identifier)
            if snapshot["scan"]["project_id"] != self.worker.args[1]:
                return
            self.running_scan_id = identifier
            self.refresh_scans()
            self.scans.setCurrentIndex(self.scans.findData(identifier))
        now = time.monotonic()
        if self.running_scan_id and (message.startswith("Stage:") or now - self.last_live_refresh >= .25):
            snapshot = self.repo.snapshot(self.running_scan_id)
            self.display_snapshot(snapshot)
            # Streaming observations do not mean the scan has finished.
            self.overview.set_message("Scan in progress; coverage is provisional. " + message, loading=not bool(snapshot['http'] or snapshot['dns']))
            for button in self.overview.export_buttons:
                button.setEnabled(False)
            self.last_live_refresh = now

    def edit_scope(self):
        project = self.projects.currentData()
        if not project:
            return
        scope = self.repo.scope(project)
        dialog = QDialog(self)
        dialog.setWindowTitle("Edit authorized scope")
        form = QFormLayout(dialog)
        include, exclude = QLineEdit(", ".join(scope.include)), QLineEdit(", ".join(scope.exclude))
        form.addRow("Include rules", include)
        form.addRow("Exclude rules (override inclusions)", exclude)
        form.addRow("Authorization reference", QLabel(self.repo.project(project)["authority"]))
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)
        if dialog.exec() == QDialog.Accepted:
            try:
                split = lambda text: [rule.strip() for rule in text.split(",") if rule.strip()]
                self.repo.update_scope(project, split(include.text()), split(exclude.text()))
                if self.worker:
                    self.cancel_scan()
                self.refresh_scans()
                self.status.setText("Scope updated and recorded in history. A running scan was cancelled; start a new scan with this scope." if self.worker else
                                    "Scope updated and recorded in history.")
            except (ValueError, OSError) as exc:
                QMessageBox.warning(self, "Scope update failed", str(exc))

    def finished(self, message):
        self.worker = None
        self.projects.setEnabled(True)
        self.scans.setEnabled(True)
        self.start.setEnabled(True)
        self.target.setEnabled(True)
        self.stop.setEnabled(False)
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        self.status.setText("Scan ended: " + message)
        if any(row["id"] == message for row in self.repo.scans(self.projects.currentData())):
            self.status.setText("Scan " + self.repo.snapshot(message)["scan"]["status"] + " • review coverage and evidence below")
        self.refresh_scans()

    def failed(self, message):
        self.finished(message)
        self.status.setText('Scan failed: ' + message)
        self.set_application_state('Failed')
        self.overview.set_message('Scan failed. Review Evidence & Errors; any displayed observations belong to the selected persisted scan.')

    def cancel_scan(self):
        self.cancel.set()
        if self.worker:
            self.set_application_state("Cancelling")
            self.status.setText("Cancellation requested; waiting for the current bounded operation to stop.")

    def host_intelligence(self):
        if self.worker:
            return
        provider, accepted = QInputDialog.getItem(self, "Host intelligence", "Read existing observations for the entered authorized public IP (may consume account credits):",
                                                 ["shodan", "censys"], 0, False)
        if not accepted:
            return
        try:
            project = self.scan_context()
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Check scan scope", str(exc))
            return
        self.cancel.clear()
        self.worker = ProviderWorker(self.repo, project, self.target.text(), provider, self.cancel)
        self.worker.signals.done.connect(self.finished)
        self.worker.signals.error.connect(self.failed)
        self.projects.setEnabled(False)
        self.scans.setEnabled(False)
        self.start.setEnabled(False)
        self.target.setEnabled(False)
        self.stop.setEnabled(True)
        self.progress.setRange(0, 0)
        self.set_application_state("Provider lookup")
        self.overview.set_message("Reading existing provider observations; no target scan initiated.")
        self.status.setText("Reading existing " + provider + " host observations; no target scan initiated.")
        QThreadPool.globalInstance().start(self.worker)

    def local_task(self, operation, done):
        job = LocalWorker(operation)
        self.local_jobs.append(job)
        job.signals.done.connect(done)
        job.signals.error.connect(self.status.setText)
        # Bound simultaneous local work so repeated clicks cannot exhaust memory.
        job.signals.done.connect(lambda _: self.local_jobs.remove(job))
        job.signals.error.connect(lambda _: self.local_jobs.remove(job))
        QThreadPool.globalInstance().start(job)

    def export(self):
        identifier = self.scans.currentData()
        if identifier and not self.local_jobs:
            destination = QFileDialog.getExistingDirectory(self, "Export directory")
            if destination:
                from .reporting import export_reports
                self.status.setText("Generating reports…")
                self.local_task(lambda: export_reports(self.repo, identifier, destination),
                                lambda path: self.status.setText("Exported to " + path))

    def compare(self):
        index = self.scans.currentIndex()
        if index >= 0 and index + 1 < self.scans.count():
            changes = compare_snapshots(self.repo.snapshot(self.scans.itemData(index + 1)), self.repo.snapshot(self.scans.currentData()), include_persistent=True)
            self.views["comparison"].setPlainText(json.dumps(changes, indent=2))
            self.tabs.setCurrentWidget(self.views["comparison"])
            self.advanced.show()
        else:
            self.status.setText("A previous scan from this project is required.")

    def open_graph(self):
        identifier = self.scans.currentData()
        if identifier and not self.local_jobs:
            from .graph import export_graph
            destination = self.repo.managed_directory("scans", identifier) / "graph.html"
            self.status.setText("Generating graph…")
            self.local_task(lambda: export_graph(self.repo.snapshot(identifier), destination),
                            lambda path: QDesktopServices.openUrl(QUrl.fromLocalFile(path)))

    def closeEvent(self, event):
        self.cancel.set()
        if self.worker is not None or self.local_jobs:
            # Keep signal owners and widgets alive until bounded jobs finish.
            # Event processing continues, so completion callbacks can drain jobs.
            if not self._closing:
                self._closing = True
                self.setEnabled(False)
                self.status.setText("Closing after active local tasks finish; cancellation requested.")
            event.ignore()
            QTimer.singleShot(50, self.close)
            return
        super().closeEvent(event)


def launch(repository):
    app = QApplication.instance() or QApplication([])
    # Window owns the dashboard theme; do not change other application windows.
    window = Window(repository)
    window.show()
    try:
        return app.exec()
    finally:
        # app.quit() can bypass closeEvent while asynchronous diagnostics are alive.
        # Drain completion callbacks before deleting their signal owners.
        window.close()
        deadline = time.monotonic() + 45
        while window.isVisible() or window.worker is not None or window.local_jobs:
            if time.monotonic() >= deadline:
                raise RuntimeError("Application shutdown timed out while local tasks were active.")
            app.processEvents()
            time.sleep(.01)
        if not QThreadPool.globalInstance().waitForDone(5000):
            raise RuntimeError("Application worker shutdown did not complete.")
        window.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        app.processEvents()
