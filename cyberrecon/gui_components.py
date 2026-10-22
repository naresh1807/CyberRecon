"""Native Qt dashboard widgets; no scanning or external requests here."""
import json
import math
import time

from PySide6.QtCore import QObject, Qt, QSize, QRectF, QUrl
from PySide6.QtGui import (QColor, QIcon, QPainter, QPen, QPixmap, QPainterPath, QPalette,
    QDesktopServices, QKeySequence, QShortcut)
from PySide6.QtWidgets import (QWidget, QLabel, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, QAbstractItemView,
    QDialog, QTextEdit, QScrollArea, QHeaderView, QSizePolicy, QComboBox, QApplication, QMenu)

ACCENTS = {'success': '#27d697', 'danger': '#ff596d', 'warning': '#edb850', 'blue': '#399bff', 'cyan': '#29c9ee'}


LINK_ROLE = Qt.UserRole + 1


def browser_target(value):
    """Convert a displayed domain or HTTP(S) URL to a safe browser target."""
    from .network import clean_url
    from .scope import host_of

    text = str(value).strip()
    if not text or len(text) > 4096:
        return None
    try:
        if "://" in text:
            return clean_url(text)
        host = host_of(text)
        authority = f"[{host}]" if ":" in host else host
        return clean_url("https://" + authority + "/")
    except (TypeError, ValueError):
        return None


def decorate_link_item(item, value):
    target = browser_target(value)
    if not target:
        return None
    item.setData(LINK_ROLE, target)
    item.setForeground(QColor('#59baff'))
    font = item.font()
    font.setUnderline(True)
    item.setFont(font)
    item.setToolTip(item.toolTip() + "\n\nClick to open in your browser. Right-click or Ctrl+C to copy.")
    return target


class TableLinkActions(QObject):
    """Add safe open/copy actions to table cells containing a URL or domain."""
    def __init__(self, table):
        super().__init__(table)
        self.table = table
        self._last_target = None
        self._last_opened_at = 0.0
        table.setMouseTracking(True)
        table.viewport().setMouseTracking(True)
        table.cellEntered.connect(self.hover_cell)
        table.cellClicked.connect(self.open_cell)
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.customContextMenuRequested.connect(self.show_context_menu)
        self.copy_shortcut = QShortcut(QKeySequence("Ctrl+C"), table)
        self.copy_shortcut.setContext(Qt.WidgetWithChildrenShortcut)
        self.copy_shortcut.activated.connect(self.copy_current_cell)

    def hover_cell(self, row, column):
        item = self.table.item(row, column)
        cursor = Qt.PointingHandCursor if item and item.data(LINK_ROLE) else Qt.ArrowCursor
        self.table.viewport().setCursor(cursor)

    def open_target(self, target):
        if target:
            return QDesktopServices.openUrl(QUrl(target))
        return False

    def open_cell(self, row, column):
        item = self.table.item(row, column)
        target = item.data(LINK_ROLE) if item else None
        if not target:
            return
        # A normal double-click emits two cellClicked signals; avoid opening two tabs.
        now = time.monotonic()
        if target == self._last_target and now - self._last_opened_at < 0.5:
            return
        self._last_target, self._last_opened_at = target, now
        self.open_target(target)

    def copy_item(self, item):
        if item is not None:
            QApplication.clipboard().setText(item.text())

    def copy_current_cell(self):
        self.copy_item(self.table.currentItem())

    def show_context_menu(self, position):
        item = self.table.itemAt(position)
        if item is None:
            return
        self.table.setCurrentItem(item)
        menu = QMenu(self.table)
        copy_action = menu.addAction("Copy value")
        target = item.data(LINK_ROLE)
        open_action = menu.addAction("Open in browser")
        open_action.setEnabled(bool(target))
        copy_action.triggered.connect(lambda: self.copy_item(item))
        open_action.triggered.connect(lambda: self.open_target(target))
        menu.exec(self.table.mapToGlobal(position))


def icon(name, color='#65b6ff', size=24):
    """Small consistent line icons drawn locally, with no new asset dependency."""
    pix = QPixmap(size, size)
    pix.fill(Qt.transparent)
    painter = QPainter(pix)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.scale(size / 24, size / 24)
    painter.setPen(QPen(QColor(color), 1.7, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    if name in ('overview', 'target', 'domains', 'dns'):
        painter.drawEllipse(QRectF(3, 3, 18, 18))
        painter.drawEllipse(QRectF(8, 3, 8, 18))
        painter.drawLine(3, 12, 21, 12)
        painter.drawLine(5, 7, 19, 7)
        painter.drawLine(5, 17, 19, 17)
    elif name in ('findings', 'tls', 'scope'):
        path = QPainterPath(); path.moveTo(12, 2); path.lineTo(20, 6); path.lineTo(19, 15)
        path.quadTo(17, 20, 12, 22); path.quadTo(7, 20, 5, 15); path.lineTo(4, 6); path.closeSubpath()
        painter.drawPath(path); painter.drawLine(12, 7, 12, 13); painter.drawPoint(12, 17)
    elif name in ('ips', 'nmap', 'ports', 'technologies'):
        for x, y in ((4, 4), (15, 4), (9, 15)):
            painter.drawRoundedRect(QRectF(x, y, 6, 5), 1, 1)
        painter.drawLine(7, 9, 12, 15); painter.drawLine(18, 9, 12, 15)
    elif name == 'play':
        path = QPainterPath(); path.moveTo(7, 4); path.lineTo(20, 12); path.lineTo(7, 20); path.closeSubpath()
        painter.fillPath(path, QColor(color))
    elif name == 'link':
        painter.drawRoundedRect(QRectF(3, 9, 12, 7), 3, 3)
        painter.drawRoundedRect(QRectF(10, 4, 11, 7), 3, 3)
        painter.drawLine(8, 14, 16, 8)
    elif name == 'search':
        painter.drawEllipse(QRectF(3, 3, 13, 13)); painter.drawLine(15, 15, 21, 21)
    elif name == 'screenshots':
        painter.drawRoundedRect(QRectF(3, 4, 18, 16), 2, 2)
        painter.drawEllipse(QRectF(6, 7, 3, 3)); painter.drawLine(4, 18, 10, 12)
        painter.drawLine(10, 12, 15, 17); painter.drawLine(15, 17, 19, 11)
    else:
        painter.drawRoundedRect(QRectF(5, 3, 14, 18), 2, 2)
        for y in (8, 12, 16): painter.drawLine(8, y, 16, y)
    painter.end()
    return QIcon(pix)


def label(text='', name=None):
    widget = QLabel(text)
    widget.setTextFormat(Qt.PlainText)
    if name: widget.setObjectName(name)
    return widget


class ElidedLabel(QLabel):
    """Single-line target value with full accessible text and tooltip."""
    def __init__(self, text):
        super().__init__(text)
        self.setTextFormat(Qt.PlainText)
        self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)

    def paintEvent(self, event):
        painter = QPainter(self); painter.setFont(self.font())
        painter.setPen(self.palette().color(QPalette.WindowText))
        painter.drawText(self.contentsRect(), self.alignment(),
                         self.fontMetrics().elidedText(self.text(), Qt.ElideRight, self.contentsRect().width()))
        painter.end()


class ObservationTable(QWidget):
    """Bounded pages, global filtering/sorting, original-record detail dialogs."""
    def __init__(self, page_size=50, compact=False):
        super().__init__()
        self.page_size, self.page, self.records, self.rows = page_size, 0, [], []
        self.columns = None
        self.filters = {}
        self._search_text = {}
        self.compact = compact
        self._rendering = False
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(5)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText('Search all observations…')
        self.filter.textChanged.connect(self.apply_filter)
        self.layout.addWidget(self.filter)
        if compact: self.filter.hide()
        self.table = QTableWidget()
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(27)
        self.table.horizontalHeader().setMinimumSectionSize(65)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSortIndicator(-1, Qt.AscendingOrder)
        self.table.horizontalHeader().setSectionsClickable(True)
        self.table.horizontalHeader().setSortIndicatorShown(True)
        self.table.horizontalHeader().sectionClicked.connect(self.header_clicked)
        self.table.horizontalHeader().sortIndicatorChanged.connect(self.sort_records)
        self.table.cellDoubleClicked.connect(self.details)
        self.link_actions = TableLinkActions(self.table)
        self.layout.addWidget(self.table, 1)
        footer = QHBoxLayout()
        self.summary = label('', 'tableSummary')
        footer.addWidget(self.summary, 1)
        self.previous, self.next = QPushButton('‹'), QPushButton('›')
        for button in (self.previous, self.next):
            button.setObjectName('pageButton'); button.setFixedSize(25, 23)
            footer.addWidget(button)
        self.previous.clicked.connect(lambda: self.change_page(-1))
        self.next.clicked.connect(lambda: self.change_page(1))
        self.layout.addLayout(footer)
        self.clear()

    def set_records(self, records, columns=None):
        self.columns = columns
        self.records = list(records)
        self._search_text = {id(r): json.dumps(r, ensure_ascii=False).casefold() for r in self.records}
        self.page = 0
        header = self.table.horizontalHeader()
        if header.sortIndicatorSection() >= 0:
            self.sort_records(header.sortIndicatorSection(), header.sortIndicatorOrder())
        else:
            self.render()

    def setPlainText(self, text):
        self.set_records(json.loads(text))

    def clear(self):
        self.set_records([])

    def filtered_records(self):
        query = self.filter.text().casefold()
        return [r for r in self.records if (not query or query in self._search_text.get(id(r), ""))
                and all(not value or (value in r.get("confidence_levels", [str(r.get("confidence", "Unknown"))]) if key == "confidence" else value in r.get(key, []) if isinstance(r.get(key), list) else str(r.get(key, "")) == value)
                        for key, value in self.filters.items())]

    def apply_filter(self):
        self.page = 0
        self.render()

    def change_page(self, delta):
        count = len(self.filtered_records())
        self.page = max(0, min(self.page + delta, max(0, math.ceil(count / self.page_size) - 1)))
        self.render()

    def header_clicked(self, column):
        header = self.table.horizontalHeader()
        order = (Qt.DescendingOrder if header.sortIndicatorSection() == column and
                 header.sortIndicatorOrder() == Qt.AscendingOrder else Qt.AscendingOrder)
        header.setSortIndicator(column, order)

    def sort_records(self, column, order):
        if self._rendering or column < 0: return
        columns = self.columns or list(dict.fromkeys(k for r in self.records for k in r if not k.startswith('_')))
        if column >= len(columns): return
        key = columns[column]
        def value(row):
            item = row.get(key, '')
            return (0, item) if isinstance(item, (int, float)) else (1, str(item).casefold())
        self.records.sort(key=value, reverse=order == Qt.DescendingOrder)
        self.page = 0
        self.render()

    def render(self):
        self._rendering = True
        filtered = self.filtered_records()
        offset = self.page * self.page_size
        self.rows = filtered[offset:offset + self.page_size]
        columns = self.columns or list(dict.fromkeys(k for r in self.records for k in r if not k.startswith('_')))
        self.table.setSortingEnabled(False)
        self.table.clear()
        self.table.setColumnCount(len(columns))
        self.table.setRowCount(len(self.rows))
        self.table.setHorizontalHeaderLabels([key.replace('_', ' ').title() for key in columns])
        for i, record in enumerate(self.rows):
            for j, key in enumerate(columns):
                value = record.get(key, '')
                text = json.dumps(value, ensure_ascii=False) if isinstance(value, (list, dict)) else str(value)
                item = QTableWidgetItem(text[:500])
                item.setData(Qt.UserRole, record.get('_record', record))
                item.setToolTip(text[:10000])
                decorate_link_item(item, text)
                if key in ('state', 'status', 'severity'):
                    severity = text.casefold()
                    color = (ACCENTS['success'] if severity in ('open', 'active observed', 'present', 'low') else
                             ACCENTS['danger'] if severity in ('critical', 'high', 'failed', 'error') else
                             ACCENTS['warning'] if severity in ('review', 'medium', 'resolved', 'partial', 'cancelled', 'unverified') else '#89bcea')
                    item.setForeground(QColor(color))
                    item.setBackground(QColor('#082337'))
                self.table.setItem(i, j, item)
        self.table.resizeColumnsToContents()
        for column in range(len(columns)):
            self.table.setColumnWidth(column, min(300, max(65, self.table.columnWidth(column))))
        self.summary.setText(f'Showing {offset + 1}–{offset + len(self.rows)} of {len(filtered)}' if filtered else
                             ('No matching observations' if self.records else 'No observations collected'))
        self.previous.setEnabled(self.page > 0)
        self.next.setEnabled(offset + self.page_size < len(filtered))
        self._rendering = False
        self.fit_columns()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.fit_columns()

    def fit_columns(self):
        if not self.compact or not hasattr(self, 'table'): return
        count = self.table.columnCount()
        weights = ([1, 1, 1.2, 2.1, 1] if self.columns and 'port' in self.columns else
                   [.9, 2, 2.1] if self.columns and 'severity' in self.columns else
                   [2, 1.6, 1.2] if self.columns and 'subdomain' in self.columns else
                   [1.4, 1.6, 1.2, 1] if count == 4 else [1] * count)
        width = self.table.viewport().width()
        for column, weight in enumerate(weights[:count]):
            self.table.setColumnWidth(column, max(65, int(width * weight / sum(weights))))

    def details(self, row, column):
        item = self.table.item(row, column)
        if item is None or item.data(LINK_ROLE): return
        dialog = QDialog(self)
        dialog.setWindowTitle('Observation details — source and evidence')
        dialog.resize(760, 470)
        layout = QVBoxLayout(dialog)
        view = QTextEdit(); view.setReadOnly(True)
        view.setPlainText(json.dumps(item.data(Qt.UserRole), indent=2, ensure_ascii=False))
        layout.addWidget(view)
        dialog.exec()


class ResultsTable(ObservationTable):
    """Global persisted observations with conjunctive metadata filters."""
    FILTERS = ("kind", "category", "severity", "confidence", "sources", "verification_status", "scan_id")
    COLUMNS = ["kind", "hostname", "ip_address", "port", "protocol", "title", "severity", "confidence", "verification_status", "sources"]

    def __init__(self, repository):
        self.repository = repository
        self.selectors = {}
        self.grouping = None
        super().__init__(page_size=50)
        row = QGridLayout()
        for index, key in enumerate(self.FILTERS):
            combo = QComboBox(); combo.setToolTip("Filter " + key.replace("_", " "))
            combo.addItem("All " + key.replace("_", " "), "")
            combo.currentIndexChanged.connect(lambda _, k=key: self.update_selector(k))
            self.selectors[key] = combo; row.addWidget(combo, index // 4, index % 4)
        self.layout.insertLayout(1, row)
        self.grouping = QComboBox()
        self.grouping.addItem("Ungrouped observations", "")
        for title, field in (("Domain", "hostname"), ("IP address", "ip_address"), ("Port", "port"),
                             ("Service", "service"), ("Technology", "technology"), ("Category (TLS / OS / CDN / security)", "category")):
            self.grouping.addItem("Group by " + title, field)
        self.grouping.setToolTip("Observed correlations only; grouping does not establish ownership or authorization.")
        self.grouping.currentIndexChanged.connect(self.apply_filter)
        self.layout.insertWidget(2, self.grouping)
        self.filter.setPlaceholderText("Search all hosts, IPs, ports, URLs, APIs, technologies and evidence…")
        self.columns = self.COLUMNS

    def filtered_records(self):
        records = super().filtered_records()
        field = self.grouping.currentData() if self.grouping is not None else ""
        if field:
            # Group all matching records before pagination; never synthesize findings.
            records.sort(key=lambda record: str(record.get(field, "Unknown")).casefold())
        return records

    def render(self):
        super().render()
        field = self.grouping.currentData() if self.grouping is not None else ""
        if field:
            count = len({str(record.get(field, "Unknown")) for record in self.filtered_records()})
            self.summary.setText(self.summary.text() + f" · {count} observed groups")

    def update_selector(self, key):
        self.filters[key] = self.selectors[key].currentData() or ""
        self.apply_filter()

    def set_records(self, records, columns=None):
        super().set_records(records, columns or self.COLUMNS)
        for key, combo in self.selectors.items():
            selected = combo.currentData()
            values = set()
            for record in self.records:
                value = record.get("confidence_levels", [record.get("confidence", "Unknown")]) if key == "confidence" else record.get(key, "Unknown")
                values.update(str(v) for v in value) if isinstance(value, list) else values.add(str(value))
            combo.blockSignals(True); combo.clear(); combo.addItem("All " + key.replace("_", " "), "")
            for value in sorted(values): combo.addItem(value, value)
            combo.setCurrentIndex(max(0, combo.findData(selected)))
            combo.blockSignals(False)
            self.filters[key] = combo.currentData() or ""
        self.apply_filter()

    def details(self, row, column):
        item = self.table.item(row, column)
        if item is None or item.data(LINK_ROLE): return
        record = item.data(Qt.UserRole)
        dialog = QDialog(self); dialog.setWindowTitle("Result details and original evidence")
        dialog.resize(800, 520); layout = QVBoxLayout(dialog)
        view = QTextEdit(); view.setReadOnly(True)
        view.setPlainText(json.dumps(record, indent=2, ensure_ascii=False)); layout.addWidget(view)
        descriptor = record.get("evidence")
        if isinstance(descriptor, dict) and descriptor.get("path"):
            button = QPushButton("View original tool output (checksum verified)")
            def read():
                try:
                    payload = self.repository.read_evidence(record["scan_id"], descriptor)
                    # A bounded preview is explicitly labelled; file remains intact.
                    view.setPlainText(payload[:65536].decode(errors="replace") +
                        ("\n[Preview limited to 65536 bytes; original evidence preserved.]" if len(payload) > 65536 else ""))
                except (OSError, ValueError) as exc:
                    view.setPlainText("Evidence unavailable or invalid: " + type(exc).__name__)
            button.clicked.connect(read); layout.addWidget(button)
        dialog.exec()


class LoadingSkeleton(QWidget):
    """Static loading placeholders, never observations or animated results."""
    def __init__(self):
        super().__init__(); self.setFixedHeight(42)

    def paintEvent(self, event):
        painter = QPainter(self); painter.setPen(Qt.NoPen); painter.setBrush(QColor('#0a3551'))
        width = max(20, (self.width() - 24) / 3)
        for column in range(3):
            for row in range(2):
                painter.drawRoundedRect(QRectF(column * (width + 12), row * 19, width * (.9 if row == 0 else .65), 9), 3, 3)
        painter.end()


class SummaryCard(QWidget):
    def __init__(self, title, glyph, accent):
        super().__init__()
        self.setObjectName('summaryCard')
        self.setAttribute(Qt.WA_StyledBackground, True)
        layout = QHBoxLayout(self); layout.setContentsMargins(12, 12, 12, 12)
        symbol = label(); symbol.setPixmap(icon(glyph, accent, 32).pixmap(32, 32))
        symbol.setObjectName('cardIcon'); symbol.setFixedSize(44, 44)
        symbol.setAlignment(Qt.AlignCenter)
        symbol.setStyleSheet('background: ' + QColor(accent).darker(450).name() + '; border: 1px solid ' + QColor(accent).darker(220).name() + '; border-radius: 22px;')
        layout.addWidget(symbol)
        text = QVBoxLayout()
        self.title = label(title, 'muted')
        text.addWidget(self.title)
        self.value = ElidedLabel('—') if glyph == 'target' else label('—')
        self.value.setObjectName('targetCardValue' if glyph == 'target' else 'cardValue')
        self.note = label('No scan selected', 'cardNote'); self.note.setWordWrap(True)
        text.addWidget(self.value); text.addWidget(self.note)
        layout.addLayout(text, 1)
        self.setMinimumHeight(100)

    def set_value(self, value, note, color=None):
        self.value.setText(str(value)); self.value.setToolTip(str(value)); self.note.setText(note)
        self.value.setStyleSheet('color: ' + (color or '#e3f1ff') + ';')


class Panel(QWidget):
    def __init__(self, title, glyph):
        super().__init__(); self.setObjectName('dashboardPanel')
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.layout = QVBoxLayout(self); self.layout.setContentsMargins(10, 10, 10, 10)
        self.layout.setSpacing(7)
        row = QHBoxLayout(); image = label(); image.setPixmap(icon(glyph, '#2bafff', 19).pixmap(19, 19))
        row.addWidget(image); row.addWidget(label(title, 'panelTitle'), 1); self.layout.addLayout(row)
        self.heading = row

    def add_table(self, columns):
        self.table = ObservationTable(page_size=8, compact=True)
        self.table.columns = columns
        button = QPushButton(); button.setIcon(icon('search')); button.setObjectName('pageButton'); button.setFixedSize(24, 24)
        button.setToolTip('Search this panel'); button.clicked.connect(lambda: self.table.filter.setVisible(self.table.filter.isHidden()))
        self.heading.addWidget(button)
        self.layout.addWidget(self.table, 1)
        self.setMinimumHeight(285)
        return self.table


class OverviewDashboard(QScrollArea):
    def __init__(self, export_action, navigate):
        super().__init__(); self.setWidgetResizable(True); self.setFrameShape(QScrollArea.NoFrame)
        self.content = QWidget(); self.content.setObjectName('overviewContent')
        self.grid = QGridLayout(self.content); self.grid.setContentsMargins(0, 0, 0, 0); self.grid.setSpacing(12)
        self.setWidget(self.content)
        self.panels, self.tables = [], {}
        info = Panel('Target Information', 'target')
        self.information = QTableWidget(7, 2)
        self.information.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.information.horizontalHeader().hide(); self.information.verticalHeader().hide()
        self.information.setShowGrid(False); self.information.setAlternatingRowColors(True)
        self.information_links = TableLinkActions(self.information)
        self.information.verticalHeader().setDefaultSectionSize(30)
        self.information.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.information.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        info.layout.addWidget(self.information); info.setMinimumHeight(285); self.panels.append(info)
        for key, title, glyph, columns in (
            ('domains', 'Subdomains', 'domains', ['subdomain', 'ip_address', 'status']),
            ('ips', 'IP Addresses', 'ips', ['address', 'hostnames', 'location', 'asn']),
            ('ports', 'Nmap Scan Results', 'nmap', ['port', 'protocol', 'service', 'version', 'state']),
            ('technologies', 'Technologies Detected', 'technologies', ['technology', 'version'])):
            panel = Panel(title, glyph); self.tables[key] = panel.add_table(columns); self.panels.append(panel)
        right = QWidget(); stack = QVBoxLayout(right); stack.setContentsMargins(0, 0, 0, 0); stack.setSpacing(10)
        findings = Panel('Recent Findings', 'findings')
        self.tables['findings'] = findings.add_table(['severity', 'title', 'location'])
        findings.setMinimumHeight(210); stack.addWidget(findings, 1)
        actions = Panel('Quick Actions', 'export'); buttons = QGridLayout(); self.export_buttons = []
        for i, name in enumerate(('JSON', 'HTML', 'PDF')):
            button = QPushButton('Export ' + name); button.setIcon(icon('export', '#bfe9ff', 16))
            button.setObjectName('quickExport'); button.clicked.connect(lambda checked=False, fmt=name: export_action(fmt))
            buttons.addWidget(button, 0, i); self.export_buttons.append(button)
        full = QPushButton('View Full Report'); full.clicked.connect(lambda: navigate('export'))
        buttons.addWidget(full, 1, 0, 1, 3); actions.layout.addLayout(buttons)
        stack.addWidget(actions); self.panels.append(right)
        self.notice = label('', 'muted'); self.notice.setWordWrap(True)
        self.notice.hide()
        self.skeleton = LoadingSkeleton(); self.skeleton.setParent(self.content); self.skeleton.hide()
        self.grid.addWidget(self.notice, 0, 0, 1, 3)
        self.reflow()

    def set_message(self, text, loading=False):
        self.notice.setText(text); self.notice.setVisible(bool(text))
        self.skeleton.setVisible(loading); self.reflow()

    def resizeEvent(self, event):
        super().resizeEvent(event); self.reflow()

    def reflow(self):
        columns = 3 if self.viewport().width() >= 1100 else 2 if self.viewport().width() >= 760 else 1
        for panel in self.panels: self.grid.removeWidget(panel)
        self.grid.removeWidget(self.notice)
        offset = 1 if not self.notice.isHidden() else 0
        if offset: self.grid.addWidget(self.notice, 0, 0, 1, columns)
        self.grid.removeWidget(self.skeleton)
        if not self.skeleton.isHidden():
            self.grid.addWidget(self.skeleton, offset, 0, 1, columns); offset += 1
        for i, panel in enumerate(self.panels): self.grid.addWidget(panel, i // columns + offset, i % columns)
        for i in range(3): self.grid.setColumnStretch(i, 1 if i < columns else 0)

    def set_snapshot(self, snapshot):
        from .dashboard import overview_data
        data = overview_data(snapshot)
        for key, table in self.tables.items(): table.set_records(data[key], table.columns)
        for i, (key, value) in enumerate(data['information']):
            for column, text in enumerate((key, value)):
                item = QTableWidgetItem(str(text)); item.setToolTip(str(text))
                decorate_link_item(item, text)
                self.information.setItem(i, column, item)
        for button in self.export_buttons: button.setEnabled(snapshot is not None)
