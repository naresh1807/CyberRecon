"""Native dashboard projections, navigation and safe UI/backend integration."""
import json
import time

import httpx
import pytest
from PySide6.QtCore import QRect, Qt, QThreadPool
from PySide6.QtWidgets import QApplication, QFileDialog, QDialog, QMessageBox
from cyberrecon.dashboard import overview_data
from cyberrecon.gui import Window, ObservationTable, _initial_window_geometry
from cyberrecon.storage import Repository
from cyberrecon.scanner import scan


@pytest.fixture
def window(tmp_path, monkeypatch, qt_application_lifetime):
    monkeypatch.setattr('cyberrecon.gui.doctor', lambda _: {'status': 'local fixture'})
    widget = Window(Repository(tmp_path / 'workspace'))
    widget.show(); qt_application_lifetime.processEvents()
    yield widget
    widget.close(); QThreadPool.globalInstance().waitForDone(45000)
    qt_application_lifetime.processEvents()


def fixture_scan(window):
    repo = window.repo
    project = repo.create_project('Owned HTTP fixture', ['127.0.0.1'], authority='Own deterministic local fixture')
    identifier = scan(repo, project, 'http://127.0.0.1/', ports=None, crawl=False,
        transport=httpx.MockTransport(lambda _: httpx.Response(200, headers={
            'content-type': 'text/html', 'server': 'OwnedFixture/1.0'},
            text='<title>Owned fixture</title><script src="/jquery.min.js"></script>')))
    window.refresh_projects(project)
    return repo.snapshot(identifier)


def test_projection_counts_unique_assets_and_preserves_unknowns(window):
    snapshot = fixture_scan(window)
    snapshot['dns'] = [{'host': 'a.example.org', 'type': 'A', 'value': '192.0.2.4'},
                       {'host': 'a.example.org', 'type': 'A', 'value': '192.0.2.4'},
                       {'host': 'a.example.org', 'type': 'A', 'value': 'not-an-address'}]
    snapshot['subdomains'] = [{'host': 'a.example.org', 'verified_current': False}]
    data = overview_data(snapshot)
    assert len(data['domains']) == 1
    assert len(data['ips']) == 2  # One observed DNS address and the literal target.
    assert data['domains'][0]['status'] == 'Resolved'
    assert all(row['location'] == row['asn'] == 'Not collected' for row in data['ips'])
    assert dict(data['information'])['Registrar'] == 'Not collected'
    assert dict(data['information'])['Creation date'] == 'Not collected'
    assert window.cards['findings'].value.text() == str(len(window.repo.snapshot(window.scans.currentData())['findings']))
    assert 'review required' in window.cards['findings'].note.text()
    assert window.cards['ports'].value.text() == '0'
    assert window.cards['technologies'].value.text() == str(len(overview_data(window.repo.snapshot(window.scans.currentData()))['technologies']))


def test_scan_completion_preserves_selected_results_view(window):
    snapshot = fixture_scan(window)
    window.navigate('dns')
    selected_row = window.navigation.currentRow()
    window.finished(snapshot['scan']['id'])
    assert window.navigation.currentRow() == selected_row
    assert window.pages.currentWidget() == window.result_views['dns']


@pytest.mark.parametrize('key', ['overview', 'domains', 'ips', 'nmap', 'technologies',
    'findings', 'dns', 'tls', 'web', 'screenshots', 'export', 'dnsdumpster'])
def test_tabs_and_sidebar_stay_synchronized(window, key):
    tab = window.tab_keys.index(key)
    window.dashboard_tabs.setCurrentIndex(tab)
    assert window.navigation.currentRow() == window.section_keys.index(key)
    assert window.pages.currentWidget() == window.pages.widget(window.section_keys.index(key))
    window.navigate('history')
    assert window.dashboard_tabs.currentIndex() == window.tab_keys.index('history')
    window.navigate(key)
    assert window.dashboard_tabs.currentIndex() == tab


def test_gui_default_profile_enables_ct_and_explains_scope(window, monkeypatch):
    monkeypatch.delenv("DNSDUMPSTER_API_KEY", raising=False)
    assert window.passive.currentText() == "ct"
    assert "public certificate-transparency" in window.passive.toolTip()
    assert "wildcard scope only when authorized" in window.passive.toolTip()
    assert "wildcard only if authorized" in window.includes.placeholderText()
    assert "public CT lookup" in window.description.text()
    assert "dnsdumpster" in window.passive.toolTip().lower()
    assert "ct,dnsdumpster" in [window.passive.itemText(i) for i in range(window.passive.count())]


def test_unverified_security_items_are_not_labeled_as_confirmed_vulnerabilities(window):
    findings_index = window.section_keys.index("findings")
    tab_index = window.tab_keys.index("findings")
    navigation_item = window.navigation.item(findings_index)
    if window.width() < 900:
        assert navigation_item.text() == ""
        assert navigation_item.toolTip() == "Potential Findings"
    else:
        assert navigation_item.text() == "Potential Findings"
    assert window.dashboard_tabs.tabText(tab_index) == "Potential Findings"
    assert window.cards["findings"].title.text() == "Potential Findings"


def test_dnsdumpster_dashboard_view_renders_and_filters_provider_observations(window):
    view = window.result_views["dnsdumpster"]
    view.set_records([
        {"host": "www.example.org", "record_type": "A", "value": "198.51.100.20",
         "asn": "64500", "source": "DNSDumpster API", "verified_current": False},
        {"host": "example.org", "record_type": "NS", "value": "ns1.example.net",
         "source": "DNSDumpster API", "verified_current": False},
    ])
    window.navigate("dnsdumpster")
    assert window.pages.currentWidget() is view
    assert view.table.rowCount() == 2
    assert "Record Type" in [view.table.horizontalHeaderItem(i).text() for i in range(view.table.columnCount())]
    view.filter.setText("64500")
    assert view.table.rowCount() == 1
    view.filter.clear()
    assert view.table.rowCount() == 2


def test_domain_cells_open_in_browser_and_can_be_copied(window, monkeypatch):
    table = window.result_views['domains']
    table.set_records([{'subdomain': 'www.example.org'}], ['subdomain'])
    item = table.table.item(0, 0)
    assert item.data(Qt.UserRole + 1) == 'https://www.example.org/'
    assert 'Right-click or Ctrl+C to copy' in item.toolTip()
    assert item.font().underline()

    opened = []
    monkeypatch.setattr('cyberrecon.gui_components.QDesktopServices.openUrl',
                        lambda url: opened.append(url.toString()) or True)
    table.table.cellClicked.emit(0, 0)
    assert opened == ['https://www.example.org/']
    table.table.setCurrentItem(item)
    table.link_actions.copy_current_cell()
    assert QApplication.clipboard().text() == 'www.example.org'


def test_overview_target_domain_is_clickable(window, monkeypatch):
    fixture_scan(window)
    item = window.overview.information.item(0, 1)
    assert item.data(Qt.UserRole + 1) == 'https://127.0.0.1/'
    opened = []
    monkeypatch.setattr('cyberrecon.gui_components.QDesktopServices.openUrl',
                        lambda url: opened.append(url.toString()) or True)
    window.overview.information.cellClicked.emit(0, 1)
    assert opened == ['https://127.0.0.1/']


def test_url_links_redact_query_values_and_reject_unsafe_schemes(window, monkeypatch):
    table = window.result_views['urls']
    table.set_records([{'url': 'https://example.org/path?token=private'}], ['url'])
    item = table.table.item(0, 0)
    assert item.data(Qt.UserRole + 1) == 'https://example.org/path?token='

    opened = []
    monkeypatch.setattr('cyberrecon.gui_components.QDesktopServices.openUrl',
                        lambda url: opened.append(url.toString()) or True)
    table.table.cellClicked.emit(0, 0)
    assert opened == ['https://example.org/path?token=']

    table.set_records([{'url': 'javascript:alert(1)'}], ['url'])
    unsafe = table.table.item(0, 0)
    assert unsafe.data(Qt.UserRole + 1) is None
    table.table.cellClicked.emit(0, 0)
    assert opened == ['https://example.org/path?token=']


def test_initial_window_geometry_fits_standard_laptop_screen():
    # A 1536x1024 preference used to exceed this common 1366x768 display.
    assert _initial_window_geometry(QRect(100, 40, 1366, 768), (1536, 1024)) == (132, 72, 1302, 704)


def test_main_and_settings_windows_fit_usable_screen(window):
    available = QApplication.primaryScreen().availableGeometry()
    maximum_width = max(1, available.width() - 64)
    maximum_height = max(1, available.height() - 64)
    assert 1 <= window.width() <= maximum_width
    assert 1 <= window.height() <= maximum_height
    window.advanced.show()
    QApplication.processEvents()
    assert 1 <= window.advanced.width() <= maximum_width
    assert 1 <= window.advanced.height() <= maximum_height
    window.advanced.hide()


def test_empty_and_narrow_layout(window):
    assert window.cards['target'].value.text() == 'No target'
    assert all(not button.isEnabled() for button in window.overview.export_buttons)
    window.resize(600, 900); QApplication.processEvents()
    assert window.width() == 600
    assert window.sidebar.width() == 54
    assert window.target.isVisible() and window.start.isVisible()
    assert window.start.geometry().right() <= window.target_row.width()
    assert window.target.geometry().width() > 150
    assert window.cards_layout.columnCount() >= 2
    window.resize(1536, 1024); QApplication.processEvents()
    assert window.sidebar.width() == 190
    assert window.cards_layout.itemAtPosition(0, 5).widget() == window.cards['technologies']


def test_table_filter_sort_pagination_and_original_details(monkeypatch):
    table = ObservationTable(page_size=8)
    records = [{'port': n, 'state': 'open', '_record': {'evidence': n}} for n in range(21)]
    table.set_records(records, ['port', 'state'])
    assert table.table.rowCount() == 8 and table.next.isEnabled()
    table.next.click()
    assert table.rows[0]['port'] == 8
    table.filter.setText('20')
    assert table.table.rowCount() == 1 and table.rows[0]['port'] == 20
    table.filter.clear()
    table.table.horizontalHeader().setSortIndicator(0, Qt.DescendingOrder)
    assert table.rows[0]['port'] == 20
    table.next.click(); assert table.rows[0]['port'] == 12
    details = []
    monkeypatch.setattr(QDialog, 'exec', lambda dialog: details.append(dialog.findChildren(__import__('PySide6.QtWidgets', fromlist=['QTextEdit']).QTextEdit)[0].toPlainText()))
    table.details(0, 0)
    assert json.loads(details[0]) == {'evidence': 12}
    table.close()


@pytest.mark.parametrize('format_name,filename', [('JSON', 'scan.json'), ('HTML', 'report.html'), ('PDF', 'report.pdf')])
def test_quick_exports_use_real_report_generation(window, tmp_path, monkeypatch, format_name, filename):
    snapshot = fixture_scan(window)
    output = tmp_path / format_name
    monkeypatch.setattr(QFileDialog, 'getExistingDirectory', lambda *args: str(output))
    window.overview.export_buttons[['JSON', 'HTML', 'PDF'].index(format_name)].click()
    deadline = time.monotonic() + 20
    while window.local_jobs and time.monotonic() < deadline:
        QApplication.processEvents(); time.sleep(.01)
    assert not window.local_jobs and (output / filename).is_file()
    assert filename in window.status.text()
    assert json.loads((output / 'scan.json').read_text())['id'] == snapshot['scan']['id']
    assert json.loads(window.report_preview.toPlainText())['scan']['id'] == snapshot['scan']['id']


def test_invalid_target_cannot_start_worker(window, monkeypatch):
    warnings = []
    monkeypatch.setattr(QMessageBox, 'warning', lambda *args: warnings.append(args[-1]))
    window.target.setText('https://example.org;bad')
    window.start_scan()
    assert warnings and window.worker is None and not window.repo.projects()


def test_failed_worker_restores_controls_and_visible_error(window):
    window.start.setEnabled(False)
    window.failed('Owned fixture failure')
    assert window.start.isEnabled() and window.worker is None
    assert 'failed' in window.status.text().lower()
    assert not window.overview.notice.isHidden()
    if window.width() < 900:
        assert window.application_state.text() == '●'
        assert window.application_state.toolTip() == 'Failed'
    else:
        assert 'Failed' in window.application_state.text()


def test_loading_and_completed_backend_scan(window, monkeypatch):
    def local_scan(*args, **kwargs):
        return scan(*args, **kwargs, transport=httpx.MockTransport(lambda _: httpx.Response(
            200, headers={'content-type': 'text/html'}, text='<title>Owned worker fixture</title>')))
    monkeypatch.setattr('cyberrecon.gui.scan', local_scan)
    window.target.setText('http://127.0.0.1/')
    window.includes.setText('127.0.0.1')
    window.authority.setText('Own deterministic worker fixture')
    window.enable_ports.setChecked(False)
    window.crawl.setChecked(False)
    window.passive.setCurrentIndex(0)  # Keep this worker test entirely offline.
    window.start_scan()
    assert window.worker is not None and not window.start.isEnabled()
    assert not window.overview.skeleton.isHidden()
    assert window.cards['findings'].value.text() == '…'
    deadline = time.monotonic() + 20
    while window.worker and time.monotonic() < deadline:
        QApplication.processEvents(); time.sleep(.01)
    assert window.worker is None and window.start.isEnabled()
    assert window.overview.skeleton.isHidden()
    snapshot = window.repo.snapshot(window.scans.currentData())
    assert snapshot['http'] and snapshot['scan']['status'] == 'complete'
    assert window.cards['target'].value.text() == '127.0.0.1'
    assert window.cards['findings'].value.text() == str(len(snapshot['findings']))


def test_native_nmap_service_join_counts_once(window):
    snapshot = fixture_scan(window)
    snapshot['ports'] = [{'host': '127.0.0.1', 'port': 8080, 'protocol': 'tcp', 'state': 'open'}]
    snapshot['services'] = [{'ip': '127.0.0.1', 'port': 8080, 'protocol': 'tcp', 'state': 'open',
                             'service': 'http', 'product': 'Owned fixture', 'version': '1.0'}]
    data = overview_data(snapshot)
    assert len(data['ports']) == 1
    assert data['ports'][0]['service'] == 'http'
    assert data['ports'][0]['version'] == 'Owned fixture 1.0'


def test_worker_failure_signal_is_not_reported_as_completion(window, monkeypatch):
    def failed_scan(*args, **kwargs):
        raise OSError('Owned worker failure')
    monkeypatch.setattr('cyberrecon.gui.scan', failed_scan)
    window.target.setText('http://127.0.0.1/')
    window.includes.setText('127.0.0.1')
    window.authority.setText('Own deterministic failure fixture')
    window.enable_ports.setChecked(False)
    window.start_scan()
    deadline = time.monotonic() + 10
    while window.worker and time.monotonic() < deadline:
        QApplication.processEvents(); time.sleep(.01)
    assert window.worker is None and window.start.isEnabled()
    assert window.current_state == 'Failed'
    assert 'Owned worker failure' in window.status.text()
    assert window.cards['target'].value.text() == 'No target'
    assert window.repo.scans(window.projects.currentData()) == []


def test_detail_views_use_dns_mapping_and_keep_original_evidence(window):
    snapshot = fixture_scan(window)
    original = {'host': 'a.example.org', 'source': 'owned fixture'}
    snapshot['subdomains'] = [original]
    snapshot['dns'] = [{'host': 'a.example.org', 'type': 'A', 'value': '192.0.2.4'},
                       {'host': 'a.example.org', 'type': 'AAAA', 'value': '2001:db8::4'}]
    window.display_snapshot(snapshot)
    row = window.result_views['domains'].rows[0]
    assert row['ip_address'] == '192.0.2.4, 2001:db8::4'
    assert row['status'] == 'Resolved' and row['_record']['discovery'] == original
    assert window.result_views['ips'].columns == ['address', 'hostnames', 'location', 'asn']


@pytest.mark.parametrize('status', ['cancelled', 'partial', 'failed'])
def test_incomplete_scan_without_warnings_has_actionable_message(window, status):
    snapshot = fixture_scan(window)
    snapshot['scan']['status'] = status
    snapshot['scan']['warnings'] = []
    window.display_snapshot(snapshot)
    assert status in window.overview.notice.text()
    assert 'Progress & Coverage' in window.overview.notice.text()
