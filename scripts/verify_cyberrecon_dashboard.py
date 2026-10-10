#!/usr/bin/env python3
"""Verify the actual native dashboard against a script-owned loopback HTTP lab.

All active requests/Nmap target the owned listener only. Temporary workspace,
application-only captures; no system package changes or release qualification.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--desktop', action='store_true')
    args = parser.parse_args()
    if args.desktop:
        if os.geteuid() == 0 or not os.environ.get('DISPLAY'):
            parser.error('A non-root live X11 desktop is required')
        os.environ.pop('QT_QPA_PLATFORM', None)
    else:
        os.environ['QT_QPA_PLATFORM'] = 'offscreen'
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from PySide6.QtCore import QThreadPool, QCoreApplication, QEvent, qInstallMessageHandler, QtMsgType
    from PySide6.QtWidgets import QApplication, QFileDialog, QDialog, QTextEdit
    import dns.resolver
    from cyberrecon.gui import Window
    from cyberrecon.storage import Repository
    from cyberrecon.dashboard import overview_data
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    if (output / 'workspace').exists():
        parser.error('Choose a fresh output directory; never overwrite workspace evidence')

    class Handler(BaseHTTPRequestHandler):
        expected_disconnects = 0
        def handle(self):
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError):
                # Nmap service probes deliberately close or reset connections.
                type(self).expected_disconnects += 1
        def do_GET(self):
            self.send_response(200); self.send_header('Content-Type', 'text/html')
            self.end_headers()
            try:
                self.wfile.write(b'<title>Owned CyberRecon dashboard lab</title><meta name="generator" content="Owned fixture CMS"><script src="/jquery.min.js"></script>')
            except (BrokenPipeError, ConnectionResetError):
                pass
        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    app = QApplication.instance() or QApplication([])
    qt_errors = []
    previous_handler = qInstallMessageHandler(lambda kind, context, message: qt_errors.append(message) if kind in (QtMsgType.QtCriticalMsg, QtMsgType.QtFatalMsg) else None)
    window = Window(Repository(output / 'workspace')); window.show()
    report = {'status': 'RUNNING', 'platform': app.platformName(), 'checks': {},
              'scope': 'Owned loopback application verification, not distro lifecycle or production release'}

    def wait_until(condition, seconds=60):
        deadline = time.monotonic() + seconds
        while not condition() and time.monotonic() < deadline:
            app.processEvents(); time.sleep(.01)
        assert condition(), 'UI operation timed out'

    def settle():
        until = time.monotonic() + .15
        while time.monotonic() < until:
            app.processEvents(); time.sleep(.01)

    try:
        settle()
        assert window.cards['target'].value.text() == 'No target'
        window.grab().save(str(output / 'empty-desktop.png'))
        report['checks']['empty'] = 'PASS'
        window.target.setText('http://127.0.0.1:' + str(server.server_port))
        window.authority.setText('Own script-controlled loopback server')
        window.includes.setText('127.0.0.1'); window.crawl.setChecked(False)
        window.port_list.setText(str(server.server_port))
        with patch('dns.resolver.Resolver.resolve', side_effect=dns.resolver.NoAnswer):
            window.start_scan()
            assert window.worker is not None and not window.start.isEnabled(), 'Start must create a worker and lock controls'
            assert not window.overview.skeleton.isHidden(), 'Loading skeleton must be visible'
            window.grab().save(str(output / 'loading-desktop.png'))
            wait_until(lambda: window.worker is None)
        snapshot = window.repo.snapshot(window.scans.currentData())
        assert snapshot['scan']['status'] in ('complete', 'partial')
        assert snapshot['http'] and snapshot['technologies']
        assert any(row['port'] == server.server_port and row['state'] == 'open' for row in snapshot['ports'])
        expected = overview_data(snapshot)
        assert window.cards['ports'].value.text() == str(sum(row['state'] == 'open' for row in expected['ports']))
        assert window.cards['findings'].value.text() == str(len(snapshot['findings']))
        report['scan_status'] = snapshot['scan']['status']
        report['warnings'] = snapshot['scan']['warnings']
        report['checks']['real-http-nmap-and-cards'] = 'PASS'
        window.resize(1536, 1024); settle(); window.grab().save(str(output / 'results-desktop.png'))
        for index, key in enumerate(window.tab_keys):
            window.dashboard_tabs.setCurrentIndex(index); app.processEvents()
            assert window.pages.currentIndex() == window.section_keys.index(key)
        report['checks']['navigation'] = list(window.tab_keys)
        window.navigate('overview'); window.resize(600, 900); settle()
        assert window.width() == 600 and window.target.isVisible() and window.start.isVisible()
        window.grab().save(str(output / 'results-narrow.png'))
        report['checks']['narrow'] = 'PASS'
        window.resize(1536, 1024); app.processEvents()
        table = window.overview.tables['technologies']
        table.filter.setText('no-such-owned-fixture'); assert table.table.rowCount() == 0
        table.filter.clear(); assert table.table.rowCount() > 0
        details = []
        with patch.object(QDialog, 'exec', lambda dialog: details.append(dialog.findChild(QTextEdit).toPlainText())):
            table.details(0, 0)
        assert details and json.loads(details[0])['source']
        report['checks']['filter-and-evidence-details'] = 'PASS'
        for index, name in enumerate(('JSON', 'HTML', 'PDF')):
            destination = output / name.lower()
            with patch.object(QFileDialog, 'getExistingDirectory', return_value=str(destination)):
                window.overview.export_buttons[index].click()
            wait_until(lambda: not window.local_jobs)
            filename = {'JSON': 'scan.json', 'HTML': 'report.html', 'PDF': 'report.pdf'}[name]
            assert (destination / filename).is_file()
        report['checks']['actual-ui-exports'] = 'PASS'
        assert json.loads(window.report_preview.toPlainText())['scan']['id'] == snapshot['scan']['id']
        window.start_scan(); assert window.worker is not None
        window.cancel_scan(); wait_until(lambda: window.worker is None)
        cancelled = window.repo.snapshot(window.scans.currentData())
        assert cancelled['scan']['status'] == 'cancelled'
        assert window.start.isEnabled()
        report['checks']['cancellation'] = 'PASS'
        window.failed('Owned error-state verification')
        assert 'Failed' in window.application_state.text() and not window.overview.notice.isHidden()
        report['checks']['failure-state'] = 'PASS'
        assert not qt_errors, 'Qt reported a critical error'
        report['checks']['qt-critical-errors'] = 'PASS: none observed'
        report['expected-nmap-disconnects'] = Handler.expected_disconnects
        report['status'] = 'PASS'
    except Exception as exc:
        report['status'] = 'FAIL'; report['error'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        window.close(); QThreadPool.globalInstance().waitForDone(45000); app.processEvents()
        window.close(); window.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete); app.processEvents()
        server.shutdown(); server.server_close(); thread.join(timeout=3)
        qInstallMessageHandler(previous_handler)
        (output / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
