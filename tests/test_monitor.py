import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
import monitor as m


def page(value='S/C', teacher='Profesora Ejemplo', year='2026'):
    return ('<select id="content_ddAño"><option selected>' + year + '</option></select>'
            '<table><tr><th>Docente</th><th>C1_TP1</th><th>C1_TP2</th></tr>'
            '<tr><td colspan="3">Matemática</td></tr><tr><td>' + teacher + '</td><td>'
            + value + '</td><td>-</td></tr></table>')


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.key = Fernet.generate_key().decode()
        self.cfg = m.Config('https://example.org/grades', 'example-user', 'example-password',
                            '123456:' + 'a' * 30, '123456', self.key)
        self.store = m.EncryptedStore(Path(self.temp.name) / 'state.enc', self.key)
        self.now = datetime(2026, 10, 30, 20, tzinfo=timezone.utc)
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def run_monitor(self, html, **kwargs):
        with patch.object(m, 'fetch_grades', return_value=m.parse_grades(html, '2026')), \
                patch.object(m, 'telegram') as send, contextlib.redirect_stdout(io.StringIO()):
            m.run_once(self.cfg, self.store, now=self.now, **kwargs)
            return send

    def test_blank_variants_equal(self):
        self.assertEqual(m.parse_grades(page('S/C'), 2026), m.parse_grades(page('-'), 2026))
        self.assertEqual(m.parse_grades(page(''), 2026), m.parse_grades(page('-'), 2026))

    def test_parser_returns_only_fingerprints_and_labels(self):
        result = m.parse_grades(page('7,85'), 2026)
        self.assertNotIn('7,85', json.dumps(result))
        self.assertEqual(result['subjects'][0]['materia'], 'Matemática')
        self.assertEqual(result['subjects'][0]['docente'], 'Profesora Ejemplo')

    def test_changed_grade_sends_only_subject_teacher(self):
        self.run_monitor(page())
        send = self.run_monitor(page('7,85'))
        send.assert_called_once()
        message = send.call_args.args[1]
        self.assertIn('Matemática', message)
        self.assertIn('Profesora Ejemplo', message)
        self.assertNotIn('7,85', message)
        self.assertNotIn('Matemática', self.store.path.read_text())
        self.assertNotIn('7,85', json.dumps(self.store.read()))
        self.run_monitor(page('7,85')).assert_not_called()

    def test_failed_send_preserves_reference(self):
        self.run_monitor(page())
        before = self.store.path.read_bytes()
        with patch.object(m, 'fetch_grades', return_value=m.parse_grades(page('9'), 2026)), \
                patch.object(m, 'telegram', side_effect=m.MonitorError('envío fallido')):
            with self.assertRaises(m.MonitorError):
                m.run_once(self.cfg, self.store, now=self.now)
        self.assertEqual(before, self.store.path.read_bytes())
        self.run_monitor(page('9')).assert_called_once()

    def test_structure_change_preserves_reference(self):
        self.run_monitor(page())
        before = self.store.path.read_bytes()
        with self.assertRaises(m.MonitorError):
            self.run_monitor(page(teacher='Otra profesora'))
        self.assertEqual(before, self.store.path.read_bytes())

    def test_migration_initial_state_does_not_repeat(self):
        self.run_monitor(page('8'))
        seed = self.store.read()
        seed.pop('last_saved')
        seed['actualizada'] = self.now.isoformat()
        self.store.path.unlink()
        os.environ['INITIAL_STATE'] = m.canonical(seed)
        self.run_monitor(page('8')).assert_not_called()
        self.assertTrue(self.store.path.exists())
        self.run_monitor(page('9')).assert_called_once()

    def test_tampered_or_wrong_key_rejected(self):
        self.store.write({'example': 'private'})
        with self.assertRaises(m.MonitorError):
            m.EncryptedStore(self.store.path, Fernet.generate_key().decode()).read()
        self.store.path.write_bytes(b'invalid-state')
        with self.assertRaises(m.MonitorError):
            self.store.read()

    def test_unknown_year_and_login_page_rejected(self):
        for html in (page(year='2025'), '<form>Login</form>', page().replace('C1_TP2', 'C1_TP1')):
            with self.subTest(html=html), self.assertRaises(m.MonitorError):
                m.parse_grades(html, 2026)

    def test_changed_grade_after_import_is_not_lost(self):
        self.run_monitor(page())
        os.environ['INITIAL_STATE'] = m.canonical(self.store.read())
        self.store.path.unlink()
        self.run_monitor(page('10')).assert_called_once()

    def test_foreign_redirect_blocked(self):
        with self.assertRaises(m.MonitorError):
            m.OnlyOrigin('https://example.org').redirect_request(None, None, 302, '', {}, 'https://other.org')


if __name__ == '__main__':
    unittest.main()
