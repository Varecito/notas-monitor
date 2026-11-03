import contextlib
import io
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from cryptography.fernet import Fernet
import monitor as m
import heartbeat
from test_monitor import page


class FeatureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.key = Fernet.generate_key().decode()
        self.cfg = m.Config('https://example.org/grades', 'example-user', 'example-password',
                            '123456:' + 'a' * 30, '123456', self.key)
        self.now = datetime(2026, 11, 2, 15, 45, tzinfo=timezone.utc)
        self.store = m.EncryptedStore(Path(self.temp.name) / 'commands.enc', self.key)
        self.health = {'last_attempt': self.now.isoformat(), 'last_ok': self.now.isoformat(),
                       'last_result': 'ok'}

    def message(self, update_id, text='/estado', chat='123456', kind='private', sender='123456'):
        return {'update_id': update_id, 'message': {'chat': {'id': int(chat), 'type': kind},
                'from': {'id': int(sender), 'is_bot': False}, 'text': text}}

    def test_owner_status_and_cursor_survive_restarts(self):
        with patch.object(m, 'telegram_api', return_value=[self.message(50)]) as api, \
                patch.object(m, 'telegram') as send:
            m.process_commands(self.cfg, self.store, self.health)
            send.assert_called_once()
            text = send.call_args.args[1]
            self.assertIn('02/11/2026 12:45:00', text)
            self.assertIn('Última revisión exitosa', text)
            self.assertEqual(self.store.read(), {'next_update': 51})
        with patch.object(m, 'telegram_api', return_value=[]) as api, patch.object(m, 'telegram') as send:
            m.process_commands(self.cfg, self.store, self.health)
            self.assertEqual(api.call_args.args[2]['offset'], 51)
            send.assert_not_called()
        self.assertNotIn('/estado', self.store.path.read_text())

    def test_other_chats_groups_and_senders_never_receive_data(self):
        updates = [self.message(1, chat='999999'), self.message(2, kind='group'),
                   self.message(3, sender='999999'), self.message(4, text='cualquier texto')]
        forwarded = self.message(5)
        forwarded['message']['forward_origin'] = {'type': 'user'}
        updates.append(forwarded)
        with patch.object(m, 'telegram_api', return_value=updates), patch.object(m, 'telegram') as send:
            m.process_commands(self.cfg, self.store, self.health)
            send.assert_not_called()
        self.assertEqual(self.store.read(), {'next_update': 6})

    def test_failed_status_send_does_not_consume_command(self):
        with patch.object(m, 'telegram_api', return_value=[self.message(50)]), \
                patch.object(m, 'telegram', side_effect=m.MonitorError('Error de envío')):
            with self.assertRaises(m.MonitorError):
                m.process_commands(self.cfg, self.store, self.health)
        self.assertIsNone(self.store.read())

    def test_backlog_coalesces_owner_requests(self):
        with patch.object(m, 'telegram_api', return_value=[self.message(50), self.message(51)]), \
                patch.object(m, 'telegram') as send:
            m.process_commands(self.cfg, self.store, self.health)
            send.assert_called_once()

    def test_failure_status_keeps_last_success(self):
        failed = {**self.health, 'last_attempt': '2026-11-02T16:00:00+00:00', 'last_result': 'error'}
        text = m.status_message(failed)
        self.assertIn('no se pudo completar', text)
        self.assertIn('13:00:00', text)
        self.assertIn('12:45:00', text)

    def test_new_corrected_and_removed_grades_without_values(self):
        before = m.parse_grades(page(), 2026)['subjects'][0]
        after = m.parse_grades(page('7,85'), 2026)['subjects'][0]
        previous = {'celdas': {before['id']: before['celdas']}}
        self.assertEqual(m.change_types(previous, after), 'Nota nueva')
        previous = {'celdas': {after['id']: after['celdas']}}
        corrected = m.parse_grades(page('9,25'), 2026)['subjects'][0]
        self.assertEqual(m.change_types(previous, corrected), 'Nota corregida')
        self.assertEqual(m.change_types(previous, before), 'Nota retirada')
        self.assertEqual(m.change_types({}, after), 'Calificación actualizada')
        self.assertNotIn('7,85', m.canonical(after['celdas']))

    def test_cycle_responds_to_status_even_when_school_fails(self):
        previous_directory = os.getcwd()
        os.chdir(self.temp.name)
        try:
            with patch.object(m, 'run_once', side_effect=m.MonitorError('Portal inaccesible')), \
                    patch.object(m, 'telegram_api', return_value=[self.message(50)]), \
                    patch.object(m, 'telegram') as send:
                with self.assertRaises(m.MonitorError):
                    m.run_cycle(self.cfg, now=self.now)
                self.assertEqual(send.call_count, 2)
                self.assertIn('Último intento', send.call_args.args[1])
                stored = m.EncryptedStore('health.enc', self.key).read()
                self.assertEqual(stored['last_result'], 'error')
                self.assertNotIn('last_ok', stored)
        finally:
            os.chdir(previous_directory)

    def test_command_menu_is_scoped_to_owner_chat(self):
        with patch.object(m, 'telegram_api') as api:
            m.configure_commands(self.cfg)
        self.assertEqual(api.call_args.args[2]['scope'], {'type': 'chat', 'chat_id': self.cfg.chat_id})

    def test_watchdog_sends_empty_signal_only_to_expected_host(self):
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value.status = 200
        url = 'https://hc-ping.com/00000000-0000-0000-0000-000000000001'
        heartbeat.ping(url, opener=opener)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.data, b'')
        self.assertEqual(request.full_url, url)
        for invalid in ('http://hc-ping.com/key', url + '?secret=x', url.replace('hc-ping.com', 'other.org')):
            with self.assertRaises(ValueError):
                heartbeat.ping(invalid, opener=opener)

    def test_watchdog_failure_is_sanitized_and_retried(self):
        opener = Mock()
        opener.open.side_effect = OSError('private-token-in-request')
        with self.assertRaises(ValueError) as caught:
            heartbeat.ping('https://hc-ping.com/00000000-0000-0000-0000-000000000001',
                           opener=opener, sleep=lambda seconds: None)
        self.assertEqual(opener.open.call_count, 3)
        self.assertNotIn('private-token-in-request', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
