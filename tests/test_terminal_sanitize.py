import unittest

from tornadorevc2.session_registry import (
    compute_fingerprint,
    fingerprint_variants,
    identities_match,
    _norm_machine_id,
)
from tornadorevc2.terminal_sanitize import sanitize_terminal_output, strip_csi_sequences


class TestSanitizeTerminalOutput(unittest.TestCase):
    def test_plain_text_unchanged(self):
        self.assertEqual(sanitize_terminal_output('hello\nworld'), 'hello\nworld')

    def test_csi_color_and_cursor(self):
        raw = '\x1b[31mred\x1b[0m\n\x1b[2J\x1b[H'
        self.assertEqual(sanitize_terminal_output(raw), 'red\n')

    def test_bracketed_paste_mode(self):
        raw = '\x1b[?2004l\x1b[?2004h'
        self.assertEqual(sanitize_terminal_output(raw), '')

    def test_terminal_title_osc(self):
        raw = '\x1b]0;user@host\x07ls -la'
        self.assertEqual(sanitize_terminal_output(raw), 'ls -la')

    def test_shell_integration_3008(self):
        raw = (
            '\x1b]3008;start=abc;machineid=mid;user=root;hostname=box;'
            'bootid=b1;pid=1234;type=command;cwd=/tmp\x07'
        )
        self.assertEqual(sanitize_terminal_output(raw), '')

    def test_shell_integration_and_title_without_terminator(self):
        raw = (
            '\x1b]3008;start=abc;machineid=mid;user=root;hostname=box;'
            'bootid=b1;pid=1234;type=command;cwd=/tmp\x1b]0;'
        )
        self.assertEqual(sanitize_terminal_output(raw), '')

    def test_vscode_shell_integration_633(self):
        raw = '\x1b]633;C;ls\x07\x1b]633;D;0\x07'
        self.assertEqual(sanitize_terminal_output(raw), '')

    def test_mixed_output(self):
        raw = (
            '\x1b[?2004l\x1b]3008;start=x;type=command;cwd=/\x07'
            '\x1b[32mok\x1b[0m\n'
        )
        self.assertEqual(sanitize_terminal_output(raw), 'ok\n')

    def test_identity_markers_preserved_by_csi_strip(self):
        raw = (
            '\x1b[?2004l\x1b]633;C\x07__T_ID_START__mybox|root|'
            'abc123def456789012345678901234ef__T_ID_END__\x1b[?2004h'
        )
        stripped = strip_csi_sequences(raw)
        self.assertIn('__T_ID_START__mybox|root|', stripped)
        self.assertIn('__T_ID_END__', stripped)

    def test_unterminated_dcs_does_not_delete_markers(self):
        raw = '\x1bPgarbage __T_ID_START__host|user|abc__T_ID_END__'
        self.assertIn('__T_ID_START__', sanitize_terminal_output(raw))


class TestSessionRegistryFingerprint(unittest.TestCase):
    def test_machine_id_normalization(self):
        raw = 'abc123def456789012345678901234ef\x1b]633;D\x07'
        self.assertEqual(
            _norm_machine_id(raw),
            'abc123def456789012345678901234ef',
        )

    def test_fingerprint_variants_include_legacy(self):
        info = {
            'type': 'unix',
            'addr': ('127.0.0.1', 4444),
            'identity': {
                'hostname': 'box',
                'username': 'root',
                'machine_id': 'abc123def456789012345678901234ef',
            },
        }
        variants = fingerprint_variants(info)
        self.assertEqual(len(variants), 2)
        self.assertNotEqual(variants[0], variants[1])

    def test_identities_match_when_only_one_side_has_machine_id(self):
        incoming = ('box', 'root', 'unix', '')
        stored = ('box', 'root', 'unix', 'abc123def456789012345678901234ef')
        self.assertTrue(identities_match(incoming, stored))


if __name__ == '__main__':
    unittest.main()
