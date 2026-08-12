import unittest

from tornadorevc2.terminal_sanitize import sanitize_terminal_output


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


if __name__ == '__main__':
    unittest.main()
