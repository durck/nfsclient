"""Guard render-only coalescing of transient Windows PTY redraws."""

import unittest

from prepare_demo_render import coalesce


class RenderTests(unittest.TestCase):
    clear = "\x1b[?25l\r\x1b[K\x1b[?25h"

    def test_split_redraw_preserves_bytes_at_completion_time(self):
        self.assertEqual(coalesce([[1, "o", self.clear], [1.1, "o", "prompt"]]),
                         [[1.1, "o", self.clear + "prompt"]])

    def test_intentional_clear_pause_is_retained(self):
        events = [[1, "o", self.clear], [1.3, "o", "prompt"]]
        self.assertEqual(coalesce(events), events)

    def test_text_input_events_and_final_clear_are_retained(self):
        for events in ([], [[1, "o", self.clear]],
                       [[1, "o", "text"], [1.1, "o", "more"]],
                       [[1, "o", self.clear], [1.1, "i", "a"]]):
            with self.subTest(events=events):
                self.assertEqual(coalesce(events), events)


if __name__ == "__main__":
    unittest.main()
