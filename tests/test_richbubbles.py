"""P2 rich bubbles: golden gate + budget/mode/override + degraded + sandbox."""
import json
import os
import unittest

from p0contract.render_policy import (
    validate_bridge, sandbox_config, check_sandbox,
)
from p2rich.renderer import render_bubble_html, render_tree
from p2rich.bubble import RichBubble
from p2rich.sandbox import (
    build_page, frame_srcdoc, frame_count_in_page, SANDBOX_ATTR, CSP_META,
)
from p0contract.fragments import FragmentError

GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "goldens")
GOLDEN_KINDS = ["text", "card-list", "form", "media", "nested"]

BUDGET = {"revision": "r1", "max_inline_height_px": 200,
          "max_inline_width_px": 300, "max_inline_actions": 2,
          "allow_inline_focus_capture": False}


def load_golden(name):
    with open(os.path.join(GOLDEN_DIR, name + ".json")) as f:
        frag = json.load(f)
    with open(os.path.join(GOLDEN_DIR, name + ".html"), "rb") as f:
        raw = f.read()
    return frag, raw


class T_Goldens(unittest.TestCase):
    def test_all_kinds_byte_for_byte(self):
        for name in GOLDEN_KINDS:
            with self.subTest(kind=name):
                frag, raw = load_golden(name)
                got = (render_bubble_html(frag, "standard") + "\n").encode()
                self.assertEqual(got, raw, f"golden mismatch: {name}")


class T_ModeBudget(unittest.TestCase):
    def base(self):
        frag, _ = load_golden("card-list")
        return frag

    def test_within_budget_stays_standard(self):
        b = RichBubble(self.base(), budget=BUDGET)
        b.set_measured({"height_px": 50, "width_px": 50, "actions": 1,
                        "focus_capture": False})
        r = b.resolve()
        self.assertEqual(r["mode"], "standard")
        self.assertEqual(r["render"], "rich")
        self.assertIn('data-op="expand"', r["html"])

    def test_overflow_escalates(self):
        b = RichBubble(self.base(), budget=BUDGET)
        b.set_measured({"height_px": 500, "width_px": 50, "actions": 1,
                        "focus_capture": False})
        r = b.resolve()
        self.assertEqual(r["mode"], "expanded")
        self.assertIn("takeover", r["html"])

    def test_provider_expanded_sticks(self):
        frag = self.base()
        frag["mode"] = "expanded"
        b = RichBubble(frag, budget=BUDGET)
        b.set_measured({"height_px": 10, "width_px": 10, "actions": 0,
                        "focus_capture": False})
        self.assertEqual(b.resolve()["mode"], "expanded")

    def test_user_expand_wins_and_collapse_returns(self):
        b = RichBubble(self.base(), budget=BUDGET)
        b.set_measured({"height_px": 10, "width_px": 10, "actions": 0,
                        "focus_capture": False})
        b.expand()
        self.assertEqual(b.resolve()["mode"], "expanded")
        b.collapse()
        r = b.resolve()
        self.assertEqual(r["mode"], "standard")
        self.assertIn('data-op="expand"', r["html"])

    def test_missing_budget_is_preview_with_expand(self):
        b = RichBubble(self.base(), budget=None)
        r = b.resolve()
        self.assertEqual(r["mode"], "standard")
        self.assertIn('data-op="expand"', r["html"])

    def test_runtime_budget_swap_changes_result(self):
        b = RichBubble(self.base(), budget=BUDGET)
        b.set_measured({"height_px": 150, "width_px": 50, "actions": 1,
                        "focus_capture": False})
        self.assertEqual(b.resolve()["mode"], "standard")
        b.budget = dict(BUDGET, max_inline_height_px=100)
        b.user_expand = b.user_collapse = False
        self.assertEqual(b.resolve()["mode"], "expanded")

    def test_expand_preserves_values_ids_and_collapse_restores_focus(self):
        frag, _ = load_golden("form")
        b = RichBubble(frag, budget=BUDGET,
                       form_values={"email": "a@b.c"}, request_ids=["r1"],
                       focus_target="email-field")
        b.set_measured({"height_px": 10, "width_px": 10, "actions": 1,
                        "focus_capture": False})
        kept = b.expand()
        self.assertEqual(kept["form_values"], {"email": "a@b.c"})
        self.assertEqual(kept["request_ids"], ["r1"])
        b.form_values["email"] = "typed-mid-escalation"
        r = b.resolve()
        self.assertEqual(r["form_values"], {"email": "typed-mid-escalation"})
        self.assertEqual(r["request_ids"], ["r1"])
        back = b.collapse()
        self.assertEqual(back["focus_target"], "email-field")
        self.assertEqual(back["form_values"], {"email": "typed-mid-escalation"})


class T_Treatment(unittest.TestCase):
    def test_shared_treatment_no_per_kind_styling(self):
        for name in GOLDEN_KINDS:
            frag, raw = load_golden(name)
            html = raw.decode()
            self.assertIn('class="bubble', html)
            # no kind-specific style class may appear
            for bad in ("bubble-text", "bubble-card", "bubble-form",
                        "bubble-media", "kind-text", "card-style"):
                self.assertNotIn(bad, html)

    def test_generated_and_generative_share_treatment(self):
        frag, _ = load_golden("form")
        html = render_bubble_html(frag, "standard")
        self.assertIn('class="bubble gen std"', html)
        self.assertIn('class="gen-badge"', html)
        self.assertIn('class="b g"', html)  # generative-intent button

    def test_cached_builtin_truthful_without_gen(self):
        frag, _ = load_golden("media")
        html = render_bubble_html(frag, "standard")
        self.assertNotIn("bubble gen", html)
        self.assertIn(">Cached<", html)
        frag2, _ = load_golden("nested")
        html2 = render_bubble_html(frag2, "standard")
        self.assertNotIn("bubble gen", html2)
        self.assertIn(">Built-in<", html2)


class T_Degraded(unittest.TestCase):
    def test_invalid_falls_back_to_last_good(self):
        good, _ = load_golden("text")
        bad = dict(good)
        bad["tree"] = {"component": "script",
                       "props": {"src": "x"}, "children": []}
        b = RichBubble(bad, budget=BUDGET, last_good=good)
        r = b.resolve()
        self.assertEqual(r["render"], "last-good")
        self.assertIn("Hello golden text", r["html"])

    def test_invalid_without_cache_uses_fallback_text(self):
        good, _ = load_golden("text")
        bad = dict(good)
        bad["tree"] = {"component": "html", "props": {}, "children": []}
        b = RichBubble(bad, budget=BUDGET, last_good=None)
        r = b.resolve()
        self.assertEqual(r["render"], "fallback")
        self.assertIn("Hello golden text", r["html"])
        self.assertTrue(r["html"])

    def test_never_silent_drop(self):
        b = RichBubble({"garbage": 1}, budget=BUDGET)
        r = b.resolve()
        self.assertIn(r["render"], ("last-good", "fallback"))
        self.assertTrue(r["html"].strip())

    def test_wrong_kind_subset_rejected(self):
        frag, _ = load_golden("text")
        frag = json.loads(json.dumps(frag))
        frag["kind"] = "text"
        frag["tree"] = {"component": "Button",
                        "props": {"label": "x", "action_id": "a",
                                  "intent": "assigned"}, "children": []}
        b = RichBubble(frag, budget=BUDGET)
        r = b.resolve()
        self.assertEqual(r["render"], "fallback")


class T_Sandbox(unittest.TestCase):
    def test_config_exact(self):
        cfg = sandbox_config()
        self.assertEqual(cfg["sandbox"], "allow-scripts")
        ok, why = check_sandbox(cfg)
        self.assertTrue(ok, why)
        bad, _ = check_sandbox({"sandbox": "allow-scripts allow-same-origin",
                                "csp": cfg["csp"]})
        self.assertFalse(bad)

    def test_single_reusable_frame_and_csp(self):
        page = build_page()
        self.assertEqual(frame_count_in_page(page), 1)
        self.assertIn('sandbox="allow-scripts"', page)
        for token in ("allow-same-origin", "allow-forms", "allow-popups",
                      "allow-top-navigation", "allow-downloads"):
            self.assertNotIn(token, page)
        for directive in ("default-src 'none'", "connect-src 'none'",
                          "form-action 'none'", "object-src 'none'",
                          "base-uri 'none'", "frame-src 'none'"):
            self.assertIn(directive, page)

    def test_bridge_denies(self):
        tok, ctx = "tok-1", "ctx-1"
        base = {"source_ok": True, "token": tok, "op": "action",
                "context": ctx,
                "payload": {"action_id": "a.ok"}}
        ok, _ = validate_bridge(dict(base), tok, ctx, ("a.ok",))
        self.assertTrue(ok)
        for mutate, _why in [
                ({"source_ok": False}, "source"),
                ({"token": "wrong"}, "token"),
                ({"op": "eval"}, "op"),
                ({"context": "other"}, "context"),
                ({"payload": {"action_id": "a.evil"}}, "action")]:
            ev = dict(base)
            ev.update(mutate)
            denied, _ = validate_bridge(ev, tok, ctx, ("a.ok",))
            self.assertFalse(denied, mutate)

    def test_no_raw_code_path(self):
        for comp in ("html", "code", "script", "style"):
            with self.assertRaises(FragmentError, msg=comp):
                render_tree({"component": comp, "props": {}, "children": []},
                            "text")
        with self.assertRaises(FragmentError):
            render_tree({"component": "Text",
                         "props": {"text": "x", "onclick": "evil()"},
                         "children": []}, "text")
        with self.assertRaises(FragmentError):
            render_tree({"component": "Media",
                         "props": {"asset_id": "https://evil/x.png",
                                   "alt": "x", "media_type": "image"},
                         "children": []}, "media")
        srcdoc = frame_srcdoc("t", "c", ("a.ok",))
        self.assertNotIn("eval(", srcdoc)


if __name__ == "__main__":
    unittest.main()


class T_P2Repair(unittest.TestCase):
    """Regression gate for t_e1371191: fail before repair, pass after."""

    def long_text(self):
        frag, _ = load_golden("text")
        frag = json.loads(json.dumps(frag))
        frag["tree"]["props"]["text"] = "LONG_SENTINEL " * 10000
        return frag

    def test_missing_budget_is_bounded_preview(self):
        b = RichBubble(self.long_text(), budget=None)
        r = b.resolve()
        self.assertEqual(r["mode"], "standard")
        self.assertEqual(r["render"], "preview")
        self.assertLess(len(r["html"]), 2000)
        self.assertLess(r["html"].count("LONG_SENTINEL"), 100)
        self.assertIn('data-preview="truncated"', r["html"])
        self.assertIn("max-height", r["html"])
        self.assertIn("\u2026", r["html"])
        self.assertIn('data-op="expand"', r["html"])

    def test_invalid_budget_is_bounded_fallback(self):
        b = RichBubble(self.long_text(), budget={"bogus": 1})
        r = b.resolve()
        self.assertEqual(r["render"], "fallback")
        self.assertLess(len(r["html"]), 2000)
        self.assertIn('data-preview="truncated"', r["html"])

    def test_overflow_collapse_returns_to_bounded_preview(self):
        b = RichBubble(self.long_text(), budget=BUDGET)
        b.set_measured({"height_px": 500, "width_px": 50, "actions": 0,
                        "focus_capture": False})
        self.assertEqual(b.resolve()["mode"], "expanded")
        b.expand()
        self.assertEqual(b.resolve()["mode"], "expanded")
        b.collapse()
        r = b.resolve()
        self.assertEqual(r["mode"], "standard")
        self.assertLess(len(r["html"]), 2000)
        self.assertIn('data-preview="truncated"', r["html"])

    def test_user_expand_wins_over_missing_budget(self):
        b = RichBubble(self.long_text(), budget=None)
        b.expand()
        r = b.resolve()
        self.assertEqual(r["mode"], "expanded")
        self.assertGreater(r["html"].count("LONG_SENTINEL"), 9000)

    def test_unsent_form_values_rendered(self):
        frag, _ = load_golden("form")
        b = RichBubble(frag, budget=BUDGET,
                       form_values={"email": "UNSENT_SENTINEL"},
                       focus_target="email-field")
        b.set_measured({"height_px": 10, "width_px": 10, "actions": 1,
                        "focus_capture": False})
        self.assertIn("UNSENT_SENTINEL", b.resolve()["html"])
        self.assertIn("UNSENT_SENTINEL",
                      render_tree(frag["tree"], "form",
                                  {"email": "UNSENT_SENTINEL"}))

    def test_csp_composition_dual_hash(self):
        page = build_page("tok", "ctx", ("a.ok",))
        self.assertIn("navigate-to 'none'", page)
        outer = page.split(
            'http-equiv="Content-Security-Policy" content="', 1)[1]
        outer = outer.split('">', 1)[0]
        self.assertEqual(outer.count("sha256-"), 3)  # 2 scripts + 1 style
        srcdoc = frame_srcdoc("tok", "ctx", ("a.ok",))
        self.assertIn("navigate-to 'none'", srcdoc)
        self.assertEqual(srcdoc.count("sha256-"), 1)
        self.assertNotIn("eval(", srcdoc)

    def test_frame_bundle_has_no_navigation_primitives(self):
        import p2rich.sandbox as sb
        for bad in ("location", "window.open", "top.location",
                    "document.write"):
            self.assertNotIn(bad, sb.FRAME_JS)

    def test_build_page_wires_bubbles_and_actions(self):
        frag, _ = load_golden("form")
        b = RichBubble(frag, budget=BUDGET, form_values={"email": "e@x.y"},
                       focus_target="email-field")
        page = build_page("tok", "ctx", ("a.submit",), bubbles=(b,))
        self.assertEqual(frame_count_in_page(page), 1)
        self.assertEqual(page.count("<article"), 1)
        self.assertIn('id="act-a.submit"', page)
        self.assertIn("P2_BUBBLES", page)
        import p2rich.sandbox as sb
        self.assertEqual(sb._js_data("</script><script>"),
                         '"\\u003c/script>\\u003cscript>"')

    def test_sandbox_config_requires_navigate_to(self):
        cfg = sandbox_config()
        self.assertEqual(cfg["csp"]["navigate-to"], "'none'")
        bad = sandbox_config()
        del bad["csp"]["navigate-to"]
        self.assertFalse(check_sandbox(bad)[0])
