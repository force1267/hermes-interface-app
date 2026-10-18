"""RichBubble: validated fragment + budget/mode/override + R04 degraded path.

- Provider declares mode; client enforces runtime render_budget (no numbers
  compiled in); explicit user Expand wins, Collapse returns to preview;
  any budget overflow auto-escalates to expanded.
- Expansion preserves unsent form values + request ids; collapse restores
  the invoking focus target.
- Invalid/incompatible fragments fall back to the last-good cached
  representation, else the envelope fallback text; never a silent drop.
"""
from p0contract.fragments import validate_fragment, FragmentError
from p0contract.render_policy import (
    enforce_budget, effective_mode, collapse_preserve,
)

from .renderer import render_bubble_html, fallback_bubble_html, check_kind
from .renderer import KIND_COMPONENTS


class RichBubble:
    def __init__(self, fragment, budget=None, last_good=None,
                 form_values=None, request_ids=None, focus_target=None):
        self.fragment = fragment
        self.budget = budget
        self.last_good = last_good
        self.form_values = dict(form_values or {})
        self.request_ids = list(request_ids or [])
        self.focus_target = focus_target
        self.user_expand = False
        self.user_collapse = False
        self.measured = None
        self.render = None   # 'rich' | 'last-good' | 'fallback'
        self.reason = None
        self.mode = "standard"
        self.html = ""

    # -- state ops --
    def set_measured(self, measured):
        """Trusted client measurement {height_px,width_px,actions,...}."""
        self.measured = dict(measured)

    def expand(self):
        self.user_expand = True
        self.user_collapse = False
        return collapse_preserve(self.form_values, self.request_ids,
                                 self.focus_target)

    def collapse(self):
        self.user_expand = False
        self.user_collapse = True
        state = collapse_preserve(self.form_values, self.request_ids,
                                  self.focus_target)
        return state  # caller restores focus to state['focus_target']

    def _overflow(self):
        if self.measured is None or self.budget is None:
            return False
        mode, _ = enforce_budget(self.measured, self.budget)
        return mode == "expanded"

    def resolve(self):
        """Validate, pick effective mode, render. Never returns empty."""
        frag = self.fragment
        try:
            validate_fragment(frag)
            check_kind(frag["tree"], frag["kind"])
        except (FragmentError, KeyError, TypeError, AttributeError) as e:
            return self._degraded(f"invalid-fragment:{e}")
        overflow = self._overflow()
        if self.measured is None or self.budget is None:
            # F03: missing/invalid budget -> static preview with Expand.
            if self.budget is not None:
                try:
                    from p0contract.render_policy import validate_budget
                    validate_budget(self.budget)
                except Exception as e:
                    return self._degraded_render(
                        frag, "fallback", f"missing-invalid-budget:{e}")
                # valid budget but nothing measured yet -> standard preview
            mode, _ = effective_mode(frag["mode"], overflow,
                                     self.user_expand, self.user_collapse)
            self.mode = mode
            self.render, self.reason = "rich", None
            self.html = render_bubble_html(frag, mode)
            return self._result()
        mode, _ = effective_mode(frag["mode"], overflow,
                                 self.user_expand, self.user_collapse)
        self.mode = mode
        self.render, self.reason = "rich", None
        self.html = render_bubble_html(frag, mode)
        return self._result()

    def _degraded(self, reason):
        if self.last_good is not None:
            try:
                validate_fragment(self.last_good)
                check_kind(self.last_good["tree"], self.last_good["kind"])
                mode, _ = effective_mode(
                    self.last_good.get("mode", "standard"), False,
                    self.user_expand, self.user_collapse)
                self.mode = mode
                self.render = "last-good"
                self.reason = reason
                self.html = render_bubble_html(self.last_good, mode)
                return self._result()
            except Exception:
                pass
        fb = ""
        try:
            fb = self.fragment.get("fallback_text", "") or ""
        except AttributeError:
            fb = ""
        if not fb:
            fb = "Content unavailable."
        self.mode = "standard"
        self.render = "fallback"
        self.reason = reason
        self.html = fallback_bubble_html(fb, reason)
        return self._result()

    def _degraded_render(self, frag, render, reason):
        # valid fragment but unusable budget -> static preview, still Expand
        self.mode = "standard"
        self.render, self.reason = render, reason
        self.html = render_bubble_html(frag, "standard")
        return self._result()

    def _result(self):
        return {"html": self.html, "mode": self.mode,
                "render": self.render, "reason": self.reason,
                "form_values": dict(self.form_values),
                "request_ids": list(self.request_ids),
                "focus_target": self.focus_target}
