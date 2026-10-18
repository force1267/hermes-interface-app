"""RichBubble: validated fragment + budget/mode/override + R04 degraded path.

- Provider declares mode; client enforces runtime render_budget (no numbers
  compiled in); explicit user Expand wins, Collapse returns to preview;
  any budget overflow auto-escalates to expanded.
- Expansion preserves unsent form values + request ids; collapse restores
  the invoking focus target.
- Invalid/incompatible fragments fall back to the last-good cached
  representation, else the envelope fallback text; never a silent drop.
- F03: with no usable budget (missing/invalid/unmeasured) or after the
  user collapses an overflowed bubble, resolve() emits a BOUNDED static
  preview (truncated body + physical size clamp + explicit Expand), never
  the full body.
"""
from p0contract.fragments import validate_fragment, FragmentError
from p0contract.render_policy import (
    enforce_budget, effective_mode, collapse_preserve,
)

from .renderer import (
    render_bubble_html, render_preview_html, fallback_bubble_html,
    check_kind,
)
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
        self.render = None   # 'rich' | 'preview' | 'last-good' | 'fallback'
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

    def _budget_unusable(self):
        """True when no valid budget is in force (missing or invalid)."""
        if self.budget is None:
            return True
        try:
            from p0contract.render_policy import validate_budget
            validate_budget(self.budget)
        except Exception:
            return True
        return False

    def _preview_result(self, frag, render, reason):
        self.mode = "standard"
        self.render, self.reason = render, reason
        self.html = render_preview_html(frag, self.form_values)
        return self._result()

    def resolve(self):
        """Validate, pick effective mode, render. Never returns empty."""
        frag = self.fragment
        try:
            validate_fragment(frag)
            check_kind(frag["tree"], frag["kind"])
        except (FragmentError, KeyError, TypeError, AttributeError) as e:
            return self._degraded(f"invalid-fragment:{e}")
        overflow = self._overflow()
        if self.user_expand:
            # Explicit user Expand always wins, even with no usable
            # budget: the user takes responsibility for the full body.
            self.mode = "expanded"
            self.render, self.reason = "rich", None
            self.html = render_bubble_html(frag, "expanded", self.form_values)
            return self._result()
        if self._budget_unusable():
            if self.budget is None:
                return self._preview_result(frag, "preview",
                                            "missing-budget:static-preview")
            return self._preview_result(frag, "fallback",
                                        "missing-invalid-budget")
        if self.measured is None:
            # Valid budget but nothing measured yet -> bounded preview.
            return self._preview_result(frag, "preview",
                                        "unmeasured:static-preview")
        mode, _ = effective_mode(frag["mode"], overflow,
                                 self.user_expand, self.user_collapse)
        self.mode = mode
        self.render, self.reason = "rich", None
        if mode == "standard" and overflow and self.user_collapse:
            # Collapse after overflow returns to the bounded preview,
            # not the full standard body.
            self.render, self.reason = "preview", "overflow-collapse:preview"
            self.html = render_preview_html(frag, self.form_values)
        else:
            self.html = render_bubble_html(frag, mode, self.form_values)
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
                self.html = render_bubble_html(self.last_good, mode,
                                               self.form_values)
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

    def _result(self):
        return {"html": self.html, "mode": self.mode,
                "render": self.render, "reason": self.reason,
                "form_values": dict(self.form_values),
                "request_ids": list(self.request_ids),
                "focus_target": self.focus_target}
