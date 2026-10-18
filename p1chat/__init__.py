"""P1 chat surface: bubble list, composer, degrade/re-upgrade.

Stdlib only. Consumes the P1 transport (p1transport.Client) but the
state machine itself works on plain envelopes + session bodies, so tests
drive it with a scripted transport: no sockets needed.

Contract mapping:
- E02/E05: one logical bubble per id; unsupported type, missing/corrupt
  payload or failed validation renders the envelope's `fallback` text
  with a visible static reason indicator -- never a silent drop.
  Stale revisions keep the previous good representation with a warning;
  exact (id, revision, major) replays are inert; dual-major second
  representations do not open a second bubble.
- Composer: send control active when text is present, voice control when
  the box is empty. P1 wires the text/send path only; voice capture,
  hold-to-record and drag-to-cancel are later phases.
- V05: degrade (session mode=text) shows static text plus the session
  reason as a banner; bubbles are untouched so a later compatible
  resume re-upgrades to rich without loss or duplication. No sticky flag:
  every on_session() re-evaluates from the session body alone.
- F03/F04 boundary: no rich bubble chrome, no sandbox, no Add-flow pages.
  Rich style here means plain validated text; static means fallback/banner.
"""
from .surface import ChatSurface, composer_mode

__all__ = ["ChatSurface", "composer_mode"]
