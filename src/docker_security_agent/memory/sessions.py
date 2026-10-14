"""Agent conversation memory, using the Agents SDK's built-in ``SQLiteSession``.

A *session* stores the conversation (user input, model messages, tool calls
and tool results) so a later ``Runner.run`` with the same session continues
where the previous one stopped. The SDK handles all of this; we only choose
the database file and the session ID.

* Default: each run gets its own session (session_id == run_id), so a new
  assessment never inherits stale context - historical findings must not be
  mistaken for current state.
* ``docker-audit assess --session NAME`` re-uses a named session, e.g. to ask
  follow-up questions about the same environment across executions.

The session DB (``data/agent_sessions.db``) is deliberately separate from the
structured assessment store (``data/assessments.db``).
"""

from __future__ import annotations

from pathlib import Path

from agents import SQLiteSession


def open_session(session_id: str, db_path: Path) -> SQLiteSession:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return SQLiteSession(session_id=session_id, db_path=db_path)
