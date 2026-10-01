"""Read-only quiz awareness for students (issue #172, student slice).

Two tools answer "what quizzes do I have, when are they due, and how many
attempts do I have left?". Neither takes a quiz, starts an attempt, or reads a
question or answer: those are academic-integrity decisions this module
deliberately does not make, so no endpoint under ``.../questions``,
``.../quiz_submissions/:id/...`` or any POST/PUT is ever called.

Canvas has two quiz engines, and they surface differently to a student token:

- **Classic Quizzes** have their own API. ``GET /courses/:id/quizzes`` lists them
  (404 when the instructor has hidden the Quizzes page), ``GET
  /courses/:id/quizzes/:id`` describes one, and ``GET
  /courses/:id/quizzes/:id/submissions`` returns the caller's own attempts when
  the caller can only submit.
- **New Quizzes** live in a separate LTI service. To Canvas they are assignments
  whose external tool is the Quizzes LTI tool, which the assignment serializer
  marks with ``is_quiz_lti_assignment: true`` (canvas-lms
  ``lib/api/v1/assignment.rb``, set only when ``assignment.quiz_lti?``). Their
  settings and per-attempt history are not exposed to students by any
  documented Canvas REST endpoint, and the tools say so instead of guessing.

``is_quiz_assignment`` is NOT a New Quizzes signal, whatever its docstring says:
the serializer sets it to ``assignment.quiz? && assignment.quiz.assignment?``,
i.e. a graded *Classic* quiz, and that was measured live on #172. Closed PR #191
used it to find New Quizzes and would have reported none.
"""

import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from fastmcp import FastMCP
from mcp.types import ToolAnnotations

from ..core.cache import get_course_code, get_course_id
from ..core.client import fetch_all_paginated_results, make_canvas_request
from ..core.dates import format_date, parse_date
from ..core.untrusted_content import fence_untrusted, fence_untrusted_inline
from ..core.validation import coerce_canvas_id, validate_params

_QUIZ_TYPE_LABELS = {
    "assignment": "graded quiz",
    "practice_quiz": "practice quiz",
    "graded_survey": "graded survey",
    "survey": "ungraded survey",
}

_SCORING_POLICY_LABELS = {
    "keep_highest": "highest attempt counts",
    "keep_latest": "latest attempt counts",
    "keep_average": "average of attempts counts",
}

# QuizSubmission states that represent a finished attempt. "untaken" is an
# attempt in progress; "settings_only" is a placeholder Canvas creates when an
# instructor grants extra attempts or time before the student starts; "preview"
# is a teacher preview. Neither of the last two is an attempt.
_FINISHED_STATES = ("complete", "pending_review")
_NON_ATTEMPT_STATES = ("settings_only", "preview")

_NEW_QUIZZES_NOTE = (
    "Note: this is a New Quiz. Its time limit, number of allowed attempts, "
    "question count and your per-attempt history are stored in the New "
    "Quizzes service, and Canvas's documented REST API does not expose them to "
    "students. Only the Canvas assignment record is shown; open the quiz in "
    "Canvas for the rest."
)

_HTTP_STATUS = re.compile(r"HTTP error: (\d{3})")


def _http_status(error: object) -> int | None:
    """The HTTP status carried by a client error string, if any."""
    match = _HTTP_STATUS.search(str(error))
    return int(match.group(1)) if match else None


def _explain_error(error: object, what: str) -> str:
    """One sentence that tells a student what a Canvas refusal most likely means.

    Canvas answers an action the caller's role may not perform with 401 (not
    403), so a 401 is not necessarily a bad token. A hidden Quizzes page answers
    404 with "That page has been disabled for this course" (``tab_enabled?`` in
    canvas-lms ``application_controller.rb``).
    """
    status = _http_status(error)
    if status == 401:
        hint = (
            f"Canvas refused to show {what} (401 Unauthorized). Either the token "
            "is invalid or expired, or your role in this course may not view it "
            "(for example it is unpublished or not assigned to you)."
        )
    elif status == 403:
        hint = f"Canvas refused to show {what} (403 Forbidden) for your role in this course."
    elif status == 404:
        hint = (
            f"Canvas could not find {what} (404). The course or item may not "
            "exist or be visible to you, or the instructor has hidden the "
            "Quizzes page in this course."
        )
    else:
        hint = f"Could not fetch {what}."
    return f"{hint} Details: {error}"


def _is_error(response: object) -> bool:
    return isinstance(response, dict) and "error" in response


def _is_new_quiz(assignment: dict[str, Any]) -> bool:
    """Whether a Canvas assignment record is a New Quiz.

    Primary signal: ``is_quiz_lti_assignment`` (present, and true, only for
    Quizzes-LTI assignments). Fallback for serializers that omit it: an
    ``external_tool`` assignment launching an Instructure-hosted ``quiz-lti``
    host, which is where New Quizzes is served from. ``is_quiz_assignment`` is
    deliberately not consulted; see the module docstring.
    """
    if assignment.get("is_quiz_lti_assignment") is True:
        return True
    if "external_tool" not in (assignment.get("submission_types") or []):
        return False
    tag = assignment.get("external_tool_tag_attributes") or {}
    url = tag.get("url") if isinstance(tag, dict) else None
    if not isinstance(url, str):
        return False
    host = (urlsplit(url).hostname or "").lower()
    return "quiz-lti" in host and host.endswith(".instructure.com")


def _is_classic_quiz_assignment(assignment: dict[str, Any]) -> bool:
    """A graded Classic quiz's assignment shell (carries its ``quiz_id``)."""
    return (
        "online_quiz" in (assignment.get("submission_types") or [])
        and assignment.get("quiz_id") is not None
    )


def _due_sort_key(record: dict[str, Any]) -> tuple[int, datetime]:
    """Earliest due date first; undated items last."""
    due = parse_date(record.get("due_at"))
    if due is None:
        return (1, datetime.max.replace(tzinfo=UTC))
    return (0, due)


def _fmt_points(value: object) -> str:
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _date_line(record: dict[str, Any]) -> str:
    due = format_date(record["due_at"]) if record.get("due_at") else "no due date"
    parts = [f"Due: {due}"]
    if record.get("unlock_at"):
        parts.append(f"Opens: {format_date(record['unlock_at'])}")
    if record.get("lock_at"):
        parts.append(f"Closes: {format_date(record['lock_at'])}")
    return " | ".join(parts)


def _yes_no(value: object) -> str:
    return "yes" if value else "no"


def _attempts_allowed(value: object) -> str:
    if value is None:
        return "not reported"
    if isinstance(value, int) and value < 0:
        return "unlimited"
    return str(value)


def _lock_line(record: dict[str, Any]) -> str | None:
    """The 'locked for you' line, or None when Canvas did not say it is locked.

    ``lock_explanation`` is Canvas-generated but can embed a module name the
    instructor wrote, so it is fenced as an inline label.
    """
    if not record.get("locked_for_user"):
        return None
    explanation = record.get("lock_explanation")
    if explanation:
        return (
            "Locked for you: yes, "
            f"{fence_untrusted_inline(explanation, 'lock explanation')}"
        )
    return "Locked for you: yes"


def _describe_assignment_submission(
    submission: object, points_possible: object
) -> str:
    """The caller's own gradebook submission for a quiz's assignment shell."""
    if not isinstance(submission, dict) or not submission:
        return "no submission record returned"
    if submission.get("excused"):
        return "excused"
    parts = []
    if submission.get("submitted_at"):
        parts.append(f"submitted {format_date(submission['submitted_at'])}")
    else:
        parts.append("not submitted")
    if submission.get("workflow_state") == "pending_review":
        parts.append("pending review")
    score = submission.get("score")
    if score is not None:
        total = f"/{_fmt_points(points_possible)}" if points_possible is not None else ""
        parts.append(f"score {_fmt_points(score)}{total}")
    if submission.get("late"):
        parts.append("late")
    if submission.get("missing"):
        parts.append("marked missing")
    return ", ".join(parts)


def _classic_quiz_block(
    quiz: dict[str, Any], assignment: dict[str, Any] | None
) -> list[str]:
    title = fence_untrusted_inline(quiz.get("title") or "Untitled quiz", "quiz title")
    quiz_type = _QUIZ_TYPE_LABELS.get(quiz.get("quiz_type"), quiz.get("quiz_type") or "unknown type")
    head = f"  Quiz ID: {quiz.get('id')} | Type: {quiz_type}"
    if quiz.get("published") is not None:
        head += f" | Published: {_yes_no(quiz.get('published'))}"
    time_limit = quiz.get("time_limit")
    details = [
        f"Time limit: {time_limit} min" if time_limit else "Time limit: none",
        f"Attempts allowed: {_attempts_allowed(quiz.get('allowed_attempts'))}",
    ]
    if quiz.get("points_possible") is not None:
        details.append(f"Points: {_fmt_points(quiz['points_possible'])}")
    lines = [f"• {title}", head, f"  {_date_line(quiz)}", f"  {' | '.join(details)}"]
    lock = _lock_line(quiz)
    if lock:
        lines.append(f"  {lock}")
    if assignment is not None:
        lines.append(
            "  Your submission: "
            + _describe_assignment_submission(
                assignment.get("submission"), assignment.get("points_possible")
            )
        )
    return lines


def _new_quiz_block(assignment: dict[str, Any]) -> list[str]:
    name = fence_untrusted_inline(assignment.get("name") or "Untitled quiz", "quiz title")
    head = f"  Assignment ID: {assignment.get('id')}"
    if assignment.get("points_possible") is not None:
        head += f" | Points: {_fmt_points(assignment['points_possible'])}"
    if assignment.get("published") is not None:
        head += f" | Published: {_yes_no(assignment.get('published'))}"
    lines = [f"• {name}", head, f"  {_date_line(assignment)}"]
    lock = _lock_line(assignment)
    if lock:
        lines.append(f"  {lock}")
    lines.append(
        "  Your submission: "
        + _describe_assignment_submission(
            assignment.get("submission"), assignment.get("points_possible")
        )
    )
    return lines


def _attempt_summary(
    own: list[dict[str, Any]], quiz: dict[str, Any]
) -> list[str]:
    """Attempts used/remaining, kept score, in-progress state and history.

    ``attempts_left`` is Canvas's own figure (``allowed_attempts - attempt +
    extra_attempts``, or -1 for unlimited) and is preferred over recomputing it.
    """
    attempts = [s for s in own if s.get("workflow_state") not in _NON_ATTEMPT_STATES]
    latest_any = max(own, key=lambda s: s.get("attempt") or 0) if own else {}
    latest = max(attempts, key=lambda s: s.get("attempt") or 0) if attempts else {}
    used = (latest.get("attempt") or 0) if latest else 0
    allowed = quiz.get("allowed_attempts")

    left = latest_any.get("attempts_left") if latest_any else None
    if left is None and isinstance(allowed, int):
        if allowed < 0:
            left = -1
        else:
            granted = (latest_any.get("extra_attempts") or 0) if latest_any else 0
            left = max(0, allowed - used + granted)

    if isinstance(left, int) and left < 0:
        usage = f"Attempts used: {used} (unlimited attempts allowed)"
    elif isinstance(left, int):
        usage = f"Attempts used: {used}, remaining: {left}"
        if isinstance(allowed, int) and allowed >= 0:
            usage = f"Attempts used: {used} of {allowed}, remaining: {left}"
        extra = latest_any.get("extra_attempts") if latest_any else None
        if extra:
            usage += f" (includes {extra} extra granted by your instructor)"
    else:
        usage = f"Attempts used: {used} (remaining attempts not reported by Canvas)"
    lines = [usage]

    points = quiz.get("points_possible")
    total = f"/{_fmt_points(points)}" if points is not None else ""
    kept = latest.get("kept_score") if latest else None
    if kept is not None:
        policy = _SCORING_POLICY_LABELS.get(quiz.get("scoring_policy"), "")
        suffix = f" ({policy})" if policy else ""
        lines.append(f"Kept score: {_fmt_points(kept)}{total}{suffix}")
    elif used:
        lines.append("Kept score: not available (results may be hidden or not yet graded)")

    in_progress = [s for s in attempts if s.get("workflow_state") == "untaken"]
    for current in in_progress:
        line = f"In progress: attempt {current.get('attempt')}"
        if current.get("started_at"):
            line += f", started {format_date(current['started_at'])}"
        if current.get("end_at"):
            line += f", must be submitted by {format_date(current['end_at'])}"
        if current.get("overdue_and_needs_submission"):
            line += " (past its end time; Canvas will submit it automatically)"
        lines.append(line)

    finished = sorted(
        (s for s in attempts if s.get("workflow_state") in _FINISHED_STATES),
        key=lambda s: s.get("attempt") or 0,
    )
    if finished:
        lines.append("History:")
        for record in finished:
            score = record.get("score")
            score_text = (
                f"score {_fmt_points(score)}{total}" if score is not None else "score not available"
            )
            entry = f"  • Attempt {record.get('attempt')}: {score_text}"
            if record.get("workflow_state") == "pending_review":
                entry += ", pending review"
            if record.get("finished_at"):
                entry += f", finished {format_date(record['finished_at'])}"
            spent = record.get("time_spent")
            if isinstance(spent, int | float):
                entry += (
                    f", time spent {round(spent / 60)} min"
                    if spent >= 60 else f", time spent {int(spent)} s"
                )
            lines.append(entry)
    elif not in_progress:
        lines.append("You have not started this quiz.")
    return lines


def register_student_quiz_tools(mcp: FastMCP) -> None:
    """Register the read-only student quiz tools."""

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    @validate_params
    async def list_quizzes(course_identifier: str | int) -> str:
        """List the quizzes in one of YOUR courses: Classic and New Quizzes.

        Read-only. Shows due/open/close dates, time limit, allowed attempts,
        points and your submission state. It never opens a quiz, starts an
        attempt, or reads questions or answers.

        Classic quizzes are listed by quiz ID; New Quizzes by assignment ID
        (Canvas exposes them only as assignments). Use get_quiz_details for one
        quiz and your attempts.

        Args:
            course_identifier: Course code or Canvas ID
        """
        course_id = await get_course_id(course_identifier)
        if not course_id:
            return f"Error: Could not find course {course_identifier}"

        classic = await fetch_all_paginated_results(
            f"/courses/{course_id}/quizzes", {"per_page": 100}
        )
        assignments = await fetch_all_paginated_results(
            f"/courses/{course_id}/assignments",
            {"include[]": ["submission"], "per_page": 100},
        )

        classic_failed = _is_error(classic) or not isinstance(classic, list)
        assignments_failed = _is_error(assignments) or not isinstance(assignments, list)

        if classic_failed and assignments_failed:
            classic_err = classic.get("error") if isinstance(classic, dict) else classic
            assignment_err = (
                assignments.get("error") if isinstance(assignments, dict) else assignments
            )
            return (
                "Error: could not list quizzes for this course.\n"
                f"- Classic quizzes: {_explain_error(classic_err, 'the quiz list')}\n"
                f"- New Quizzes (assignments): {_explain_error(assignment_err, 'the assignment list')}"
            )

        assignment_list: list[dict[str, Any]] = (
            [a for a in assignments if isinstance(a, dict)] if not assignments_failed else []
        )
        by_quiz_id = {
            str(a["quiz_id"]): a for a in assignment_list if _is_classic_quiz_assignment(a)
        }
        new_quizzes = sorted(
            (a for a in assignment_list if _is_new_quiz(a)), key=_due_sort_key
        )

        course_display = await get_course_code(course_id) or course_identifier
        lines = [f"Quizzes for {course_display}:", ""]

        if not classic_failed:
            quizzes = sorted((q for q in classic if isinstance(q, dict)), key=_due_sort_key)
            lines.append(f"Classic Quizzes ({len(quizzes)}):")
            if not quizzes:
                lines.append("  none visible to you")
            for quiz in quizzes:
                lines.extend(_classic_quiz_block(quiz, by_quiz_id.get(str(quiz.get("id")))))
        else:
            classic_err = classic.get("error") if isinstance(classic, dict) else classic
            lines.append(f"Classic Quizzes: {_explain_error(classic_err, 'the quiz list')}")
            # A hidden Quizzes page does not hide graded quizzes from the
            # assignment list, so the student still sees their deadlines.
            shells = sorted(by_quiz_id.values(), key=_due_sort_key)
            if shells:
                lines.append(
                    f"Graded Classic quizzes found in the assignment list ({len(shells)}); "
                    "practice quizzes and surveys cannot be listed this way:"
                )
                for shell in shells:
                    name = fence_untrusted_inline(shell.get("name") or "Untitled quiz", "quiz title")
                    lines.append(f"• {name}")
                    lines.append(f"  Quiz ID: {shell.get('quiz_id')} | Assignment ID: {shell.get('id')}")
                    lines.append(f"  {_date_line(shell)}")
                    lines.append(
                        "  Your submission: "
                        + _describe_assignment_submission(
                            shell.get("submission"), shell.get("points_possible")
                        )
                    )

        lines.append("")
        if not assignments_failed:
            lines.append(f"New Quizzes ({len(new_quizzes)}):")
            if not new_quizzes:
                lines.append("  none visible to you")
            for assignment in new_quizzes:
                lines.extend(_new_quiz_block(assignment))
            if new_quizzes:
                lines.append(
                    "  (Time limits and allowed attempts for New Quizzes are not "
                    "available to students through the Canvas API.)"
                )
        else:
            assignment_err = (
                assignments.get("error") if isinstance(assignments, dict) else assignments
            )
            lines.append(
                "New Quizzes: unknown. "
                + _explain_error(assignment_err, "the assignment list")
            )

        lines.append("")
        lines.append(
            "For your attempts on one quiz, use get_quiz_details with quiz_id "
            "(Classic) or assignment_id (New Quizzes)."
        )
        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    @validate_params
    async def get_quiz_details(
        course_identifier: str | int,
        quiz_id: str | int | None = None,
        assignment_id: str | int | None = None,
    ) -> str:
        """Get one quiz's settings and YOUR OWN attempts (used, remaining, kept score).

        Read-only. It never starts an attempt and never reads questions or
        answers. Pass exactly one of quiz_id (a Classic quiz, as listed by
        list_quizzes) or assignment_id (a New Quiz, or the assignment of a
        graded Classic quiz). For New Quizzes Canvas does not expose settings
        or attempt history to students, and the result says so.

        Args:
            course_identifier: Course code or Canvas ID
            quiz_id: Canvas Classic quiz ID
            assignment_id: Canvas assignment ID (New Quizzes)
        """
        if quiz_id is not None and assignment_id is None:
            which, raw_id = "quiz_id", quiz_id
        elif assignment_id is not None and quiz_id is None:
            which, raw_id = "assignment_id", assignment_id
        else:
            return (
                "Error: pass exactly one of quiz_id (Classic quiz) or "
                "assignment_id (New Quiz). list_quizzes shows which applies."
            )
        # IDs are interpolated into request paths, so anything but plain digits
        # is refused before a request is built.
        checked_id = coerce_canvas_id(raw_id)
        if checked_id is None:
            return f"Error: {which} must be a numeric Canvas ID. Use list_quizzes to find it."

        course_id = await get_course_id(course_identifier)
        if not course_id:
            return f"Error: Could not find course {course_identifier}"
        course_display = await get_course_code(course_id) or course_identifier

        assignment: dict[str, Any] | None = None
        if assignment_id is not None:
            response = await make_canvas_request(
                "get",
                f"/courses/{course_id}/assignments/{checked_id}",
                params={"include[]": ["submission"]},
            )
            if _is_error(response) or not isinstance(response, dict):
                detail = response.get("error") if isinstance(response, dict) else response
                return "Error: " + _explain_error(detail, f"assignment {checked_id}")
            assignment = response

            if _is_new_quiz(assignment):
                lines = [f"New Quiz in {course_display}:"]
                lines.extend(_new_quiz_block(assignment))
                description = assignment.get("description")
                if description:
                    lines.append("Description:")
                    lines.append(fence_untrusted(description, "quiz description"))
                attempt = (assignment.get("submission") or {}).get("attempt")
                if attempt:
                    lines.append(
                        f"Canvas submission attempt number: {attempt} (as recorded "
                        "in the Canvas gradebook; it may not match the New Quizzes "
                        "attempt count)"
                    )
                if assignment.get("html_url"):
                    lines.append(f"Open in Canvas: {assignment['html_url']}")
                lines.append("")
                lines.append(_NEW_QUIZZES_NOTE)
                return "\n".join(lines)

            if not _is_classic_quiz_assignment(assignment):
                types = ", ".join(assignment.get("submission_types") or []) or "none"
                return (
                    f"Error: assignment {checked_id} is not a quiz (submission "
                    f"types: {types}). Use get_my_submission for ordinary assignments."
                )
            linked = coerce_canvas_id(assignment["quiz_id"])
            if linked is None:
                return f"Error: assignment {checked_id} names an invalid quiz ID."
            checked_id = linked

        quiz = await make_canvas_request("get", f"/courses/{course_id}/quizzes/{checked_id}")
        if _is_error(quiz) or not isinstance(quiz, dict):
            detail = quiz.get("error") if isinstance(quiz, dict) else quiz
            message = "Error: " + _explain_error(detail, f"quiz {checked_id}")
            if quiz_id is not None and _http_status(detail) == 404:
                message += (
                    "\nIf this is a New Quiz, pass its assignment_id instead "
                    "(list_quizzes shows it)."
                )
            return message

        quiz_type = _QUIZ_TYPE_LABELS.get(quiz.get("quiz_type"), quiz.get("quiz_type") or "unknown type")
        lines = [
            f"Classic quiz in {course_display}: "
            f"{fence_untrusted_inline(quiz.get('title') or 'Untitled quiz', 'quiz title')}",
            f"Quiz ID: {quiz.get('id')} | Type: {quiz_type}"
            + (f" | Assignment ID: {quiz['assignment_id']}" if quiz.get("assignment_id") else ""),
            _date_line(quiz),
        ]
        time_limit = quiz.get("time_limit")
        settings = [
            f"Time limit: {time_limit} min" if time_limit else "Time limit: none",
            f"Attempts allowed: {_attempts_allowed(quiz.get('allowed_attempts'))}",
        ]
        if quiz.get("points_possible") is not None:
            settings.append(f"Points: {_fmt_points(quiz['points_possible'])}")
        if quiz.get("question_count") is not None:
            settings.append(f"Questions: {quiz['question_count']}")
        lines.append(" | ".join(settings))
        if quiz.get("allowed_attempts") not in (None, 1) and quiz.get("scoring_policy"):
            lines.append(
                "Scoring: "
                + _SCORING_POLICY_LABELS.get(quiz["scoring_policy"], quiz["scoring_policy"])
            )
        if quiz.get("published") is not None:
            lines.append(f"Published: {_yes_no(quiz.get('published'))}")
        if quiz.get("has_access_code"):
            lines.append("Requires an access code from your instructor.")
        if quiz.get("require_lockdown_browser"):
            lines.append("Requires LockDown Browser.")
        if quiz.get("one_time_results"):
            lines.append("Results can be viewed only once after each attempt.")
        if quiz.get("hide_results") == "always":
            lines.append("Results are hidden from students.")
        elif quiz.get("hide_results") == "until_after_last_attempt":
            lines.append("Results are shown only after your last attempt.")
        lock = _lock_line(quiz)
        if lock:
            lines.append(lock)
        if assignment is not None:
            lines.append(
                "Your gradebook submission: "
                + _describe_assignment_submission(
                    assignment.get("submission"), assignment.get("points_possible")
                )
            )
        description = quiz.get("description")
        if description:
            lines.append("Description:")
            lines.append(fence_untrusted(description, "quiz description"))
        if quiz.get("html_url"):
            lines.append(f"Open in Canvas: {quiz['html_url']}")

        lines.append("")
        lines.append("Your attempts:")
        me = await make_canvas_request("get", "/users/self")
        if not isinstance(me, dict) or _is_error(me) or me.get("id") is None:
            detail = me.get("error") if isinstance(me, dict) else me
            lines.append(f"Could not identify you to read your attempts: {detail}")
            return "\n".join(lines)

        # For a caller who can only submit, Canvas returns that caller's own
        # attempts as one unpaginated list (the in-progress attempt, or every
        # submitted attempt); see QuizSubmissionsApiController#index. A token
        # with grading rights instead gets a paginated list of OTHER students'
        # records, never its own, which is why records are filtered to the
        # caller's id and the rest are counted but never shown.
        response = await make_canvas_request(
            "get", f"/courses/{course_id}/quizzes/{checked_id}/submissions"
        )
        if _is_error(response) or not isinstance(response, dict):
            detail = response.get("error") if isinstance(response, dict) else response
            lines.append(_explain_error(detail, "your quiz attempts"))
            return "\n".join(lines)

        records = [r for r in response.get("quiz_submissions") or [] if isinstance(r, dict)]
        my_id = str(me["id"])
        own = [r for r in records if str(r.get("user_id")) == my_id]
        others = len(records) - len(own)
        lines.extend(_attempt_summary(own, quiz))
        if others:
            lines.append(
                f"Canvas also returned {others} quiz submission(s) belonging to "
                "other users (your token can view grades in this course); they "
                "are not shown."
            )
        return "\n".join(lines)
