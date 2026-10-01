"""Pure reproduction of Canvas's course-grade arithmetic (no I/O).

The student grade tools (``tools/student_grades.py``) fetch a course's
assignment groups with the caller's own submissions and hand them to this
module. Keeping the arithmetic here, free of HTTP and formatting, lets the
tests pin it against hand-checked examples.

What is reproduced, following Canvas's client-side grade calculator
(``ui/shared/grading/AssignmentGroupGradeCalculator.ts`` and
``CourseGradeCalculator.ts`` in canvas-lms):

- An assignment counts only when it is published, graded (not
  ``not_graded``) and not ``omit_from_final_grade``. Excused submissions are
  removed before anything else.
- The **current** grade uses graded work only: a submission with no score, or
  one in ``pending_review``, is left out. The **final** grade counts every
  remaining assignment, an ungraded one as 0.
- Drop rules (``drop_lowest``, ``drop_highest``, ``never_drop``) apply per
  group to whatever survived the step above. Canvas does not drop the lowest
  *percentages*: it keeps the subset whose combined score/possible ratio is
  best (worst, for ``drop_highest``), solved as a fractional optimization.
  Canvas bisects on the ratio; this module uses Dinkelbach's iteration, which
  reaches the same optimum exactly. Exact ties can resolve to a different but
  equally scored subset.
- Weighted groups: groups with zero points possible are left out, the rest
  contribute ``score / possible * weight``, and the sum is rescaled to 100 only
  when the counted weights total less than 100 (weights above 100 act as extra
  credit). No counted weight means no grade.
- Unweighted: total score over total points possible.

Not reproduced: grading-period weighting, and anything a student cannot see
(unposted grades, assignments not assigned to them). Callers must say so.
"""

import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

# Canvas's built-in scheme (GradingStandard.default_grading_standard), used
# when a course has no scheme of its own or the caller cannot read it.
CANVAS_DEFAULT_SCHEME: tuple[tuple[str, float], ...] = (
    ("A", 0.94),
    ("A-", 0.90),
    ("B+", 0.87),
    ("B", 0.84),
    ("B-", 0.80),
    ("C+", 0.77),
    ("C", 0.74),
    ("C-", 0.70),
    ("D+", 0.67),
    ("D", 0.64),
    ("D-", 0.61),
    ("F", 0.0),
)

# Canvas stores course scores rounded to two decimals and assigns the letter
# from that rounded score, so letter_for_percent rounds first. Targets are
# deliberately stricter: the requirement is computed so the UNROUNDED grade
# reaches the target, which can ask for 0.01 points more than strictly needed
# but never tells a student a score is enough when it is not.
SCORE_DECIMALS = 2
_RATIO_EPSILON = 1e-12


@dataclass(frozen=True)
class GradedItem:
    """One assignment as the grade calculation sees it."""

    assignment_id: str
    group_id: str
    points_possible: float
    score: float | None = None
    excused: bool = False
    pending_review: bool = False
    counts_toward_grade: bool = True

    @property
    def is_graded(self) -> bool:
        """Has a visible score that Canvas's current grade would use."""
        return self.score is not None and not self.pending_review


@dataclass(frozen=True)
class GroupRules:
    """An assignment group's weight and drop rules."""

    group_id: str
    weight: float = 0.0
    drop_lowest: int = 0
    drop_highest: int = 0
    never_drop: frozenset[str] = frozenset()


@dataclass(frozen=True)
class GroupGrade:
    """Result for one assignment group."""

    group_id: str
    weight: float
    score: float
    possible: float
    kept: tuple[str, ...]
    dropped: tuple[str, ...]

    @property
    def percent(self) -> float | None:
        if self.possible > 0:
            return self.score / self.possible * 100
        return None


@dataclass(frozen=True)
class CourseGrade:
    """Result for the whole course."""

    percent: float | None
    weighted: bool
    groups: tuple[GroupGrade, ...]
    # Weighted: total weight of the groups that counted. Unweighted: unused.
    counted_weight: float = 0.0


@dataclass(frozen=True)
class _Entry:
    assignment_id: str
    score: float
    total: float
    order: int


def _ratio(entries: Iterable[_Entry], extra_score: float, extra_total: float) -> float | None:
    entries = list(entries)
    total = sum(e.total for e in entries) + extra_total
    if total <= 0:
        return None
    return (sum(e.score for e in entries) + extra_score) / total


def _keep_by_ratio(
    candidates: Sequence[_Entry],
    cant_drop: Sequence[_Entry],
    keep_count: int,
    maximize: bool,
) -> list[_Entry]:
    """Keep ``keep_count`` candidates with the best (or worst) combined ratio.

    The never-drop entries are part of the ratio but are never candidates.
    Dinkelbach's method: rank by ``score - q * total`` for the current ratio q,
    keep the top ``keep_count``, recompute q from that set, and repeat until q
    stops moving. Each step improves q monotonically, and there are finitely
    many subsets, so it terminates at the optimum.
    """
    keep_count = max(1, keep_count)
    if len(candidates) <= keep_count:
        return list(candidates)

    cant_score = sum(e.score for e in cant_drop)
    cant_total = sum(e.total for e in cant_drop)

    def choose(q: float) -> list[_Entry]:
        # sorted() is stable with reverse=True too, so equal values keep
        # assignment order, matching Canvas's stable sort.
        ranked = sorted(candidates, key=lambda e: e.score - q * e.total, reverse=maximize)
        return ranked[:keep_count]

    start = _ratio(candidates, cant_score, cant_total)
    chosen = choose(start if start is not None else 0.0)
    q = _ratio(chosen, cant_score, cant_total)
    # A chosen set with no points possible (only zero-point extra credit, and
    # no never-drop points) has no ratio; Canvas keeps it as is too.
    for _ in range(1000):
        if q is None:
            break
        nxt = choose(q)
        new_q = _ratio(nxt, cant_score, cant_total)
        if new_q is None:
            chosen = nxt
            break
        improved = new_q > q + _RATIO_EPSILON if maximize else new_q < q - _RATIO_EPSILON
        if not improved:
            break
        chosen, q = nxt, new_q
    return sorted(chosen, key=lambda e: e.order)


def _assignment_sort_key(assignment_id: str) -> tuple[int, str]:
    # Numeric IDs compare numerically without mixing int and str in a key.
    return (len(assignment_id), assignment_id) if assignment_id.isdigit() else (1 << 30, assignment_id)


def drop_assignments(
    entries: Sequence[_Entry],
    drop_lowest: int = 0,
    drop_highest: int = 0,
    never_drop: frozenset[str] = frozenset(),
) -> tuple[list[_Entry], list[_Entry]]:
    """Apply a group's drop rules. Returns (kept, dropped), kept in input order.

    Clamping follows Canvas: at least one droppable entry is always kept, and
    ``drop_highest`` is ignored when it and ``drop_lowest`` together would
    leave nothing.
    """
    drop_lowest = max(0, int(drop_lowest or 0))
    drop_highest = max(0, int(drop_highest or 0))
    if not (drop_lowest or drop_highest):
        return list(entries), []

    cant = [e for e in entries if e.assignment_id in never_drop]
    droppable = [e for e in entries if e.assignment_id not in never_drop]
    if not droppable:
        return list(entries), []

    n = len(droppable)
    drop_lowest = min(drop_lowest, n - 1)
    if drop_lowest + drop_highest >= n:
        drop_highest = 0
    keep_highest = n - drop_lowest
    keep_lowest = keep_highest - drop_highest

    if any(e.total > 0 for e in droppable):
        kept_high = _keep_by_ratio(droppable, cant, keep_highest, maximize=True)
        kept = _keep_by_ratio(kept_high, cant, keep_lowest, maximize=False)
    else:
        # Nothing has points possible: plain score order, ID as tie-break.
        ordered = sorted(droppable, key=lambda e: (e.score, _assignment_sort_key(e.assignment_id)))
        kept = ordered[len(ordered) - keep_highest:][:keep_lowest]

    kept_orders = {e.order for e in kept}
    kept_all = sorted([*kept, *cant], key=lambda e: e.order)
    dropped = [e for e in droppable if e.order not in kept_orders]
    return kept_all, dropped


def calculate_group(
    rules: GroupRules, items: Sequence[GradedItem], include_ungraded: bool
) -> GroupGrade:
    """Score one group: filter, drop, then sum."""
    entries: list[_Entry] = []
    for order, item in enumerate(items):
        if item.group_id != rules.group_id or not item.counts_toward_grade or item.excused:
            continue
        if not include_ungraded and not item.is_graded:
            continue
        score = item.score if item.score is not None else 0.0
        entries.append(_Entry(item.assignment_id, score, max(item.points_possible, 0.0), order))

    kept, dropped = drop_assignments(
        entries, rules.drop_lowest, rules.drop_highest, rules.never_drop
    )
    return GroupGrade(
        group_id=rules.group_id,
        weight=rules.weight or 0.0,
        score=sum(e.score for e in kept),
        possible=sum(e.total for e in kept),
        kept=tuple(e.assignment_id for e in kept),
        dropped=tuple(e.assignment_id for e in dropped),
    )


def calculate_course(
    groups: Sequence[GroupRules],
    items: Sequence[GradedItem],
    weighted: bool,
    include_ungraded: bool = False,
) -> CourseGrade:
    """Course percentage the way Canvas computes it (unrounded)."""
    group_grades = tuple(calculate_group(g, items, include_ungraded) for g in groups)

    if weighted:
        relevant = [g for g in group_grades if g.possible > 0]
        full_weight = sum(g.weight for g in relevant)
        if full_weight == 0:
            return CourseGrade(None, True, group_grades, 0.0)
        total = sum(g.score / g.possible * g.weight for g in relevant)
        if full_weight < 100:
            total = total * 100 / full_weight
        return CourseGrade(total, True, group_grades, full_weight)

    score = sum(g.score for g in group_grades)
    possible = sum(g.possible for g in group_grades)
    percent = score / possible * 100 if possible > 0 else None
    return CourseGrade(percent, False, group_grades)


def apply_hypothetical_scores(
    items: Sequence[GradedItem], scores: Mapping[str, float]
) -> list[GradedItem]:
    """Replace scores as if graded (the student's what-if)."""
    return [
        replace(item, score=float(scores[item.assignment_id]), excused=False, pending_review=False)
        if item.assignment_id in scores
        else item
        for item in items
    ]


def remaining_items(items: Sequence[GradedItem]) -> list[GradedItem]:
    """Counted, non-excused, still-ungraded assignments worth points."""
    return [
        item
        for item in items
        if item.counts_toward_grade
        and not item.excused
        and not item.is_graded
        and item.points_possible > 0
    ]


def project_uniform(
    groups: Sequence[GroupRules],
    items: Sequence[GradedItem],
    weighted: bool,
    percent_on_remaining: float,
) -> CourseGrade:
    """Course grade if every remaining assignment scored the same percent."""
    remaining = {item.assignment_id for item in remaining_items(items)}
    fraction = percent_on_remaining / 100
    filled = [
        replace(item, score=fraction * item.points_possible, pending_review=False)
        if item.assignment_id in remaining
        else item
        for item in items
    ]
    return calculate_course(groups, filled, weighted, include_ungraded=False)


@dataclass(frozen=True)
class TargetResult:
    """Uniform percent needed on remaining work to reach a target."""

    target_percent: float
    remaining_ids: tuple[str, ...]
    remaining_points: float
    # Lowest uniform percent (0.01 resolution) that reaches the target, or
    # None when even ``max_percent`` does not.
    required_percent: float | None
    projected_at_zero: float | None
    projected_at_full: float | None

    @property
    def already_secured(self) -> bool:
        return self.required_percent == 0.0

    @property
    def needs_extra_credit(self) -> bool:
        return self.required_percent is not None and self.required_percent > 100


def _meets(percent: float | None, target: float) -> bool:
    return percent is not None and percent >= target - 1e-9


def required_uniform_percent(
    groups: Sequence[GroupRules],
    items: Sequence[GradedItem],
    weighted: bool,
    target_percent: float,
    max_percent: float = 200.0,
) -> TargetResult:
    """Lowest uniform percent on all remaining work that reaches the target.

    The course grade rises with the score on remaining work (drop rules can
    make it step rather than slide), so the threshold is found by bisection
    and then checked directly.
    """
    remaining = remaining_items(items)
    remaining_ids = tuple(item.assignment_id for item in remaining)
    remaining_points = sum(item.points_possible for item in remaining)

    def grade_at(p: float) -> float | None:
        return project_uniform(groups, items, weighted, p).percent

    at_zero = grade_at(0.0)
    at_full = grade_at(100.0)

    def result(required: float | None) -> TargetResult:
        return TargetResult(
            target_percent=target_percent,
            remaining_ids=remaining_ids,
            remaining_points=remaining_points,
            required_percent=required,
            projected_at_zero=at_zero,
            projected_at_full=at_full,
        )

    if not remaining:
        return result(0.0 if _meets(at_zero, target_percent) else None)
    if _meets(at_zero, target_percent):
        return result(0.0)

    if _meets(at_full, target_percent):
        low, high = 0.0, 100.0
    elif _meets(grade_at(max_percent), target_percent):
        low, high = 100.0, max_percent
    else:
        return result(None)

    for _ in range(60):
        mid = (low + high) / 2
        if _meets(grade_at(mid), target_percent):
            high = mid
        else:
            low = mid
    # Round UP to the reporting resolution, then make sure that value works.
    required = math.ceil(high * 100 - 1e-9) / 100
    while not _meets(grade_at(required), target_percent) and required < max_percent:
        required = round(required + 0.01, 2)
    return result(required)


# --------------------------------------------------------------------------
# Letter grades
# --------------------------------------------------------------------------


def parse_grading_scheme(
    data: Any, scaling_factor: float | None = None
) -> tuple[tuple[str, float], ...] | None:
    """Normalize a Canvas grading scheme to ((name, lower_bound_fraction), ...).

    Accepts the course API's ``grading_scheme`` (``[["A", 0.94], ...]``) and the
    grading standards API's (``[{"name": "A", "value": 0.94}, ...]``). A points
    based scheme whose bounds are given in points is converted with its
    ``scaling_factor``. Returns None for anything that does not look like a
    scheme, so the caller falls back to Canvas's default.
    """
    if not isinstance(data, list) or not data:
        return None
    entries: list[tuple[str, float]] = []
    for row in data:
        if isinstance(row, Mapping):
            name, value = row.get("name"), row.get("value")
        elif isinstance(row, (list, tuple)) and len(row) == 2:
            name, value = row
        else:
            return None
        if not isinstance(name, str) or not name.strip():
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        if not math.isfinite(value) or value < 0:
            return None
        entries.append((name, float(value)))
    if scaling_factor and scaling_factor > 1 and any(v > 1 for _, v in entries):
        entries = [(n, v / scaling_factor) for n, v in entries]
    if any(v > 1.0 + 1e-9 for _, v in entries):
        return None
    entries.sort(key=lambda e: e[1], reverse=True)
    return tuple(entries)


def letter_for_percent(
    percent: float | None, scheme: Sequence[tuple[str, float]]
) -> str | None:
    """Letter for a course percentage: the highest bound it reaches."""
    if percent is None or not scheme:
        return None
    rounded = round(percent, SCORE_DECIMALS)
    for name, lower in scheme:
        if rounded >= round(lower * 100, 6) - 1e-9:
            return name
    return scheme[-1][0]


def find_letter(
    letter: str, scheme: Sequence[tuple[str, float]]
) -> tuple[str, float] | None:
    """(scheme name, lower-bound percent) for ``letter``: exact match first,
    then a unique case-insensitive one. None when the scheme has no such letter."""
    wanted = letter.strip()
    for name, lower in scheme:
        if name == wanted:
            return name, round(lower * 100, 6)
    folded = [(name, lower) for name, lower in scheme if name.strip().casefold() == wanted.casefold()]
    if len(folded) == 1:
        return folded[0][0], round(folded[0][1] * 100, 6)
    return None


# --------------------------------------------------------------------------
# Canvas JSON -> model
# --------------------------------------------------------------------------


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def own_submission(assignment: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """The caller's submission embedded by ``include[]=submission``.

    Canvas embeds one object for a student. A list appears for observers;
    only an unambiguous single entry is used.
    """
    submission = assignment.get("submission")
    if isinstance(submission, Mapping):
        return submission
    if isinstance(submission, list) and len(submission) == 1:
        only = submission[0]
        if isinstance(only, Mapping):
            return only
    return None


def assignment_counts(assignment: Mapping[str, Any]) -> bool:
    """Whether Canvas counts this assignment toward the course grade."""
    if assignment.get("omit_from_final_grade"):
        return False
    if assignment.get("grading_type") == "not_graded":
        return False
    if "not_graded" in (assignment.get("submission_types") or []):
        return False
    if assignment.get("workflow_state") == "unpublished" or assignment.get("published") is False:
        return False
    return True


def submission_statuses(
    assignment: Mapping[str, Any], submission: Mapping[str, Any] | None
) -> list[str]:
    """Plain-language status labels for one of the caller's assignments."""
    labels: list[str] = []
    if assignment.get("omit_from_final_grade"):
        labels.append("not counted toward final grade")
    if assignment.get("grading_type") == "not_graded" or "not_graded" in (
        assignment.get("submission_types") or []
    ):
        labels.append("not graded")
    if submission is None:
        labels.append("no submission record visible")
        return labels

    state = submission.get("workflow_state")
    score = _number(submission.get("score"))
    if submission.get("excused"):
        labels.append("excused")
    elif state == "pending_review":
        labels.append("pending review (needs manual grading)")
    elif score is not None:
        labels.append("graded")
    elif state == "graded":
        # Canvas withholds the score from students until the grade is posted.
        labels.append("grade not posted yet (hidden from you)")
    elif submission.get("missing"):
        labels.append("missing")
    elif submission.get("submitted_at"):
        labels.append("submitted, not graded yet")
    else:
        labels.append("unsubmitted")

    if score is not None and submission.get("missing"):
        labels.append("marked missing")
    if submission.get("late"):
        labels.append("late")
    deducted = _number(submission.get("points_deducted"))
    if deducted:
        labels.append(f"late penalty -{deducted:g} pts")
    return labels


def build_grade_model(
    groups_json: Sequence[Mapping[str, Any]],
) -> tuple[list[GroupRules], list[GradedItem]]:
    """Turn ``/assignment_groups?include[]=assignments&include[]=submission``
    into the calculation model. IDs become strings."""
    groups: list[GroupRules] = []
    items: list[GradedItem] = []
    for group in groups_json:
        if not isinstance(group, Mapping) or group.get("id") is None:
            continue
        group_id = str(group["id"])
        rules = group.get("rules") or {}
        if not isinstance(rules, Mapping):
            rules = {}
        never_drop = rules.get("never_drop") or []
        groups.append(
            GroupRules(
                group_id=group_id,
                weight=_number(group.get("group_weight")) or 0.0,
                drop_lowest=int(_number(rules.get("drop_lowest")) or 0),
                drop_highest=int(_number(rules.get("drop_highest")) or 0),
                never_drop=frozenset(str(a) for a in never_drop if a is not None),
            )
        )
        for assignment in group.get("assignments") or []:
            if not isinstance(assignment, Mapping) or assignment.get("id") is None:
                continue
            submission = own_submission(assignment)
            score = _number(submission.get("score")) if submission else None
            items.append(
                GradedItem(
                    assignment_id=str(assignment["id"]),
                    group_id=group_id,
                    points_possible=max(_number(assignment.get("points_possible")) or 0.0, 0.0),
                    score=score,
                    excused=bool(submission and submission.get("excused")),
                    pending_review=bool(
                        submission and submission.get("workflow_state") == "pending_review"
                    ),
                    counts_toward_grade=assignment_counts(assignment),
                )
            )
    return groups, items
