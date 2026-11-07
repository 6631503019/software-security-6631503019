"""
content.py — serve the course's own markdown (worksheets, lab READMEs) as HTML.

This is the content plane: SP-3 in instructor/FULL-PLATFORM-DESIGN.md, and the
half of "no Google" that replaces Classroom's *distribute the material* role.
Read-only, no student data, no upload.

WHY THIS DOESN'T USE A MARKDOWN LIBRARY
    Because of what is actually in these files. `labs/week05-xss-client-side/
    worksheet.md` line 56 instructs students to POST:

        <script>alert(document.cookie)</script>

    and line 61 gives them a beacon that exfiltrates the cookie to a remote URL.
    Those are course content — the exercise — and they must render as *visible
    text a student can read and copy*, never as markup the browser executes.

    Every mainstream markdown renderer passes raw HTML through by default.
    Pointing one at this repo and serving the result from the same origin as the
    teacher's authenticated session would be stored XSS, delivered by our own
    teaching material, into the account that holds every student's grade. The
    Week 5 lab would have worked on the platform that teaches it.

    So: **escape the whole document first, then apply a small whitelist of
    markdown constructs to the already-escaped text.** Nothing can pass through,
    because by the time any construct is recognised there is no live markup left
    to recognise. That ordering is the entire security argument, and
    `test_content.py` holds it in place with the real Week 5 payloads.

    The cost is a deliberately limited dialect: headings, bold/italic/code,
    fenced code, lists, tables, links, blockquotes, rules. That covers what the
    worksheets use. It does not do footnotes, definition lists or inline HTML,
    and it should not grow to.

PATH SAFETY
    Content is addressed by a slug matched against a strict pattern and resolved
    against a fixed root, then verified to still be inside it after resolution —
    a slug never becomes a path fragment that `..` can walk out of.
"""

from __future__ import annotations

import html
import json
import os
import re

# Where the weekNN-* directories live.
#
# Local dev: this module sits in labs/live-quiz/, so the default (its parent) is
# `labs/` and everything just works from a checkout.
#
# In the container the app is at /app and there is no repo above it, so the
# default would resolve to `/` and every week would 404 — which is exactly what
# the first production deploy did. The image therefore bakes the content in at
# /content and sets CONTENT_ROOT to match. (The lab solutions this copies are
# already public in the repo; the real answer keys live in git-ignored
# instructor/ and are not in the build context at all.)
CONTENT_ROOT = os.environ.get(
    "CONTENT_ROOT",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# A course's content directories. Anchored, no dots, so `..` and absolute paths
# never match — that property is load-bearing and survives every change below.
#
# The unit prefix is PER COURSE because the real courses disagree:
#   software-security       week01-threat-modeling … week19-…
#   security-cryptography   week01-intro … week14-…
#   cloud-infrastructure    lesson01-03-aws-…, lesson07b-cloudtrail-…, lesson13-…
# and cloud-infra's numbering is not even regular: a lesson can span two numbers
# (`01-03`) or carry a letter suffix (`07b`). So the number is captured as an
# opaque STRING for display and never parsed into an int — the previous
# `int(name[4:6])` was a positional slice that assumed "week" + exactly 2 digits
# and would raise on `lesson07b`.
#
# Ordering stays lexical on the directory name, which is correct precisely
# because the numbers are zero-padded: lesson04 < lesson07 < lesson07b < lesson10.
UNIT_RE_CACHE: dict[str, re.Pattern] = {}
UNIT_NAME_RE = re.compile(r"^[a-z]{2,16}$")


def unit_re(unit: str = "week") -> re.Pattern:
    if unit not in UNIT_RE_CACHE:
        if not UNIT_NAME_RE.match(unit):
            raise ValueError(f"bad unit name {unit!r}")
        UNIT_RE_CACHE[unit] = re.compile(
            rf"^{unit}(\d{{2}}[a-z]?(?:-\d{{2}})?)-([a-z0-9-]+)$")
    return UNIT_RE_CACHE[unit]


# Kept for the many callers and tests that predate multi-course: the default unit.
WEEK_RE = re.compile(r"^week\d{2}[a-z]?(?:-\d{2})?-[a-z0-9-]+$")

# ── Courses ────────────────────────────────────────────────────────────────
# The instructor teaches several courses (software-security,
# security-cryptography, cloud-infrastructure-security) rendered from one
# curriculum monorepo. This plane used to serve exactly one of them: CONTENT_ROOT
# pointed at a single repo's `labs/` and the index was titled in the template.
#
# A course is (slug, title, root). Nothing more — a course is an ordering over
# week directories, which is also all a manifest is in the monorepo.
#
# Course slugs must NOT look like a week directory. `/learn/<x>` is ambiguous
# between "course x" and the legacy "week x of the default course", and we
# disambiguate on WEEK_RE. _load_courses() rejects a slug that would collide, so
# the ambiguity can never arise from configuration.
COURSE_SLUG_RE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")


def _clean_modules(slug: str, raw) -> list[dict]:
    """Validate a course's optional `modules` declaration.

    Shape: [{"label": "Unit A — Foundations", "from": 1, "to": 3}, ...] — an
    ordered list of INCLUSIVE ranges over a unit's `number`. A course that
    declares none gets `[]` and renders exactly as it does today.

    Ranges are matched against `number`, which is NOT unique: the cloud course
    has both `lesson07` and `lesson07b`, and both carry number 7. That is the
    behaviour we want — 7 and 7b belong to the same module — but it means a
    range must never be treated as a count of units.

    Validated here, at load, rather than at render: a typo in the deployment's
    $COURSES should stop the container from starting, not silently drop a week
    out of the outline where nobody would notice it.
    """
    if not raw:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"COURSES: {slug!r} modules must be a list")
    out, hi_prev = [], None
    for m in raw:
        if not isinstance(m, dict):
            raise ValueError(f"COURSES: {slug!r} module entries must be objects")
        try:
            lo = int(m["from"])
            hi = int(m.get("to", lo))
        except (KeyError, TypeError, ValueError):
            raise ValueError(f"COURSES: {slug!r} module {m!r} needs an integer 'from'")
        if hi < lo:
            raise ValueError(f"COURSES: {slug!r} module {m!r} ends before it starts")
        # Overlap would put one unit in two modules, and the grouper resolves
        # that by first-match — i.e. silently. Refuse it instead.
        if hi_prev is not None and lo <= hi_prev:
            raise ValueError(
                f"COURSES: {slug!r} module {m!r} overlaps the previous one "
                f"(which ended at {hi_prev}); ranges must be ordered and disjoint")
        hi_prev = hi
        label = m.get("label")
        out.append({"label": str(label) if label else None, "from": lo, "to": hi})
    return out


def list_modules(course_slug: str | None = None) -> list[dict]:
    """Group a course's units into modules: [{label, weeks}, ...].

    THE CONTRACT the template relies on: concatenating every group's `weeks`
    reproduces `list_weeks(course_slug)` exactly — same units, same order. It
    holds by construction, because this walks `weeks` and never reorders or
    filters; a unit that matches no declared range lands in an UNLABELLED group
    in its own position. So a half-written `modules` declaration degrades to a
    partly-flat page, never to a page that has quietly lost week 14.

    Returns [] when the course declares no modules, which is the signal
    learn_index.html reads to render the flat list it renders today. Two of the
    three live courses take that path, so it is the majority, not a fallback.
    """
    c = course(course_slug)
    weeks = list_weeks(course_slug)
    spec = (c or {}).get("modules") or []
    if not spec or not weeks:
        return []

    def which(n: int):
        for i, m in enumerate(spec):
            if m["from"] <= n <= m["to"]:
                return i
        return None

    groups: list[dict] = []
    for w in weeks:
        i = which(w["number"])
        # Merge only into a RUN of the same module. Two separate unlabelled
        # stretches either side of a named module must stay separate, or the
        # page would claim week 7 sits next to week 17.
        if groups and groups[-1]["_i"] == i:
            groups[-1]["weeks"].append(w)
        else:
            groups.append({"_i": i,
                           "label": spec[i]["label"] if i is not None else None,
                           "weeks": [w]})
    return [{"label": g["label"], "weeks": g["weeks"]} for g in groups]


def _load_courses() -> list[dict]:
    """Course registry, from $COURSES (JSON) or a single course from CONTENT_ROOT.

    The single-course default is what keeps this change invisible to the current
    deployment: with no $COURSES set the platform behaves exactly as before,
    serving CONTENT_ROOT under one course.

    $COURSES is a JSON list of {slug, title, root, arena_url?}. `root` is the
    directory holding the weekNN-* dirs (i.e. a course repo's `labs/`).
    """
    raw = os.environ.get("COURSES", "").strip()
    if not raw:
        return [{
            "slug": os.environ.get("COURSE_SLUG", "software-security"),
            "title": os.environ.get("COURSE_TITLE", "Software Security"),
            "root": CONTENT_ROOT,
            "arena_url": os.environ.get("ARENA_URL", "").strip() or None,
            "unit": "week",
            "modules": [],
            "unit_label": "Week",
        }]
    out, seen = [], set()
    for c in json.loads(raw):
        slug = str(c.get("slug", "")).strip()
        if not COURSE_SLUG_RE.match(slug):
            raise ValueError(f"COURSES: bad course slug {slug!r}")
        if WEEK_RE.match(slug):
            # Would make /learn/<slug> ambiguous with a legacy week URL.
            raise ValueError(f"COURSES: slug {slug!r} collides with a week directory name")
        if slug in seen:
            raise ValueError(f"COURSES: duplicate slug {slug!r}")
        seen.add(slug)
        root = os.path.realpath(str(c["root"]))
        if not os.path.isdir(root):
            raise ValueError(f"COURSES: {slug!r} root does not exist: {root}")
        unit = str(c.get("unit") or "week")
        if not UNIT_NAME_RE.match(unit):
            raise ValueError(f"COURSES: {slug!r} has bad unit {unit!r}")
        out.append({"slug": slug, "title": str(c.get("title") or slug),
                    "root": root, "arena_url": (c.get("arena_url") or None),
                    "unit": unit,
                    "modules": _clean_modules(slug, c.get("modules")),
            # Which unit the cohort is on right now, as a `number` (not an index):
            # optional, and absent means "say nothing", which is what every course
            # did before this existed. A term moves on; a wrong marker is worse
            # than none, so it is never guessed from the date.
            "current": str(c["current"]) if c.get("current") not in (None, "") else None,
                    "unit_label": str(c.get("unit_label") or unit.capitalize())})
    if not out:
        raise ValueError("COURSES was set but produced no courses")
    return out


COURSES = _load_courses()


# Plural nouns for the card's composition line, in the order they are shown.
# "13 labs · 2 exams · 2 CTFs · 2 reviews" is the one sentence on a course card
# that differs between courses, which is the whole reason the card exists —
# three cards carrying the same sentence is the "eight identical boxes" the
# front door was rebuilt to fix.
_MIX_NOUNS = [("LAB", "lab", "labs"), ("EXAM", "exam", "exams"),
              ("CTF", "CTF", "CTFs"), ("REVIEW", "review", "reviews"),
              ("CAPSTONE", "capstone", "capstones"), ("GUIDE", "guide", "guides")]


def course_mix(course_slug: str | None = None) -> list[str]:
    """What a course is made of, counted from what is actually on disk.

    Never configured and never estimated: if a directory stops publishing a
    worksheet its badge changes and this line changes with it. That is the
    difference between a card that describes the course and a card that
    describes what somebody once typed into an env var.

    A unit whose directory carries no recognised primary (badge == "", which is
    reachable — a slides-only directory does it) is counted under "other"
    rather than dropped, so the parts always sum to week_count.
    """
    counts: dict[str, int] = {}
    for w in list_weeks(course_slug):
        counts[w.get("badge") or ""] = counts.get(w.get("badge") or "", 0) + 1
    out = []
    for key, one, many in _MIX_NOUNS:
        n = counts.get(key, 0)
        if n:
            out.append(f"{n} {one if n == 1 else many}")
    n = counts.get("", 0)
    if n:
        out.append(f"{n} other")
    return out


def nav_courses() -> list[dict]:
    """Just {slug, title} for the shared nav's course switcher.

    A PROJECTION, deliberately — never the course dicts themselves. Those carry
    `root`, an absolute path on the server's filesystem, and the nav is rendered
    into every page by base.html: one stray `{{ c }}` in a future edit would
    print the deployment's directory layout onto a public page. Handing the
    template only the two fields it needs makes that impossible rather than
    merely unlikely.

    Cheap on purpose: no list_weeks() call, so adding the switcher to a page
    costs no directory scan. That is also why this is not a context_processor —
    Flask would run it for /host and /play too, which is the one surface that
    must not gain new work or new ways to fail.
    """
    return [{"slug": c["slug"], "title": c["title"]} for c in COURSES]


def list_courses() -> list[dict]:
    """Every configured course, with the derived fields the course card shows.

    `week_count`, `graded_count` and `mix` are all counted from list_weeks() at
    call time. They are additive — every existing caller that only reads slug /
    title / week_count is unaffected.
    """
    out = []
    for c in COURSES:
        weeks = list_weeks(c["slug"])
        out.append({**c,
                    "week_count": len(weeks),
                    "graded_count": sum(1 for w in weeks if w.get("graded")),
                    "mix": course_mix(c["slug"])})
    return out


def course(slug: str | None) -> dict | None:
    """Resolve a course slug. `None` means the default (first) course, which is
    what every pre-existing single-course caller and URL relies on."""
    if slug is None:
        return COURSES[0]
    return next((c for c in COURSES if c["slug"] == slug), None)


def _root_of(course_slug: str | None) -> str | None:
    c = course(course_slug)
    return c["root"] if c else None
# Every student-facing document a week can carry, keyed by the URL segment.
#
# Still an ALLOWLIST of exact filenames, not a pattern or a denylist: a lab
# directory also holds `solution_app.py`, `vulnerable_app.py` and compose files,
# and the answer keys live in the git-ignored instructor/ tree. Nothing here may
# ever be widened to "any .md" — the point is that adding a file to a lab does
# not silently publish it.
#
# The six non-lab weeks (review, written exam, practical CTF) carry no
# worksheet.md at all: their material IS mock-ctf.md / exam.md / ctf.md. Before
# these were listed, /learn showed those weeks as a README and nothing else —
# the main document for six of nineteen weeks was simply absent from the
# platform while appearing complete on disk.
PUBLIC_FILES = {
    "worksheet": "worksheet.md",
    "readme": "README.md",
    # non-lab weeks — this is their primary material
    "mock-ctf": "mock-ctf.md",          # W7, W17 review
    "exam": "exam.md",                  # W8, W18 written
    "ctf": "ctf.md",                    # W9, W19 practical
    "scrimmage": "scrimmage.md",        # W16 capstone
    # per-week supplements a worksheet references
    "attack": "attack.md",              # W6, W10, W14
    "harden": "harden.md",              # W13
    "dependency-confusion": "dependency-confusion.md",  # W12
    "template": "THREAT-MODEL-TEMPLATE.md",             # W1 — students fill this in
    "pipeline": "README-pipeline.md",   # W15
}

# Lecture decks live outside the week directory, at slides/weekNN.md. Served
# read-only like everything else here; the generated .pptx is NOT served (it is
# a binary the renderer can't make inert, and the markdown is the source anyway).
SLIDES_DIR = "slides"

# Human labels for the document kinds. Lives here, not in a template, because
# BOTH the course index and the reading page print them: while it was a Jinja
# `set` inside learn_index.html the reading page had no access and printed raw
# slugs instead, so the same document was "Lecture slides" on one page and
# "slides" on the next click. The fallback de-hyphenates and capitalises, so a
# kind added to PUBLIC_FILES can never render as a bare slug.
KIND_LABELS = {
    "worksheet": "Worksheet",
    "readme": "Overview",
    "slides": "Lecture slides",
    "mock-ctf": "Mock CTF",
    "exam": "Exam paper",
    "ctf": "CTF brief",
    "scrimmage": "Scrimmage",
    "attack": "Attack notes",
    "harden": "Hardening notes",
    "dependency-confusion": "Supply-chain notes",
    "template": "Template to fill in",
    "pipeline": "Pipeline guide",
    "guide": "Course guide",
}


def kind_label(kind: str) -> str:
    return KIND_LABELS.get(kind) or (kind or "").replace("-", " ").capitalize()

# Interactive simulations a worksheet may embed, by slug. An ALLOWLIST, because
# this is the one construct in the whole renderer that produces an <iframe> —
# a slug that isn't here renders as an ordinary code block, so a typo or a
# hostile string degrades to visible text rather than to markup.
#
# A worksheet embeds one with a fenced block:
#
#     ```sim
#     trust-boundary
#     ```
#
# A fence is used rather than a link because it cannot occur by accident in
# prose, and because the body is matched whole against this dict.
SIMS = {
    "trust-boundary": "Trust boundaries & threat chaining (Week 1)",
    "cia-triad": "Classify the incident: which CIA property took the hit? (Week 1)",
    "path-traversal": "The /upload endpoint: same input, opposite outcomes (Week 1)",
    "stride-drill": "Name the threat: STRIDE applied to one endpoint (Week 1)",
    "fuzz-verdict": "What actually crashes harness.c, computed live (Week 2)",
    "triage-drill": "Which bug is this really? Raw findings, deduplicated (Week 2)",
    "resolver-confusion": "Which package actually installs? Computed live (Week 12)",
    "mass-assign": "Which fields actually get stored? (Week 10)",
    "iam-scope": "Two findings, one statement: Action vs Resource wildcards (Week 13)",
    "prompt-guard": "Three layers, watched one at a time (Week 14)",
    "gate-check": "Does this PR pass the gate? (Week 15)",
    "sqli-parse": "How concatenation changes the SQL parse tree (Week 4)",
    "aes-modes": "Why ECB leaks a picture, and what CBC's XOR costs (Week 3)",
    "ecdsa-malleability": "One signature, two spellings: (r, s) and (r, n − s) (Cryptography, Week 11)",
    "iam-evaluation": "How AWS actually evaluates a request (Cloud Infrastructure, Lesson 7)",
    "jwt-forge": "Editing a JWT: base64url is encoding, not sealing (Week 6)",
    "stack-frame": "What a stack canary detects and what FORTIFY_SOURCE prevents (Week 11)",
    "xss-context": "One value, four sinks: why escaping is context-dependent (Week 5)",
    "eop-deck": "Draw a card, tie it to your DFD — no printer needed (Week 1)",
}

# Which unit each simulation belongs to. /sim's own copy says "each one is
# embedded in the worksheet it belongs to" and its titles even name the week,
# but nothing linked there — the page was a dead end reachable from the global
# nav on every page. Kept as its own table rather than folded into SIMS so the
# allowlist above stays a plain slug->title map, which is what the renderer and
# the route both read.
SIM_SOURCE = {
    "trust-boundary": ("software-security", "week01-threat-modeling"),
    "cia-triad": ("software-security", "week01-threat-modeling"),
    "path-traversal": ("software-security", "week01-threat-modeling"),
    "stride-drill": ("software-security", "week01-threat-modeling"),
    "fuzz-verdict": ("software-security", "week02-sdlc-tooling"),
    "triage-drill": ("software-security", "week02-sdlc-tooling"),
    "resolver-confusion": ("software-security", "week12-supply-chain"),
    "mass-assign": ("software-security", "week10-api-security"),
    "iam-scope": ("software-security", "week13-cloud-container"),
    "prompt-guard": ("software-security", "week14-ai-llm-security"),
    "gate-check": ("software-security", "week15-devsecops-pipeline"),
    "sqli-parse": ("software-security", "week04-injection"),
    "aes-modes": ("software-security", "week03-cryptography"),
    # Course slugs here are the deployed URL slugs ($COURSES in production —
    # instructor/platform-build/deploy/.env.example), not the repo directory
    # names. "security-cryptography" and "cloud-infrastructure-security" 404:
    # the live site is /learn/cryptography and /learn/cloud-security.
    "ecdsa-malleability": ("cryptography", "week11-signatures-zkp"),
    "iam-evaluation": ("cloud-security", "lesson07-iam-policy-evaluation"),
    "jwt-forge": ("software-security", "week06-authn-authz"),
    "stack-frame": ("software-security", "week11-memory-safety-exploitation"),
    "xss-context": ("software-security", "week05-xss-client-side"),
    "eop-deck": ("software-security", "week01-threat-modeling"),
}


def sim_entries() -> list[dict]:
    """The simulations, each with the unit it illustrates (when that unit is
    actually published in a configured course — otherwise the link is omitted
    rather than pointed at a 404)."""
    out = []
    for slug in sorted(SIMS):
        course_slug, week = SIM_SOURCE.get(slug, (None, None))
        href = None
        if course_slug and course(course_slug) is not None:
            if any(w["slug"] == week for w in list_weeks(course_slug)):
                href = f"/learn/{course_slug}/{week}"
        out.append({"slug": slug, "title": SIMS[slug], "week_href": href})
    return out


def list_weeks(course_slug: str | None = None) -> list[dict]:
    """Every week directory that has something public to show, in order.

    `course_slug=None` keeps the original single-course behaviour.
    """
    c = course(course_slug)
    if c is None:
        return []
    root = c["root"]
    pat = unit_re(c.get("unit", "week"))
    out = []
    for name in sorted(os.listdir(root)):
        m = pat.match(name)
        if not m:
            continue
        d = os.path.join(root, name)
        if not os.path.isdir(d):
            continue
        available = [k for k, f in PUBLIC_FILES.items()
                     if os.path.isfile(os.path.join(d, f))]
        if _slides_path(m.group(1), course_slug):
            available.append("slides")
        if not available:
            continue
        # The title must be the one on the document the row OPENS, not the
        # README's. Verified 2026-07-30: week 7's README says "Reflection &
        # Review (pre-Midterm)" while the row links mock-ctf.md, titled "Mock CTF
        # (Midterm dry-run)". The list promised revision and delivered a timed
        # CTF. Same divergence on weeks 8, 9, 18, 19 — the exam blocks.
        primary = None
        for k in PRIMARY_ORDER:
            if k in available:
                primary = k
                break
        primary = primary or (available[0] if available else None)
        primary_file = (PUBLIC_FILES.get(primary) if primary != "slides"
                        else None)
        # Independent of `primary` on purpose — see BADGE_ORDER's docstring.
        assessment = next((k for k in BADGE_ORDER if k in available), None)
        title = None
        if primary_file:
            title = _title_of(os.path.join(d, primary_file))
        title = title or _title_of(os.path.join(d, "worksheet.md")) \
            or _title_of(os.path.join(d, "README.md")) \
            or name[7:].replace("-", " ").title()
        num = m.group(1)
        out.append({
            "slug": name,
            # TWO fields, because one cannot be both sortable and truthful.
            # `number` is an int taken from the leading two digits, which the
            # pattern guarantees exist — so ordering stays numeric (an earlier
            # attempt made this a string and "10" sorted before "2"; the existing
            # tests caught it, correctly).
            # `number_label` is what a student reads, and it keeps the
            # irregularity the cloud course actually has: "7b", "1-3".
            "number": int(num[:2]),
            "number_label": _num_label(num),
            "unit_label": c.get("unit_label", "Week"),
            "badge": PRIMARY_BADGE.get(assessment, ""),
            "graded": PRIMARY_BADGE.get(assessment, "") in GRADED_BADGES,
            "title": title,
            "short_title": short_title(title),
            "primary": primary,
            "available": available,
        })
    return out


# Which document IS the week, when the URL doesn't say. Order matters and is not
# alphabetical: it is "the thing a student opens when they open the week".
#
# Six of the nineteen weeks have NO worksheet.md — the review weeks are a
# mock CTF, the exam weeks are the paper, the practical weeks are the CTF brief.
# `/learn/<course>/<week>` used to hardcode `kind="worksheet"` for all of them,
# so **week07, 08, 09, 17, 18 and 19 returned 404 on their main link** — both
# written exams, both midterm/final CTFs and both mock CTFs, i.e. the six
# highest-stakes documents in the course. Present since the content plane was
# first built; found 2026-07-30 by requesting every week's bare URL rather than
# by reading the route.
# Titles as a student should read them in a LIST, which is not how they read at
# the top of a document. The headings carry context the row already gives —
# "Worksheet 4 — ", "Week 8 — " — and an hours figure that is wrong twice over:
# worksheets 13-16 say "(4 hrs)", but a KOSEN class is 3 hours and an MFU session
# is a whole Saturday. Verified against all 19 real headings.
_TRIM_LEAD = re.compile(
    r"^(?:Worksheet|Week|Lab|Lesson)s?(?:\s+[\d\u2013-]+)?\s*[:—–-]\s*", re.I)
_TRIM_TAIL = re.compile(r"\s*\((?:\d+(?:\.\d+)?\s*(?:hrs?|hours?)|Week\s+\d+)\)\s*$", re.I)


def _num_label(num: str) -> str:
    """"07" -> "7" · "07b" -> "7b" · "01-03" -> "1-3" (a range of lessons)."""
    parts = num.split("-")
    out = []
    for part in parts:
        digits = part[:2].lstrip("0") or "0"
        out.append(digits + part[2:])
    return "\u2013".join(out) if len(out) > 1 else out[0]


def short_title(title: str) -> str:
    """A list-row title. Never returns empty — an unmatched heading renders raw,
    which is redundant rather than blank."""
    if not title:
        return title
    out = title.strip()
    # Repeat: the cloud course stacks two prefixes — "Worksheet — Lessons 1-3: ".
    # Bounded so a pathological title cannot spin.
    for _ in range(4):
        nxt = _TRIM_LEAD.sub("", out, count=1).strip()
        if nxt == out:
            break
        out = nxt
    out = _TRIM_TAIL.sub("", out).strip()
    return out or title.strip()


# What KIND of thing a unit is, from the document that IS it. A student scanning
# 19 rows needs to see at a glance which ones are assessments — the exam weeks and
# the midterm/final CTFs look exactly like an ordinary lab in a bare list, and
# that is how someone walks into a graded block expecting a worksheet.
PRIMARY_BADGE = {
    "worksheet": "LAB",
    "mock-ctf": "REVIEW",
    "exam": "EXAM",
    "ctf": "CTF",
    "scrimmage": "CAPSTONE",
    "readme": "GUIDE",
}
# Which of those carry a mark.
#
# LAB IS IN THIS SET, and leaving it out was the worst defect in the badge system
# it was added to fix. syllabus.md:163 — "Weekly lab worksheets — 13 graded | 30%"
# — makes the worksheets the SINGLE LARGEST component of the final grade, and all
# 13 of them render from `primary == "worksheet"` → badge LAB. With LAB excluded,
# the 30% component was drawn in the same greyed style as "read anything, any
# time", i.e. the feature whose entire purpose is to stop a student walking into
# graded work unawares was telling them the largest graded component was optional
# reading. That is worse than having no badges: it is a confident wrong answer.
#
# REVIEW (weeks 7, 17) genuinely is not graded — those are mock CTFs for practice.
GRADED_BADGES = {"LAB", "EXAM", "CTF"}

#     GRADED assessment kinds always win when present: these weeks never carry
#     a worksheet.md alongside them (PUBLIC_FILES' comment — "non-lab weeks,
#     this is their primary material"), so putting "slides" after them changes
#     nothing for exam/review/practical/capstone weeks.
#
# "slides" sits ahead of "worksheet" so an ordinary lab week opens on the
# CONCEPT explanation, not the hands-on task list — a bare "Week N" link was
# landing students straight on Task 3's docker commands with no lecture
# content in sight. The worksheet is one click away either way (learn_doc.html's
# crumb links every OTHER available kind) — see BADGE_ORDER below for why this
# alone does not touch grading.
PRIMARY_ORDER = ("mock-ctf", "exam", "ctf", "scrimmage", "slides", "worksheet", "readme")

# What a week's badge/graded status is ABOUT — deliberately not PRIMARY_ORDER.
# list_weeks() used to key PRIMARY_BADGE off `primary` directly, on the
# assumption that "the document that opens" and "the thing this week grades
# you on" were the same fact. Adding "slides" to PRIMARY_ORDER broke that
# assumption silently: every ordinary week's primary became "slides", "slides"
# has no entry in PRIMARY_BADGE, and the LAB/GRADED badge vanished from the
# course index for every week 1-6/10-15 with no error anywhere — caught only by
# test_worksheets_are_marked_graded's `assert labs`. This is the old
# PRIMARY_ORDER, kept as its own constant so the two questions ("what opens"
# vs "what is this week graded on") can change independently from here on.
BADGE_ORDER = ("worksheet", "mock-ctf", "exam", "ctf", "scrimmage", "readme")


def current_unit(course_slug: str | None = None) -> str | None:
    """The unit the cohort is on, or None. Set per course in $COURSES."""
    c = course(course_slug)
    return (c or {}).get("current")


def primary_kind(slug: str, course_slug: str | None = None) -> str | None:
    """The document a bare week URL should open, or None if the week has none."""
    week = next((w for w in list_weeks(course_slug) if w["slug"] == slug), None)
    return week["primary"] if week else None


def _slurp(path: str) -> str | None:
    """Read a file, or None if it cannot be read.

    An UNREADABLE file is treated exactly like a missing one. Production served
    a 500 with a stack trace for two weeks because one course file had been
    rsync'd with mode 0600: `git` tracks only the exec bit, so nothing in the
    repo, the diff or CI could show it, and the container's non-root user simply
    could not open it. A wrong file mode is a deployment defect, not a reason to
    hand a student a traceback — it now 404s like any other absent document, and
    readiness_check.py probes the linked kinds so the defect is still caught
    loudly at deploy time rather than silently in class.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _title_of(path: str) -> str | None:
    """First `# heading` — the document's own title, not one we invent."""
    if not os.path.isfile(path):
        return None
    md = _slurp(path)
    if md is None:
        return None
    for line in md.splitlines():
        m = re.match(r"^#\s+(.+)", line.strip())
        if m:
            return m.group(1).strip()
    return None


def _slides_path(unit_token: str, course_slug: str | None = None) -> str | None:
    """slides/weekNN.md, if it exists. Outside the week directory, so it gets its
    own containment check rather than reusing the lab-dir one."""
    c = course(course_slug)
    if c is None:
        return None
    if not re.fullmatch(r"\d{2}[a-z]?(?:-\d{2})?", unit_token or ""):
        return None      # never let a caller-supplied string reach a path join
    root = os.path.realpath(c["root"])
    # CONTENT_ROOT is `labs/` (or /content in the image); slides/ is its sibling
    # in a checkout and a sibling under /content in the image.
    for base in (os.path.dirname(root), root):
        p = os.path.realpath(os.path.join(
            base, SLIDES_DIR, f"{c.get('unit', 'week')}{unit_token}.md"))
        if (p == base or p.startswith(base + os.sep)) and os.path.isfile(p):
            return p
    return None


def read(slug: str, kind: str, course_slug: str | None = None) -> str | None:
    """Raw markdown for one week's public document, or None.

    Resolves and then re-checks containment: even though WEEK_RE already makes
    traversal impossible, the check costs nothing and survives someone later
    relaxing the pattern. With several courses configured the containment check
    matters more, not less — it is now per-course, so a week slug can never
    reach out of its own course's root.
    """
    c = course(course_slug)
    if c is None:
        return None
    if not unit_re(c.get("unit", "week")).match(slug or ""):
        return None
    base_root = c["root"]
    if kind == "slides":
        m = unit_re(course(course_slug).get("unit", "week")).match(slug)
        p = _slides_path(m.group(1), course_slug) if m else None
        if p is None:
            return None
        return _slurp(p)
    if kind not in PUBLIC_FILES:
        return None
    root = os.path.realpath(base_root)
    path = os.path.realpath(os.path.join(root, slug, PUBLIC_FILES[kind]))
    if not (path == root or path.startswith(root + os.sep)):
        return None
    if not os.path.isfile(path):
        return None
    return _slurp(path)


# ── course-root documents ───────────────────────────────────────────────────
# Documents that live ABOVE the course root (the repo root, next to labs/) and
# are referenced by worksheets through repo-relative markdown links. Thirteen
# worksheets link `../../SUBMISSION.md` — the hand-in instructions — and until
# this existed every one of those links 404'd, because the content plane served
# week directories and nothing else.
#
# An ALLOWLIST keyed by the exact repo-relative path, exactly like PUBLIC_FILES.
# The value is the URL segment. Nothing here is ever derived from a request:
# a name reaches the filesystem only after matching this table, so the fact that
# these paths escape the course root cannot become a traversal primitive.
# Instructor material never appears here and could not: instructor/ is
# git-ignored and .dockerignore's allowlist keeps it out of the image entirely.
COURSE_DOCS = {
    "SUBMISSION.md": "submission",
    "ETHICS.md": "ethics",
    "project/README.md": "project",
    "project/REPORT-TEMPLATE.md": "project-report",
    "project/starter-app/README.md": "project-starter-app",
    "quizzes/quiz1.md": "quiz1",
    "quizzes/quiz2.md": "quiz2",
    "quizzes/README.md": "quizzes",
}
_DOC_BY_NAME = {v: k for k, v in COURSE_DOCS.items()}


def _course_doc_path(name: str, course_slug: str | None = None) -> str | None:
    """Absolute path of an allowlisted course-root document, or None.

    `name` is matched against the allowlist BEFORE any path join, and the result
    is containment-checked against the repo root the same way read() checks the
    course root — belt and braces, since the lookup already makes traversal
    impossible.
    """
    rel = _DOC_BY_NAME.get(name or "")
    if rel is None:
        return None
    c = course(course_slug)
    if c is None:
        return None
    repo_root = os.path.realpath(os.path.dirname(os.path.realpath(c["root"])))
    p = os.path.realpath(os.path.join(repo_root, rel))
    if not p.startswith(repo_root + os.sep):
        return None
    return p if os.path.isfile(p) else None


def list_course_docs(course_slug: str | None = None) -> list[dict]:
    """The allowlisted course-root documents this course actually ships."""
    out = []
    for rel, name in COURSE_DOCS.items():
        p = _course_doc_path(name, course_slug)
        if p:
            out.append({"name": name, "title": _title_of(p) or rel, "rel": rel})
    return out


def render_course_doc(name: str, course_slug: str | None = None) -> dict | None:
    p = _course_doc_path(name, course_slug)
    if p is None:
        return None
    md = _slurp(p)
    if md is None:
        return None
    c = course(course_slug)
    title = _title_of(p) or _DOC_BY_NAME[name]
    body = render(md, title=title,
                  ctx={"course": c["slug"], "dir": os.path.dirname(p)})
    return {"name": name, "kind": "guide", "title": title, "html": body,
            "outline": outline(body),
            "course": c["slug"], "course_title": c["title"]}


# --- rendering -------------------------------------------------------------

_INLINE_CODE = re.compile(r"`([^`]+)`")
# A code span, OR a whole link whose label is a code span.
#
# The two branches can never compete: one can only start at `[`, the other only
# at a backtick, so whichever is written first, the scanner reaches the `[` of a
# code-labelled link before its backtick and matches the link branch there.
# (Checked, not assumed — swapping the order changes no test.) What matters is
# that this runs INSTEAD OF the bare code pass, so the label and the brackets
# around it are consumed together rather than the label being lifted out and the
# brackets stranded as literal text.
#
# The `[` and `](…)` sit OUTSIDE the backticks, so a payload written inside them
# (`` `[x](javascript:1)` ``) still matches the plain code branch and is never
# linkified — the property the code-first ordering exists to protect.
_CODE_OR_CODE_LINK = re.compile(
    r"\[`(?P<label>[^`]+)`\]\((?P<href>[^)\s]+)\)"
    r"|`(?P<code>[^`]+)`")
# The content class allows a LONE `*` so bold can contain italic — it was
# `[^*]+`, which stopped dead on any nested emphasis and left both markers on
# the page. `**Q2. Broken hashes — and *where* it matters.**` is a graded
# question's own heading, and it rendered with the asterisks showing. Non-greedy
# so the first `**` still closes the run, and `\*(?!\*)` keeps `**` itself out
# of the content, so adjacent bold runs cannot swallow each other.
_BOLD = re.compile(r"\*\*((?:[^*]|\*(?!\*))+?)\*\*")
_ITALIC = re.compile(r"(?<![*\w])\*([^*\n]+)\*(?!\*)")
_LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
_ULI = re.compile(r"^\s*[-*+]\s+(.*)$")
_OLI = re.compile(r"^\s*\d+[.)]\s+(.*)$")
_RULE = re.compile(r"^\s*(-{3,}|\*{3,}|_{3,})\s*$")
# Matches the ESCAPED form: by the time block constructs are scanned, `>` is
# already `&gt;`. Escape-then-parse is the security property, so every pattern
# that touches < > & must be written against the escaped text, not the source.
_QUOTE = re.compile(r"^&gt;\s?(.*)$")
_TABLE_SEP = re.compile(r"^\s*\|?[\s:|-]+\|[\s:|-]*$")

# Only these schemes become clickable. `javascript:` and `data:` are the two that
# turn a link into script execution; anything unrecognised renders as plain text.
_SAFE_LINK = re.compile(r"^(https?://|mailto:|/|\#|\./|\.\./)", re.I)

# ── Diagrams ───────────────────────────────────────────────────────────────
# A worksheet may show a picture: `![alt](img/threat-model.svg)`.
#
# WHY A DEDICATED img/ DIRECTORY, AND AN ALLOWLIST OF TYPES
#   A unit directory holds the lab's source, its compose files, its solutions.
#   If any file in it could be addressed as an image, this route would become a
#   way to read `solution_app.py` — the content plane already refuses to serve
#   that as a document, and it must not hand it back through another door. So an
#   image resolves ONLY at `<unit>/img/<name>`, and only with a known extension.
#
# WHY SVG IS ALLOWED ANYWAY
#   An SVG can contain <script>. Loaded through <img> a browser will not run it
#   — that is a hard rule of the img element, not a heuristic. Loaded by
#   NAVIGATING to the file it will. The renderer only ever emits <img>, but the
#   URL is guessable, so the route pins `default-src 'none'` on the file
#   response itself: direct navigation gets the picture and no script either way.
IMG_TYPES = {".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg",
             ".jpeg": "image/jpeg", ".webp": "image/webp", ".gif": "image/gif"}
_IMG_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_IMAGE = re.compile(r"!\[(?P<alt>[^\]]*)\]\((?P<src>[^)\s]+)\)")


def unit_image_path(course_slug, unit: str, name: str) -> str | None:
    """Absolute path of a unit's image, or None if there isn't one to serve.

    THE single authority. The renderer calls it to decide whether to emit an
    `<img>`; the route calls it to decide whether to hand back bytes. Sharing it
    is the point: a URL can never be rendered that the route would refuse, and
    nothing can be served that the renderer would not have linked.
    """
    if not name or not _IMG_NAME.match(name):
        return None
    if os.path.splitext(name)[1].lower() not in IMG_TYPES:
        return None
    c = course(course_slug)
    if c is None or not unit or not unit_re(c.get("unit", "week")).match(unit):
        return None
    if not primary_kind(unit, c["slug"]):        # not a published unit
        return None
    root = os.path.realpath(c["root"])
    p = os.path.realpath(os.path.join(root, unit, "img", name))
    if not p.startswith(root + os.sep) or not os.path.isfile(p):
        return None
    return p


def _resolve_repo_image(src: str, ctx: dict | None) -> str | None:
    """A markdown image source -> the URL that serves it, or None.

    Same filesystem-identity rule as `_resolve_repo_link`: the path is joined
    onto the document's own directory and the result must land inside this
    course's `<unit>/img/`. A source that resolves nowhere renders as plain
    text rather than as a broken picture.
    """
    if ctx is None or not src or "://" in src or src.startswith("/"):
        return None
    c = course(ctx.get("course"))
    if c is None:
        return None
    try:
        p = os.path.realpath(os.path.join(ctx["dir"], html.unescape(src)))
    except (OSError, ValueError, KeyError):
        return None
    root = os.path.realpath(c["root"])
    if not p.startswith(root + os.sep):
        return None
    rel = os.path.relpath(p, root).split(os.sep)
    if len(rel) != 3 or rel[1] != "img":
        return None
    unit, _, name = rel
    if unit_image_path(c["slug"], unit, name) != p:
        return None
    return f"/learn/{c['slug']}/{unit}/img/{name}"


def _resolve_repo_link(href: str, ctx: dict | None) -> str | None:
    """Map a repo-relative markdown link onto the URL that serves it, or None.

    Worksheets are written to be read in a git checkout, so they link their
    siblings the way files do: `../../SUBMISSION.md`, `../week16-capstone/
    worksheet.md`. Rendered verbatim those become browser-relative URLs that
    resolve against /learn/... and 404 — which is what 47 of 124 document pages
    were doing, including the hand-in instructions linked from thirteen
    worksheets.

    Resolution is by FILESYSTEM IDENTITY, not string munging: the href is joined
    onto the document's own directory and the result is compared against paths
    this app already serves. Anything that does not land on a servable document
    returns None and the caller renders it as plain text, so a link can never be
    invented for a file the content plane would refuse to serve.
    """
    if ctx is None or not href or "://" in href:
        return None
    target = html.unescape(href).split("#", 1)[0].split("?", 1)[0]
    if target.startswith("/"):
        return None
    # A worksheet links a sibling week the way a directory listing does —
    # `../week01-threat-modeling/`. Rendered verbatim that becomes a
    # trailing-slash URL which hard-404s, and week 7's revision list is six of
    # them: the study map for the midterm, every entry dead. Weeks 8, 9 and 17
    # carry the same shape in their "Pairs with" line.
    is_dir_link = target.endswith("/") or (target and "." not in os.path.basename(target))
    if not target.endswith(".md") and not is_dir_link:
        return None
    c = course(ctx.get("course"))
    if c is None:
        return None
    try:
        p = os.path.realpath(os.path.join(ctx["dir"], target))
    except (OSError, ValueError, KeyError):
        return None

    root = os.path.realpath(c["root"])
    if is_dir_link and not target.endswith(".md"):
        # Same rule as everything else here: it resolves only if it lands on a
        # real unit directory OF THIS COURSE that the app actually publishes.
        if not os.path.isdir(p) or not p.startswith(root + os.sep):
            return None
        rel = os.path.relpath(p, root).split(os.sep)
        if len(rel) != 1 or not unit_re(c.get("unit", "week")).match(rel[0]):
            return None
        return (f"/learn/{c['slug']}/{rel[0]}"
                if primary_kind(rel[0], c["slug"]) else None)
    if not os.path.isfile(p):
        return None
    # inside the course root -> a week's own public document
    if p.startswith(root + os.sep):
        rel = os.path.relpath(p, root).split(os.sep)
        if len(rel) == 2:
            week, fname = rel
            for k, v in PUBLIC_FILES.items():
                if v == fname and unit_re(c.get("unit", "week")).match(week):
                    return f"/learn/{c['slug']}/{week}/{k}"
        return None
    # above it -> an allowlisted course-root document
    repo_root = os.path.realpath(os.path.dirname(root))
    if p.startswith(repo_root + os.sep):
        rel = os.path.relpath(p, repo_root).replace(os.sep, "/")
        name = COURSE_DOCS.get(rel)
        if name:
            return f"/learn/{c['slug']}/doc/{name}"
    return None


def _inline(escaped: str, ctx: dict | None = None) -> str:
    """Inline constructs, applied to text that is ALREADY html-escaped.

    Order matters: code spans first, so a payload inside backticks (which is how
    the worksheets present them) is never scanned for emphasis or links.

    That ordering had one casualty. A link whose LABEL is a code span —
    ``[`ETHICS.md`](ETHICS.md)``, the house style for pointing at a file — was
    split by the code pass into `[`, the code, and `](ETHICS.md)`, so the link
    pattern never saw a link and students read a literal
    `[ETHICS.md](ETHICS.md)`, brackets and all, with nothing to click. Twenty of
    them across sixteen published documents, including the two that point at each
    course's ethics policy. `_CODE_LINK` below matches that whole shape FIRST, so
    the label is still treated as code (never re-scanned for markdown) while the
    link around it is built by the same `_build_link` every other link goes
    through — same scheme check, same repo-link resolution, same quoting.
    """
    escaped = escaped.replace("\x00", "")     # see the sentinel note below

    # Each code span (and code-labelled link) is lifted out and replaced by a
    # NUL-delimited sentinel, `_fmt` runs over what is left, and the finished
    # HTML is put back.
    #
    # The lifting is what protects code content — `_fmt` never sees a backtick's
    # contents, so a payload written in backticks is still never scanned for
    # emphasis or links. What changed is that `_fmt` now sees ONE string instead
    # of the fragments between code spans, and that is the whole fix: emphasis
    # around a code span used to have its opening `**` in one fragment and its
    # closing `**` in another, so the two could never pair and both leaked into
    # the page as literal asterisks. ``**`exp` and `aud`**`` was the ugliest
    # case — the stray markers were visible AND `<strong>` landed on the word
    # "and" instead of on the claims.
    #
    # NUL is the sentinel because the input is already HTML-escaped, so it holds
    # no markup, and a NUL cannot survive into rendered prose meaningfully. Any
    # NUL already in the source is stripped above, so a document cannot forge a
    # sentinel and reach the substitution.
    holes: list[str] = []

    def _stash(m):
        if m.group("href") is not None:                      # [`label`](href)
            holes.append(_build_link(f"<code>{m.group('label')}</code>",
                                     m.group("href"), ctx))
        else:
            holes.append(f"<code>{m.group('code')}</code>")
        return f"\x00{len(holes) - 1}\x00"

    def _stash_img(m):
        """`![alt](src)`. Stashed rather than formatted for the same reason code
        spans are: the finished tag must never be re-scanned. `_ITALIC` would
        otherwise happily find a pair of asterisks spanning an alt attribute and
        open an <em> inside it."""
        url = _resolve_repo_image(m.group("src"), ctx)
        if url is None:
            # No such picture. Stash the markdown VERBATIM rather than returning
            # it: left in place, `_fmt`'s link pass matches the `[alt](src)` part,
            # declines the relative path, and emits `!alt (src)` — a stray bang
            # in front of half-eaten syntax that reads like a typo in the prose
            # instead of a missing file.
            holes.append(m.group(0))
            return f"\x00{len(holes) - 1}\x00"
        alt = m.group("alt").replace('"', "&quot;")
        holes.append(f'<img src="{url}" alt="{alt}" loading="lazy" decoding="async">')
        return f"\x00{len(holes) - 1}\x00"

    # Code first (so a payload in backticks is never scanned), then images.
    stashed = _IMAGE.sub(_stash_img, _CODE_OR_CODE_LINK.sub(_stash, escaped))
    formatted = _fmt(stashed, ctx)
    # Looped: an image whose alt held a code span carries that code span's
    # sentinel inside the tag this pass puts back, and one substitution would
    # leave it visible as a NUL-wrapped integer.
    for _ in range(4):
        if "\x00" not in formatted:
            break
        formatted = re.sub(r"\x00(\d+)\x00",
                           lambda m: holes[int(m.group(1))], formatted)
    return formatted.replace("\x00", "")


def _build_link(text: str, href: str, ctx: dict | None) -> str:
    """One link, from already-escaped `text` and `href`. The only place an <a> is
    built, so every caller gets the same safety decisions."""
    # A repo-relative .md link is rewritten to the URL that serves the same
    # document. Done BEFORE the scheme test, because the rewritten value is
    # always a site-absolute path and so always passes it.
    resolved = _resolve_repo_link(href, ctx)
    if resolved:
        href = resolved
    # href is already escaped; unescape only to test the scheme, never to emit.
    elif not _SAFE_LINK.match(html.unescape(href)):
        return f"{text} ({href})"      # shown, not clickable
    elif ctx and href.startswith(("./", "../")):
        # A repo-relative path that resolution just declined: the file is
        # absent, or present but not something this plane serves. It used to
        # render as a link straight to a 404; show the path as text instead,
        # which is honest about there being nothing to open.
        # Guarded on `ctx` because without it nothing was ever resolved —
        # a caller rendering a bare string gets the old behaviour untouched.
        #
        # NOT limited to `.md`. It was, and the moment code-labelled links
        # started resolving, week15's ``[`.github/workflows/security-ci.yml`]
        # (../../.github/workflows/security-ci.yml)`` turned from inert text
        # into a live link to a 404 — the content plane serves documents, not
        # the repo, so no relative path to a non-document can ever open.
        return f"{text} ({href})"
    # Quotes MUST be escaped here even though the document-wide escape used
    # quote=False. This is the one place content lands inside an attribute,
    # and `[x](https://a"onmouseover="alert(1))` contains no whitespace, so it
    # satisfies the href pattern and would otherwise close the attribute and
    # open a live event handler. Found by testing, not by reading.
    safe = href.replace('"', "&quot;").replace("'", "&#x27;")
    return f'<a href="{safe}" rel="noopener noreferrer">{text}</a>'


def _fmt(s: str, ctx: dict | None = None) -> str:
    s = _BOLD.sub(r"<strong>\1</strong>", s)
    s = _ITALIC.sub(r"<em>\1</em>", s)
    return _LINK.sub(lambda m: _build_link(m.group(1), m.group(2), ctx), s)


_TAGS = re.compile(r"<[^>]+>")
_NONWORD = re.compile(r"[^a-z0-9]+")
_H_OUT = re.compile(r'<h([23]) id="([^"]+)">(.*?)</h\1>', re.S)


def outline(rendered_html: str) -> list[dict]:
    """The h2/h3 headings of an already-rendered document, for a table of
    contents. Scans OUR OWN output — every id and every tag in it was emitted by
    render() a moment earlier — so this is not HTML parsing of untrusted input.
    Text is flattened to plain text: it lands in link text, never in markup.
    """
    return [{"level": int(lvl), "id": hid,
             "text": html.unescape(_TAGS.sub("", body)).strip()}
            for lvl, hid, body in _H_OUT.findall(rendered_html or "")]


def _slug_id(text_html: str, used: set) -> str:
    """A stable, unique #fragment for a heading.

    Headings carried no id at all, so nothing inside a 17 KB worksheet was
    addressable: no table of contents, no deep link, and _SAFE_LINK's allowance
    for `#` fragments could never resolve to anything.
    """
    base = _NONWORD.sub("-", html.unescape(_TAGS.sub("", text_html)).lower()).strip("-")
    base = ("s-" + base)[:60].rstrip("-") or "s"
    out, n = base, 2
    while out in used:
        out, n = f"{base}-{n}", n + 1
    used.add(out)
    return out


_FRONTMATTER = re.compile(r"\A---\r?\n.*?\r?\n---\r?\n", re.S)
_MD_COMMENT = re.compile(r"<!--.*?-->", re.S)


def strip_slide_chrome(md: str) -> str:
    """Remove Marp frontmatter and speaker notes from a lecture deck.

    Decks are Marp sources: a YAML frontmatter block, then `<!-- ... -->`
    comments that are the LECTURER'S OWN CUES ("Hook: ...", "Cold-call: ..."),
    then `---` slide breaks. Served through the generic renderer they came out
    as student-visible body text — the frontmatter as the opening paragraph and
    every private teaching note as prose, on all 31 published decks.

    Applied to the SOURCE, before escaping: these are markdown-level constructs,
    and stripping them here means the escape-then-parse ordering downstream is
    untouched. Anything not removed here is still escaped as usual, so a deck
    that omits either construct renders exactly as before.
    """
    md = _FRONTMATTER.sub("", md, count=1)
    return _MD_COMMENT.sub("", md)


def render(md: str, title: str | None = None, ctx: dict | None = None) -> str:
    """Markdown → HTML, with every byte escaped before anything is recognised.

    `title`, when given, suppresses the document's own first heading if it
    repeats it — the page chrome already prints the title as its <h1>, and every
    worksheet was announcing itself twice in a row.
    `ctx` ({"course": slug, "dir": abs dir of the source file}) lets
    repo-relative markdown links resolve to the URLs that serve them.
    """
    lines = html.escape(md, quote=False).replace("&#x27;", "'").splitlines()
    out: list[str] = []
    i, n = 0, len(lines)
    list_stack: list[str] = []
    # How far the numbering of an ordered list had got, and whether what closed
    # it was an interruption the list survives.
    #
    # This renderer has no block nesting: a fenced code block indented under
    # "1." is not part of the item, it closes the list, and the next step opened
    # a brand-new <ol> starting at 1 again. Week 14's four lab steps therefore
    # rendered as 1 · 1,2 · 1 — two different things both labelled step 1, and
    # no step 3 — while the same worksheet's Submit line asks for "your one-line
    # note from step 1, and the two `grep -c` outputs from step 3". The markdown
    # was written 1,2,3,4 and was never wrong; only the count was lost.
    ol_items = 0           # items emitted by the ordered list still in play
    ol_broken = False      # what closed it was a blank line or a code block
    used_ids: set = set()
    want_title = (title or "").strip()
    seen_heading = False

    def close_lists(soft=False):
        """`soft` marks an interruption the numbering survives: a blank line, or
        INDENTED content, which in markdown belongs to the list item above it.
        Indentation is the whole test, and it is what the worksheets actually
        use — step 1's command block, the paragraph explaining its output and
        the sub-bullets listing what to capture are all indented under the step.
        Unindented content at column 0 is a new block that ends the list, so
        `ol_broken` is cleared and the next list starts at 1.

        The clear happens even when the stack is already empty, because by the
        time a paragraph is reached the blank line above it has usually closed
        the list; the paragraph is the thing that says the list is over.

        This mirrors CommonMark, where `1. a` / blank / `2. b` is one loose list
        but `1. a` / blank / prose-at-column-0 / `1. b` is two."""
        nonlocal ol_broken
        while list_stack:
            kind = list_stack.pop()
            out.append(f"</{kind}>")
            if kind == "ol":
                ol_broken = soft
        if not soft:
            ol_broken = False

    def indented(s: str) -> bool:
        return s[:1].isspace()

    while i < n:
        line = lines[i]

        # fenced code — emitted verbatim (already escaped), never re-scanned
        fence = re.match(r"^\s*```+\s*([A-Za-z0-9_+-]*)\s*$", line)
        if fence:
            close_lists(soft=indented(line))
            lang = fence.group(1)
            body, i = [], i + 1
            while i < n and not re.match(r"^\s*```+\s*$", lines[i]):
                body.append(lines[i])
                i += 1
            i += 1

            # ```sim … ``` embeds an interactive simulation. The body must match
            # a slug in the SIMS allowlist EXACTLY; anything else falls through
            # to a normal code block, so an unknown or hostile slug becomes
            # visible text and never an iframe.
            #
            # The frame is sandboxed with `allow-scripts` and deliberately
            # WITHOUT `allow-same-origin`: granting both together is equivalent
            # to no sandbox at all, because the framed page could then reach
            # into this origin and remove its own sandbox attribute. A
            # simulation needs no access to the parent document.
            if lang == "sim":
                slug = "\n".join(body).strip()
                if slug in SIMS:
                    out.append(
                        f'<figure class="sim">'
                        f'<iframe src="/sim/{slug}" title="{html.escape(SIMS[slug])}"'
                        f' sandbox="allow-scripts" loading="lazy"'
                        f' referrerpolicy="no-referrer"></iframe>'
                        f'<figcaption>{html.escape(SIMS[slug])} — '
                        f'<a href="/sim/{slug}">open full size</a></figcaption>'
                        f"</figure>")
                    continue

            cls = f' class="lang-{lang}"' if lang else ""
            out.append(f"<pre><code{cls}>" + "\n".join(body) + "</code></pre>")
            continue

        if not line.strip():
            close_lists(soft=True)
            i += 1
            continue

        if _RULE.match(line):
            close_lists()
            out.append("<hr>")
            i += 1
            continue

        h = _HEADING.match(line)
        if h:
            close_lists()
            raw = h.group(2).strip()
            # The document's own title, repeated as its first heading, is
            # dropped: the page chrome already renders it as the <h1> directly
            # above, so every worksheet opened with the same sentence twice.
            # Only the FIRST heading is eligible — a later section that happens
            # to share the title's wording is real content and stays.
            if (not seen_heading and want_title
                    and html.unescape(raw).strip() == want_title):
                seen_heading = True
                i += 1
                continue
            seen_heading = True
            lvl = min(len(h.group(1)) + 1, 6)   # shift down: page owns <h1>
            body = _inline(raw, ctx)
            out.append(f'<h{lvl} id="{_slug_id(body, used_ids)}">{body}</h{lvl}>')
            i += 1
            continue

        q = _QUOTE.match(line)
        if q:
            close_lists()
            body = []
            while i < n and _QUOTE.match(lines[i]):
                body.append(_QUOTE.match(lines[i]).group(1))
                i += 1
            out.append(f"<blockquote><p>{_inline(' '.join(body), ctx)}</p></blockquote>")
            continue

        # table: a header row followed by a |---|---| separator
        if "|" in line and i + 1 < n and _TABLE_SEP.match(lines[i + 1]):
            close_lists()
            def cells(s):
                return [c.strip() for c in s.strip().strip("|").split("|")]
            head = cells(line)
            i += 2
            rows = []
            while i < n and "|" in lines[i] and lines[i].strip():
                rows.append(cells(lines[i]))
                i += 1
            th = "".join(f"<th>{_inline(c, ctx)}</th>" for c in head)
            tb = "".join("<tr>" + "".join(f"<td>{_inline(c, ctx)}</td>" for c in r) + "</tr>"
                         for r in rows)
            out.append(f"<table><thead><tr>{th}</tr></thead><tbody>{tb}</tbody></table>")
            continue

        m = _ULI.match(line) or _OLI.match(line)
        if m:
            want = "ul" if _ULI.match(line) else "ol"
            if not list_stack or list_stack[-1] != want:
                # Read the resume state BEFORE closing: close_lists() clears it,
                # and on the resume path the list is already closed (the blank
                # line above the code block did it), so the call here is the
                # no-op that would otherwise throw the count away.
                #
                # And resume only if the author AGREES: the number they typed
                # has to be the one the resumed list would produce. Indentation
                # alone is a good heuristic but not a proof — an indented note
                # under the last step of Part 1 keeps the count alive across the
                # heading-less gap to Part 2, whose "1." would then render as 3.
                # Written numbers settle it. Nothing is guessed: where the author
                # left the numbers lazy (every item `1.`) there is no agreement
                # to find, and the list simply starts over, exactly as before.
                wrote = int(re.match(r"^\s*(\d+)", line).group(1)) if want == "ol" else 0
                resuming = (want == "ol" and ol_broken and ol_items > 0
                            and wrote == ol_items + 1)
                close_lists(soft=indented(line))
                list_stack.append(want)
                if resuming:
                    out.append(f'<ol start="{ol_items + 1}">')
                else:
                    if want == "ol":
                        # Preserve an explicitly authored starting number.
                        # ol_items tracks the last displayed number, not item count.
                        ol_items = wrote - 1
                        if wrote > 1:
                            out.append(f'<ol start="{wrote}">')
                        else:
                            out.append("<ol>")
                    else:
                        out.append("<ul>")
                # A <ul> nested under an ordered step (the "capture all of:"
                # bullets in week 14) must not clear the outer count — only an
                # <ol> actually re-opening does.
                if want == "ol":
                    ol_broken = False
            if want == "ol":
                ol_items += 1
            # Absorb the item's soft-wrapped continuation lines, the same way
            # the paragraph branch below does. Without this a bullet whose text
            # wrapped was cut in half: the <li> closed early, the list closed,
            # and the remainder became a paragraph — so any emphasis straddling
            # the wrap lost its pair and showed as literal asterisks. That is
            # what put stray `**` on thirty-odd published pages, and it read as
            # a broken sentence in the middle of a lab instruction.
            item = [m.group(1)]
            i += 1
            while i < n and lines[i].strip() and not (
                    _HEADING.match(lines[i]) or _ULI.match(lines[i]) or
                    _OLI.match(lines[i]) or _RULE.match(lines[i]) or
                    _QUOTE.match(lines[i]) or _TABLE_SEP.match(lines[i]) or
                    lines[i].lstrip().startswith("```")):
                item.append(lines[i].strip())
                i += 1
            out.append(f"<li>{_inline(' '.join(item), ctx)}</li>")
            continue

        close_lists(soft=indented(line))
        para = []
        while i < n and lines[i].strip() and not (
                _HEADING.match(lines[i]) or _ULI.match(lines[i]) or
                _OLI.match(lines[i]) or _RULE.match(lines[i]) or
                _QUOTE.match(lines[i]) or lines[i].lstrip().startswith("```")):
            para.append(lines[i].strip())
            i += 1
        out.append(f"<p>{_inline(' '.join(para), ctx)}</p>")

    close_lists()
    return "\n".join(out)


def render_document(slug: str, kind: str, course_slug: str | None = None) -> dict | None:
    md = read(slug, kind, course_slug)
    if md is None:
        return None
    c = course(course_slug)
    if kind == "slides":
        _m = unit_re(c.get("unit", "week")).match(slug)
        _p = _slides_path(_m.group(1), course_slug) if _m else None
        title = (_title_of(_p) if _p else None) or f"Slides — {slug}"
        # A deck is a Marp source, not prose: drop the frontmatter and the
        # lecturer's own speaker notes before anything else looks at it.
        md = strip_slide_chrome(md)
        # The WEEK'S OWN unit dir (where its img/ actually lives), not the
        # physically separate slides/ dir the .md source lives in. Using
        # os.path.dirname(_p) here (slides/) meant every relative image or
        # link in a deck silently failed: slides/ isn't even inside
        # c["root"] (labs/), so _resolve_repo_image/_resolve_repo_link's
        # root-containment check rejected it before the img/-shape check
        # ever ran, and the raw `![alt](src)` markdown rendered verbatim.
        # No prior deck had ever referenced an image, so this had never
        # fired — caught by week01's first one.
        #
        # `slug` itself, not `_m.group(1)` (unit_re's capture is only the
        # digits, "01" — the join target this fix needs is the whole
        # directory name, "week01-threat-modeling", which `slug` already is).
        src_dir = (os.path.realpath(os.path.join(c["root"], slug))
                  if _m else os.path.realpath(c["root"]))
    else:
        src = os.path.join(c["root"], slug, PUBLIC_FILES[kind])
        title = _title_of(src) or slug
        src_dir = os.path.dirname(os.path.realpath(src))
    body = render(md, title=title, ctx={"course": c["slug"], "dir": src_dir})
    return {"slug": slug, "kind": kind, "title": title, "html": body,
            "outline": outline(body),
            "course": c["slug"], "course_title": c["title"]}
