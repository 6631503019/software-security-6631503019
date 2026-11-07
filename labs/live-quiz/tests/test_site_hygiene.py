"""Regression tests for the site-wide defects a full audit of the live site found.

Every test here corresponds to something that was ACTUALLY BROKEN in production,
not to a hypothetical. They are grouped by the failure they prevent, because the
value of each one is "this specific thing came back".

The expensive lesson behind the first group: an unreadable file (mode 0600 after
an rsync) 500'd a linked page for weeks. Git tracks only the exec bit, so no
diff, review or CI job could have shown it — only a request could.
"""

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import content as C          # noqa: E402
from app import app as flask_app   # noqa: E402


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    return flask_app.test_client()


def _course():
    return C.COURSES[0]["slug"]


# ── an unreadable file must 404, never 500 ─────────────────────────────────

def test_unreadable_document_is_treated_as_missing(tmp_path, monkeypatch):
    """A file mode a deploy got wrong must not hand a student a stack trace."""
    p = tmp_path / "locked.md"
    p.write_text("# Secret\n")
    p.chmod(0o000)
    try:
        assert C._slurp(str(p)) is None
        assert C._title_of(str(p)) is None
    finally:
        p.chmod(0o644)          # so pytest's tmp cleanup can remove it


def test_every_linked_document_kind_actually_renders():
    """The week14 README 500'd in production while every sibling served fine.

    Walks what the course index ADVERTISES and renders each one, so a document
    the site links but cannot produce fails here instead of in class.
    """
    broken = []
    for c in C.COURSES:
        for w in C.list_weeks(c["slug"]):
            for kind in w["available"]:
                if C.render_document(w["slug"], kind, c["slug"]) is None:
                    broken.append(f"{c['slug']}/{w['slug']}/{kind}")
    assert not broken, f"linked but unrenderable: {broken}"


# ── repo-relative markdown links ───────────────────────────────────────────

def test_no_rendered_document_emits_a_repo_relative_md_link():
    """`[x](../../SUBMISSION.md)` rendered verbatim resolves against /learn/...
    and 404s. It did, on 47 of 124 document pages."""
    offenders = []
    for c in C.COURSES:
        for w in C.list_weeks(c["slug"]):
            for kind in w["available"]:
                doc = C.render_document(w["slug"], kind, c["slug"])
                if doc and re.search(r'href="\.\.?/[^"]*\.md"', doc["html"]):
                    offenders.append(f"{c['slug']}/{w['slug']}/{kind}")
    assert not offenders, f"repo-relative .md links still linked: {offenders}"


def test_course_root_docs_resolve_and_serve(client):
    """SUBMISSION.md is linked from thirteen worksheets; it must be a real page."""
    slug = _course()
    names = [d["name"] for d in C.list_course_docs(slug)]
    assert "submission" in names
    r = client.get(f"/learn/{slug}/doc/submission")
    assert r.status_code == 200


def test_repo_relative_links_are_rewritten_not_merely_dropped():
    """The no-broken-links test above is satisfied by degrading a link to plain
    text, so on its own it would still pass if resolution stopped working. This
    asserts the useful half: the link a student needs is a LINK, and it goes
    somewhere that answers 200.

    Renders the worksheet specifically, not `w["primary"]` — content.PRIMARY_ORDER
    now prefers slides for an ordinary week, so `primary` is no longer where
    SUBMISSION.md gets linked from (that's still the worksheet, per
    test_course_root_docs_resolve_and_serve's own docstring). Weeks without a
    worksheet (exam/review/practical/capstone) fall back to `primary`, same as
    before, so this still exercises every week's default reading.
    """
    slug = _course()
    linked = set()
    for w in C.list_weeks(slug):
        kind = "worksheet" if "worksheet" in w["available"] else w["primary"]
        doc = C.render_document(w["slug"], kind, slug)
        linked.update(re.findall(r'href="(/learn/[^"]*/doc/[^"]*)"', doc["html"]))
    assert f"/learn/{slug}/doc/submission" in linked, (
        "no worksheet linked SUBMISSION.md as a resolved URL — either the "
        "fixture changed or link resolution regressed")
    # and every URL it produced is one this app will actually serve
    valid = {f"/learn/{slug}/doc/{d['name']}" for d in C.list_course_docs(slug)}
    assert linked <= valid, f"resolved to URLs that do not exist: {linked - valid}"


def test_week_to_week_relative_link_resolves_to_the_on_site_url():
    """`../week16-capstone/worksheet.md` must become /learn/<c>/week16-.../worksheet."""
    slug = _course()
    md = "[the capstone](../week16-capstone/worksheet.md)"
    root = os.path.realpath(C.course(slug)["root"])
    if not os.path.isdir(os.path.join(root, "week16-capstone")):
        pytest.skip("fixture course has no week16-capstone")
    out = C.render(md, ctx={"course": slug,
                            "dir": os.path.join(root, "week19-final-ctf-capstone")})
    assert f'href="/learn/{slug}/week16-capstone/worksheet"' in out


@pytest.mark.parametrize("name", ["../../../etc/passwd", "..", "", "nope",
                                  "instructor", "SUBMISSION.md"])
def test_course_doc_names_outside_the_allowlist_are_refused(client, name):
    assert C.render_course_doc(name, _course()) is None
    assert client.get(f"/learn/{_course()}/doc/{name}").status_code in (404, 308)


# ── legacy redirects must find the OWNING course ───────────────────────────

def test_legacy_week_url_redirects_into_the_course_that_owns_it(client):
    """Hardcoding COURSES[0] sent every cryptography legacy URL into
    software-security, where it 404'd — and a live crypto page emits six."""
    for c in C.COURSES:
        weeks = C.list_weeks(c["slug"])
        if not weeks:
            continue
        r = client.get(f"/learn/{weeks[0]['slug']}")
        assert r.status_code == 301
        assert f"/learn/{c['slug']}/" in r.headers["Location"], (
            f"{weeks[0]['slug']} belongs to {c['slug']} but went to "
            f"{r.headers['Location']}")
        assert client.get(r.headers["Location"]).status_code == 200


# ── headers every response needs ───────────────────────────────────────────

@pytest.mark.parametrize("path", ["/", "/login", "/register", "/quiz",
                                  "/submit", "/play", "/learn", "/sim"])
def test_every_public_page_carries_a_csp(client, path):
    """/ and /login — the page with the password form — had no CSP at all."""
    csp = client.get(path).headers.get("Content-Security-Policy", "")
    assert "default-src 'none'" in csp
    assert "unsafe-inline" not in csp


def test_learn_plane_keeps_its_stricter_script_free_policy(client):
    """The app-wide default must never widen the content plane, which renders
    worksheets containing live XSS payloads."""
    csp = client.get(f"/learn/{_course()}/").headers["Content-Security-Policy"]
    assert "script-src" not in csp
    assert "form-action 'none'" in csp


@pytest.mark.parametrize("path", ["/", "/login", "/learn"])
def test_head_mirrors_get(client, path):
    """HEAD /login answered 400: Flask dispatches HEAD to the GET view, and the
    `== "GET"` test dropped it into the POST branch's CSRF check."""
    assert client.head(path).status_code == client.get(path).status_code


def test_security_headers_are_not_duplicated(client):
    r = client.get("/learn")
    assert len(r.headers.get_all("X-Content-Type-Options")) == 1
    assert len(r.headers.get_all("Content-Security-Policy")) == 1


# ── discoverability ────────────────────────────────────────────────────────

def test_robots_and_sitemap_are_served(client):
    rb = client.get("/robots.txt")
    assert rb.status_code == 200 and "text/plain" in rb.headers["Content-Type"]
    assert b"Disallow: /login" in rb.data and b"Allow: /learn" in rb.data

    sm = client.get("/sitemap.xml")
    assert sm.status_code == 200 and "xml" in sm.headers["Content-Type"]
    body = sm.data.decode()
    assert f"/learn/{_course()}/" in body
    for w in C.list_weeks(_course()):
        assert f"/learn/{_course()}/{w['slug']}" in body


def test_pages_carry_description_and_card_metadata(client):
    """Lecturers share these URLs in LINE and Teams; they unfurled as bare
    links, and nothing gave a search engine a snippet to use."""
    html = client.get(f"/learn/{_course()}/").data.decode()
    for needle in ('name="description"', 'property="og:title"',
                   'property="og:image"', 'rel="canonical"', 'rel="icon"'):
        assert needle in html, f"missing {needle}"


def test_favicon_and_card_assets_exist(client):
    for path in ("/static/favicon.svg", "/static/favicon.png",
                 "/static/apple-touch-icon.png", "/static/og-card.png"):
        assert client.get(path).status_code == 200, path


def test_woff2_is_served_as_a_font(client):
    r = client.get("/static/fonts/InterVariable.woff2")
    assert r.status_code == 200
    assert r.headers["Content-Type"] == "font/woff2"
    assert "max-age" in r.headers.get("Cache-Control", "")


# ── the shell must not change shape between pages ──────────────────────────

@pytest.mark.parametrize("path", ["/", "/learn", "/quiz", "/submit",
                                  "/login", "/register"])
def test_every_shell_page_gets_the_course_switcher(client, path):
    """Four routes forgot to pass nav_courses, so the header grew and shrank as
    a student navigated. It comes from a context processor now."""
    html = client.get(path).data.decode()
    assert "lx-tier2" in html, f"{path} is not on the shared shell"
    if len(C.COURSES) > 1:
        assert "lx-tier1" in html, f"{path} lost the course switcher"


def test_reading_page_offers_a_way_onward(client):
    """A 6000px worksheet ended in the footer with no link to the next unit."""
    weeks = C.list_weeks(_course())
    if len(weeks) < 2:
        pytest.skip("needs at least two units")
    html = client.get(f"/learn/{_course()}/{weeks[0]['slug']}").data.decode()
    assert "lx-docnav" in html
    assert weeks[1]["slug"] in html


def test_slides_do_not_leak_frontmatter_or_speaker_notes():
    """Decks are Marp sources. The YAML block and the lecturer's own
    `<!-- Cold-call: ... -->` cues were rendering as student-visible text."""
    checked = 0
    for c in C.COURSES:
        for w in C.list_weeks(c["slug"]):
            if "slides" not in w["available"]:
                continue
            html = C.render_document(w["slug"], "slides", c["slug"])["html"]
            assert "marp: true" not in html, f"{w['slug']} leaks frontmatter"
            assert "&lt;!--" not in html and "<!--" not in html, \
                f"{w['slug']} leaks a speaker note"
            checked += 1
    assert checked, "no decks found — this test would pass vacuously"


# ── the site must not publish URLs a client can choose ─────────────────────

def test_self_referential_urls_ignore_a_forged_host_header(monkeypatch):
    """The sitemap's <loc>, the canonical link and og:url are absolute URLs the
    site publishes ABOUT ITSELF. Derived from request.url_root they come from
    the Host header, so a forged one makes this app hand a crawler, a
    link-preview fetcher or a shared cache URLs on someone else's domain.
    """
    import app as appmod
    monkeypatch.setattr(appmod, "SITE_ORIGIN", "https://learn.example")
    flask_app.config["TESTING"] = True
    c = flask_app.test_client()

    sm = c.get("/sitemap.xml", headers={"Host": "evil.example"}).data.decode()
    assert "evil.example" not in sm
    assert "<loc>https://learn.example/" in sm

    page = c.get("/learn", headers={"Host": "evil.example"}).data.decode()
    assert "evil.example" not in page
    assert 'rel="canonical" href="https://learn.example/learn"' in page

    rb = c.get("/robots.txt", headers={"Host": "evil.example"}).data.decode()
    assert "evil.example" not in rb


# ── "this week" ────────────────────────────────────────────────────────────

def test_current_unit_marker_is_opt_in_and_absent_by_default():
    """19 identical rows and no student accounts means nothing can infer where
    the cohort is; the course states it in $COURSES or the page says nothing.
    A wrong marker is worse than none, so it is never guessed from the date."""
    assert C.current_unit(_course()) in (None, C.COURSES[0].get("current"))
    for c in C.COURSES:
        if not c.get("current"):
            assert C.current_unit(c["slug"]) is None


def test_current_unit_marks_exactly_one_row(monkeypatch, client):
    """It must mark the unit whose number_label matches — not an index, because
    the cloud course really has `7b` and `1–3` as unit numbers."""
    slug = _course()
    weeks = C.list_weeks(slug)
    if not weeks:
        pytest.skip("no units published")
    target = weeks[min(2, len(weeks) - 1)]
    c = dict(C.course(slug)); c["current"] = target["number_label"]
    monkeypatch.setattr(C, "COURSES", [c] + [x for x in C.COURSES if x["slug"] != slug])
    html_out = client.get(f"/learn/{slug}/").data.decode()
    assert html_out.count('aria-current="step"') == 1
    assert html_out.count('id="lx-now"') == 1
    assert "This week" in html_out


# The three courses only appear in C.COURSES when $COURSES is set, which happens
# on the production host and nowhere else — so a test that walks C.COURSES sees
# exactly one course in CI and silently guards a third of what it claims to.
# These content invariants therefore walk THIS repo's own labs/ directory, which
# is always present in a checkout. The cross-course version of the same rule
# lives in the curriculum monorepo, which is the one place every course's
# lessons sit side by side.
_LABS_ROOT = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


# ── no lab may send a student to a port their browser refuses ──────────────

# Chrome, Chromium and Firefox all ship a hard-coded list of ports they will not
# open, to stop the browser being used to speak other protocols. A page telling
# a student to open one of these is not "flaky" — it can never work, on any
# machine, for anyone.
BLOCKED_PORTS = {
    1719, 1720, 1723, 2049, 3659, 4045, 5060, 5061,
    6000,                       # X11 — this is the one that actually bit us
    6566, 6665, 6666, 6667, 6668, 6669, 6697, 10080,
}

_URL_PORT = re.compile(r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0):(\d+)", re.I)


def _lab_docs():
    """Every student-facing markdown file under a week/lesson directory."""
    for root in [_LABS_ROOT]:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, names in os.walk(root):
            for n in names:
                if n.endswith(".md"):
                    yield os.path.join(dirpath, n)


def test_no_worksheet_points_a_browser_at_a_blocked_port():
    """Week 14's insecure chatbot listened on :6000 and its worksheet told
    students to open it in a browser and screenshot the resulting alert. Every
    browser refuses :6000 with ERR_UNSAFE_PORT before the request is sent, so
    that task — 35 minutes of a 40-point band — could not be completed by
    anyone. `curl` reaches :6000 happily and never executes script, which is
    exactly why the curl-based task beside it kept passing and hid the fault.

    Reproduced before the fix with two identical servers: Chromium loaded :6001
    and refused :6000.
    """
    offenders = []
    for path in _lab_docs():
        text = _slurp_text(path)
        if text is None:
            continue
        for port in {int(p) for p in _URL_PORT.findall(text)}:
            if port in BLOCKED_PORTS:
                offenders.append(f"{os.path.relpath(path)} -> :{port}")
    assert not offenders, (
        "these pages tell a student to open a port no browser will load: "
        + "; ".join(sorted(offenders)))


def test_published_compose_files_do_not_bind_a_blocked_port():
    """The other half: the worksheet can only be right if the lab agrees. A
    compose file publishing a blocked port means the next person to write the
    worksheet is led straight back into the same hole."""
    offenders = []
    for root in [_LABS_ROOT]:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, names in os.walk(root):
            for n in names:
                if not (n.startswith("docker-compose") and n.endswith((".yml", ".yaml"))):
                    continue
                path = os.path.join(dirpath, n)
                text = _slurp_text(path)
                if text is None:
                    continue
                for host_port in re.findall(r'["\']?(\d{2,5}):\d{2,5}["\']?', text):
                    if int(host_port) in BLOCKED_PORTS:
                        offenders.append(f"{os.path.relpath(path)} -> :{host_port}")
    assert not offenders, (
        "these labs publish a port no browser will load: " + "; ".join(sorted(offenders)))


def _slurp_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


# ── a graded flag must never appear on a page students read ────────────────

_FLAG_DEFAULT = re.compile(
    r'(?:os\.environ\.get\(\s*["\'](FLAG_[A-Z0-9_]+)["\']\s*,\s*["\']'
    r'|(FLAG_[A-Z0-9_]+)\s*[:=]\s*["\']?)(FLAG\{[^"\'\s}]+\})')


def _flag_defaults(labs_root):
    """Every concrete flag value a lab's own code falls back to. That value IS
    the graded answer for the week — it is what the vulnerable app prints and
    what the worksheet's deliverable asks the student to capture."""
    out = {}
    for dirpath, _dirs, names in os.walk(labs_root):
        for n in names:
            if not n.endswith((".py", ".sh", ".tf", ".yml", ".yaml", ".js")):
                continue
            text = _slurp_text(os.path.join(dirpath, n))
            if text is None:
                continue
            for m in _FLAG_DEFAULT.finditer(text):
                out[m.group(3)] = m.group(1) or m.group(2)
    return out


def test_no_graded_flag_value_is_printed_on_a_reading_page():
    """Six cloud lessons and six cryptography weeks printed the week's own flag
    on the README a student reads BEFORE doing the lab — three times per page in
    some — while the deliverable was "the captured flag" and the integrity
    policy said flags are per-student and sharing one is "a violation for both
    parties". Nobody could earn that flag honestly, because everyone's was the
    same string and it was already on the page.

    The check is a cross-reference, not a word list: a value only counts if the
    lab's own code falls back to it. That is what makes it the answer rather
    than an illustration — a payload, a worked example or a demo value in a
    snippet is none of this test's business.

    Removing the value from the page does not make it secret (it is still in the
    source students clone); it stops the answer being handed to someone who
    never opened the lab. The real fix is the per-student mint the same
    paragraph already points at.
    """
    offenders = []
    for root in [_LABS_ROOT]:
        if not os.path.isdir(root):
            continue
        for value, var in _flag_defaults(root).items():
            for dirpath, _dirs, names in os.walk(root):
                for n in names:
                    if not n.endswith(".md"):
                        continue
                    path = os.path.join(dirpath, n)
                    text = _slurp_text(path)
                    if text and value in text:
                        offenders.append(f"{os.path.relpath(path)} prints {var}'s value")
    assert not offenders, (
        "a graded flag is printed on a page students read: " + "; ".join(sorted(set(offenders))))


# ── instructor material must not drift from the lab it grades ──────────────

# `instructor/` is git-ignored: it exists on the professor's disk and in no
# clone, so no diff, no PR and no CI job can ever show it going stale. That is
# precisely why a worksheet fix can leave its answer key behind, and a stale key
# marks a correct answer wrong.
#
# These tests are the only thing that looks. They SKIP when instructor/ is
# absent — which is every CI run — and do real work on the machine that actually
# has it. A test that silently passes because the thing it checks is missing
# would be worse than no test, so the skip is explicit and says so.
_INSTRUCTOR = os.path.normpath(os.path.join(_LABS_ROOT, "..", "instructor"))

_needs_instructor = pytest.mark.skipif(
    not os.path.isdir(_INSTRUCTOR),
    reason="instructor/ is git-ignored and absent here (expected in CI); "
           "run this on the machine that holds the answer keys")


def _instructor_docs():
    for dirpath, _dirs, names in os.walk(_INSTRUCTOR):
        for n in names:
            if n.endswith((".md", ".py", ".yml", ".yaml")):
                yield os.path.join(dirpath, n)


def _published_ports():
    """Every port a lab legitimately mentions, per week — BOTH sides of each
    `host:container` mapping. The container side counts: `8080:5000` makes 5000
    a real thing for a key to name, and flagging it would train the reader to
    ignore this test."""
    out = {}
    for dirpath, _dirs, names in os.walk(_LABS_ROOT):
        week = os.path.basename(dirpath)
        for n in names:
            if not (n.startswith("docker-compose") and n.endswith((".yml", ".yaml"))):
                continue
            text = _slurp_text(os.path.join(dirpath, n))
            if not text:
                continue
            for a, b in re.findall(r'["\']?(\d{2,5}):(\d{2,5})["\']?', text):
                out.setdefault(week, set()).update((int(a), int(b)))
    return out


# 1990-2099 written as a bare number is a year, not a port. `week04-injection`
# sits one comma away from "2026" in half the exam bank.
_YEARISH = re.compile(r"^(?:19|20)\d{2}$")


@_needs_instructor
def test_instructor_material_cites_no_retired_lab_port():
    """Week 14 moved off :6000 (every browser refuses it). The exam item bank
    and the challenge-image catalogue still said 6000 — and those are what the
    final CTF is built from, so students would have been handed a port nothing
    listens on. Found by grep, not by any gate, which is the whole point.
    """
    live = _published_ports()
    stale = []
    for path in _instructor_docs():
        text = _slurp_text(path)
        if not text:
            continue
        for week, port in re.findall(r"(week\d{2}[a-z]?[\w-]*)[^\n]{0,80}?[:\s](\d{4,5})\b", text):
            # Keys cite the short form (`week14`); the directory is
            # `week14-ai-llm-security`. Resolve by prefix or the lookup silently
            # returns None and the test passes without checking anything — which
            # is exactly what it did until a mutation caught it.
            ports = live.get(week) or next(
                (v for k, v in live.items() if k.startswith(week)), None)
            if ports and not _YEARISH.match(port) and int(port) not in ports:
                stale.append(f"{os.path.relpath(path, _INSTRUCTOR)} cites {week} :{port}, "
                             f"lab publishes {sorted(ports)}")
    assert not stale, "instructor material cites a port the lab no longer uses: " + "; ".join(sorted(set(stale)))


def test_a_command_never_compiles_a_file_the_week_does_not_ship():
    """Week 11 told students to run `clang … harness.c`; it ships
    `fuzz_harness.c`, and its own kickoff line two paragraphs up already said so.

    Two refinements, both forced by evidence rather than taste:

    * PER WEEK, not global. `harness.c` genuinely exists — in week 2 — so a
      "does this filename appear anywhere under labs/" check cannot see the bug.
      I wrote that weaker version first and a mutation proved it blind.
    * COMMANDS ONLY. Restricting it to fenced code blocks is what separates a
      broken instruction from a legitimate cross-reference: week 17 is a review
      of weeks 10-16 and cites week 11's `safe.rs` in prose, which is correct.
      A command, by contrast, runs in the week's own directory.
    """
    offenders = []
    for entry in sorted(os.listdir(_LABS_ROOT)):
        week_dir = os.path.join(_LABS_ROOT, entry)
        # Only real units. `toolbox/` is the shared container students run the
        # labs INSIDE, so its README demonstrating week 11's command is correct,
        # not a defect; `live-quiz/` is the platform itself.
        if not os.path.isdir(week_dir) or not re.match(r"(week|lesson)\d{2}", entry):
            continue
        ships = set(os.listdir(week_dir))
        for name in os.listdir(week_dir):
            if not name.endswith(".md"):
                continue
            text = _slurp_text(os.path.join(week_dir, name))
            if not text:
                continue
            for block in re.findall(r"```[a-z]*\n(.*?)```", text, re.S):
                for cited in set(re.findall(r"(?<![\w/.])([A-Za-z0-9_-]+\.(?:c|rs))\b", block)):
                    if cited not in ships:
                        offenders.append(f"{entry}/{name} runs a command on {cited}, "
                                         f"which that week does not ship")
    assert not offenders, ("a command tells students to build a file the week does "
                           "not ship: " + "; ".join(sorted(set(offenders))))


# ── a step number a student reads must be the number the author wrote ──────

def _authored_item_numbers(text):
    """The number on every line the renderer will treat as an ordered item,
    read the same way it reads them: its own pattern, fenced code skipped."""
    nums, fenced = [], False
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if re.match(r"^\s*```+", line):
            fenced = not fenced
            continue
        if fenced or C._ULI.match(line):
            continue

        # The renderer recognizes a table before it recognizes an ordered list.
        # Do not count a numbered-looking table header as a list item.
        if i + 1 < len(lines) and C._TABLE_SEP.match(lines[i + 1]):
            continue

        if C._OLI.match(line):
            nums.append(int(re.match(r"^\s*(\d+)", line).group(1)))
    return nums


def _rendered_item_numbers(html):
    nums = []
    for m in re.finditer(r'<ol(?: start="(\d+)")?>(.*?)</ol>', html, re.S):
        first = int(m.group(1) or 1)
        nums += list(range(first, first + m.group(2).count("<li>")))
    return nums


def test_every_lab_page_renders_the_step_numbers_its_author_wrote():
    """A worksheet's own cross-references are only as good as its numbering.

    This renderer has no block nesting, so a code block indented under step 1
    closed the list and step 2 opened a fresh one at 1. Four documents in the
    cryptography course rendered their lab steps as 1 · 1,2 · 1 — two different
    things both labelled step 1 and no step 3 — while `week14-authentication`'s
    Submit line asks for "your one-line note from step 1, and the two `grep -c`
    outputs from step 3". The markdown said 1,2,3,4 and always had.

    HONEST SCOPE: this walks the labs of THIS repo only. The four documents that
    were actually broken live in the cryptography repo, so on a bare checkout
    this test proves the renderer does not break the software-security
    worksheets — not that it fixed the ones it was written for. `test_content.py`
    carries the reproduction. Run it where the other course repos are checked
    out and it covers them too.

    Documents that number every item `1.` and let the renderer count are skipped:
    there is no authored sequence to disagree with.
    """
    offenders = []
    for path in _lab_docs():
        text = _slurp_text(path)
        if text is None:
            continue
        authored = _authored_item_numbers(text)
        if not authored or set(authored) == {1}:
            continue
        shown = _rendered_item_numbers(C.render(text))
        if authored != shown:
            i = next((k for k in range(min(len(authored), len(shown)))
                      if authored[k] != shown[k]), 0)
            offenders.append(
                f"{os.path.relpath(path, _LABS_ROOT)}: item #{i + 1} onward reads "
                f"{shown[i:i + 4]}, the author wrote {authored[i:i + 4]}")
    assert not offenders, (
        "these pages renumber their own steps, so any 'see step N' in them points "
        "at the wrong thing: " + "; ".join(sorted(offenders)))
