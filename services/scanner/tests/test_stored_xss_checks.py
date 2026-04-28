import asyncio
import html

from app.scanner.checks.stored_xss import (
    build_stored_xss_payload,
    build_stored_xss_submission,
    check_stored_xss_response,
    classify_stored_xss_context,
    is_same_origin,
    select_safe_stored_xss_forms,
    verify_stored_xss_execution,
)


CONTACT_FORM = """
<form method="post" action="/contact">
  <input type="hidden" name="csrf_token" value="abc123">
  <input name="name" required>
  <input type="email" name="email" required>
  <textarea name="message" required></textarea>
  <button>Send feedback</button>
</form>
"""


def test_safe_contact_form_selected() -> None:
    forms = select_safe_stored_xss_forms(
        "https://example.com/contact",
        CONTACT_FORM,
        max_forms=3,
    )

    assert len(forms) == 1
    assert forms[0].action_url == "https://example.com/contact"


def test_login_form_skipped() -> None:
    forms = select_safe_stored_xss_forms(
        "https://example.com/login",
        """
        <form method="post" action="/login">
          <input name="username">
          <input type="password" name="password">
          <button>Login</button>
        </form>
        """,
        max_forms=3,
    )

    assert forms == []


def test_admin_form_skipped() -> None:
    forms = select_safe_stored_xss_forms(
        "https://example.com/admin/comments",
        """
        <form method="post" action="/wp-admin/comment">
          <textarea name="comment"></textarea>
          <button>Update comment</button>
        </form>
        """,
        max_forms=3,
    )

    assert forms == []


def test_file_upload_form_skipped() -> None:
    forms = select_safe_stored_xss_forms(
        "https://example.com/contact",
        """
        <form method="post" action="/contact">
          <input type="file" name="attachment">
          <textarea name="message"></textarea>
          <button>Send feedback</button>
        </form>
        """,
        max_forms=3,
    )

    assert forms == []


def test_same_origin_enforcement() -> None:
    assert is_same_origin("https://example.com/a", "https://example.com/b")
    assert not is_same_origin("https://example.com/a", "https://evil.example/b")

    forms = select_safe_stored_xss_forms(
        "https://example.com/contact",
        """
        <form method="post" action="https://evil.example/contact">
          <textarea name="message"></textarea>
          <button>Send feedback</button>
        </form>
        """,
        max_forms=3,
    )

    assert forms == []


def test_payload_submission_construction() -> None:
    form = select_safe_stored_xss_forms(
        "https://example.com/contact",
        CONTACT_FORM,
        max_forms=1,
    )[0]
    marker = "SCANNER_MARKER_UNIQUE"
    submission = build_stored_xss_submission(form, marker)

    assert submission is not None
    assert submission["name"] == "WebScanner"
    assert submission["email"] == "scanner@example.com"
    assert submission["csrf_token"] == "abc123"
    assert submission["message"] == build_stored_xss_payload(marker)


def test_raw_stored_marker_detection() -> None:
    form = select_safe_stored_xss_forms(
        "https://example.com/contact",
        CONTACT_FORM,
        max_forms=1,
    )[0]
    marker = "SCANNER_MARKER_UNIQUE"
    issues = check_stored_xss_response(
        form=form,
        marker=marker,
        revisit_url="https://example.com/reviews",
        response_body=f"<article>{marker}</article>",
    )

    assert len(issues) == 1
    assert issues[0].category == "stored_xss"
    assert issues[0].severity == "medium"
    assert issues[0].confidence == "medium"
    assert "context=html_body" in (issues[0].evidence or "")


def test_escaped_marker_low_confidence_detection() -> None:
    marker = "SCANNER_MARKER_UNIQUE"
    payload = build_stored_xss_payload(marker)
    detection = classify_stored_xss_context(
        marker,
        payload,
        f"<p>{html.escape(payload)}</p>",
    )

    assert detection is not None
    assert detection.context == "escaped"
    assert detection.severity == "low"
    assert detection.confidence == "low"


def test_script_block_context_detection() -> None:
    marker = "SCANNER_MARKER_UNIQUE"
    payload = build_stored_xss_payload(marker)
    detection = classify_stored_xss_context(
        marker,
        payload,
        f"<script>window.__WEBSCANNER_STORED_XSS__='{marker}'</script>",
    )

    assert detection is not None
    assert detection.context == "javascript_string"
    assert detection.severity == "high"


def test_browser_verification_skipped_if_disabled() -> None:
    verified = asyncio.run(
        verify_stored_xss_execution(
            ["https://example.com/comment"],
            "SCANNER_MARKER_UNIQUE",
            enabled=False,
        )
    )

    assert verified == set()


def test_duplicate_prevention_key_stable_for_same_form_revisit_context() -> None:
    form = select_safe_stored_xss_forms(
        "https://example.com/contact",
        CONTACT_FORM,
        max_forms=1,
    )[0]
    first = check_stored_xss_response(
        form=form,
        marker="SCANNER_MARKER_ONE",
        revisit_url="https://example.com/reviews",
        response_body="<p>SCANNER_MARKER_ONE</p>",
    )[0]
    second = check_stored_xss_response(
        form=form,
        marker="SCANNER_MARKER_TWO",
        revisit_url="https://example.com/reviews",
        response_body="<p>SCANNER_MARKER_TWO</p>",
    )[0]

    assert first.dedupe_key == second.dedupe_key
    assert "SCANNER_MARKER" not in (first.evidence or "")


def test_max_form_limit() -> None:
    html_content = """
    <form method="post" action="/contact">
      <textarea name="message"></textarea><button>Contact us</button>
    </form>
    <form method="post" action="/feedback">
      <textarea name="feedback"></textarea><button>Send feedback</button>
    </form>
    <form method="post" action="/review">
      <textarea name="review"></textarea><button>Leave review</button>
    </form>
    """
    forms = select_safe_stored_xss_forms(
        "https://example.com/contact",
        html_content,
        max_forms=2,
    )

    assert len(forms) == 2
