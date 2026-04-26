from app.scanner.checks.file_upload import check_file_upload_forms


def test_upload_form_detected() -> None:
    issues = check_file_upload_forms(
        "https://example.com/profile",
        """
        <form method="post" action="/avatar" enctype="multipart/form-data">
          <input type="hidden" name="csrf_token" value="secret">
          <input type="file" name="avatar" accept="image/png,image/jpeg">
        </form>
        """,
    )

    assert len(issues) == 1
    assert issues[0].category == "file_upload"
    assert issues[0].title == "File upload form detected"
    assert issues[0].severity == "info"
    assert "file_inputs=avatar" in (issues[0].evidence or "")


def test_upload_form_missing_csrf() -> None:
    issues = check_file_upload_forms(
        "https://example.com/profile",
        """
        <form method="post" action="/avatar" enctype="multipart/form-data">
          <input type="file" name="avatar" accept="image/png">
        </form>
        """,
    )

    titles = {issue.title for issue in issues}
    assert "File upload form missing CSRF token" in titles
    assert any(
        issue.title == "File upload form missing CSRF token"
        and issue.severity == "medium"
        for issue in issues
    )


def test_upload_form_with_accept_attribute_has_no_accept_finding() -> None:
    issues = check_file_upload_forms(
        "https://example.com/profile",
        """
        <form method="post" action="/avatar" enctype="multipart/form-data">
          <input type="hidden" name="_token" value="secret">
          <input type="file" name="avatar" accept="image/png">
        </form>
        """,
    )

    titles = {issue.title for issue in issues}
    assert "File upload form detected" in titles
    assert "File upload form missing file type restrictions" not in titles


def test_upload_form_missing_multipart_enctype() -> None:
    issues = check_file_upload_forms(
        "https://example.com/profile",
        """
        <form method="post" action="/avatar">
          <input type="hidden" name="csrf_token" value="secret">
          <input type="file" name="avatar" accept="image/png">
        </form>
        """,
    )

    titles = {issue.title for issue in issues}
    assert "File upload form missing multipart enctype" in titles


def test_upload_evidence_does_not_store_input_values() -> None:
    issues = check_file_upload_forms(
        "https://example.com/profile",
        """
        <form method="post" action="/avatar">
          <input type="hidden" name="csrf_token" value="super-secret-token">
          <input type="file" name="avatar" accept="image/png">
          <input name="caption" value="private caption">
        </form>
        """,
    )

    evidence = " ".join(issue.evidence or "" for issue in issues)
    assert "super-secret-token" not in evidence
    assert "private caption" not in evidence
    assert "file_inputs=avatar" in evidence


def test_upload_duplicate_prevention() -> None:
    html = """
    <form method="post" action="/avatar">
      <input type="file" name="avatar">
    </form>
    <form method="post" action="/avatar">
      <input type="file" name="profile_photo">
    </form>
    """
    issues = check_file_upload_forms("https://example.com/profile", html)
    detected = [
        issue for issue in issues if issue.title == "File upload form detected"
    ]

    assert len(detected) == 1
