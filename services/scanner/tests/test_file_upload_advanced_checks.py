from app.scanner.checks.file_upload_advanced import check_file_upload_advanced


def test_detects_risky_extension_accept() -> None:
    issues = check_file_upload_advanced(
        "https://example.com/upload",
        """
        <form method="post" action="/upload" enctype="multipart/form-data">
          <input type="hidden" name="csrf_token" value="secret">
          <label>Upload PNG only, max 2MB</label>
          <input type="file" name="avatar" accept=".php">
        </form>
        """,
    )

    assert any(
        issue.title == "File upload form allows risky file types"
        and issue.severity == "high"
        and "risky=.php" in (issue.evidence or "")
        for issue in issues
    )


def test_detects_wildcard_accept() -> None:
    issues = check_file_upload_advanced(
        "https://example.com/upload",
        """
        <form method="post" action="/upload" enctype="multipart/form-data">
          <input type="hidden" name="_nonce" value="secret">
          <p>Allowed file type: PNG, max 2MB</p>
          <input type="file" name="document" accept="*/*">
        </form>
        """,
    )

    assert any(
        issue.title == "File upload form uses broad accept wildcard"
        and issue.severity == "medium"
        and "wildcard=*/*" in (issue.evidence or "")
        for issue in issues
    )


def test_detects_svg_risk() -> None:
    issues = check_file_upload_advanced(
        "https://example.com/upload",
        """
        <form method="post" action="/upload" enctype="multipart/form-data">
          <input type="hidden" name="csrf_token" value="secret">
          <p>Allowed SVG icon, max 50KB</p>
          <input type="file" name="icon" accept=".svg,image/svg+xml">
        </form>
        """,
    )

    assert any(
        issue.title == "File upload form allows risky file types"
        and ".svg" in (issue.evidence or "")
        and "image/svg+xml" in (issue.evidence or "")
        for issue in issues
    )


def test_detects_https_page_posting_to_http_action() -> None:
    issues = check_file_upload_advanced(
        "https://example.com/profile",
        """
        <form method="post" action="http://example.com/upload" enctype="multipart/form-data">
          <input type="hidden" name="csrf_token" value="secret">
          <p>PNG only, max 2MB</p>
          <input type="file" name="avatar" accept=".png">
        </form>
        """,
    )

    assert any(
        issue.title == "File upload form uses insecure action URL"
        and issue.severity == "high"
        for issue in issues
    )


def test_detects_missing_csrf_token() -> None:
    issues = check_file_upload_advanced(
        "https://example.com/upload",
        """
        <form method="post" action="/upload" enctype="multipart/form-data">
          <p>PNG only, max 2MB</p>
          <input type="file" name="avatar" accept=".png">
        </form>
        """,
    )

    assert any(issue.title == "File upload form missing CSRF token" for issue in issues)


def test_detects_multiple_upload() -> None:
    issues = check_file_upload_advanced(
        "https://example.com/upload",
        """
        <form method="post" action="/upload" enctype="multipart/form-data">
          <input type="hidden" name="csrf_token" value="secret">
          <p>PNG only, max 2MB</p>
          <input type="file" name="photos" accept=".png" multiple>
        </form>
        """,
    )

    assert any(issue.title == "Multiple file upload enabled" for issue in issues)


def test_safe_image_only_upload_produces_only_low_or_informational() -> None:
    issues = check_file_upload_advanced(
        "https://example.com/upload",
        """
        <form method="post" action="/upload" enctype="multipart/form-data">
          <input type="hidden" name="csrf_token" value="secret">
          <p>PNG or JPEG only, max 2MB</p>
          <input type="file" name="avatar" accept=".png,.jpg,.jpeg" required>
        </form>
        """,
    )

    assert all(issue.severity in {"info", "low"} for issue in issues)


def test_evidence_does_not_store_values() -> None:
    issues = check_file_upload_advanced(
        "https://example.com/upload",
        """
        <form method="post" action="/upload">
          <input type="hidden" name="csrf_token" value="super-secret-token">
          <input name="caption" value="private caption">
          <input type="file" name="avatar" accept=".php">
        </form>
        """,
    )
    evidence = " ".join(issue.evidence or "" for issue in issues)

    assert "super-secret-token" not in evidence
    assert "private caption" not in evidence
    assert "avatar" in evidence


def test_duplicate_prevention() -> None:
    issues = check_file_upload_advanced(
        "https://example.com/upload",
        """
        <form method="post" action="/upload">
          <input type="file" name="avatar">
        </form>
        <form method="post" action="/upload">
          <input type="file" name="document">
        </form>
        """,
    )
    missing_accept = [
        issue
        for issue in issues
        if issue.title == "File upload form missing file type restrictions"
    ]

    assert len(missing_accept) == 1
