from app.scanner.checks.exposure_paths import classify_exposure_path


def test_exposed_env_file_is_critical_and_redacted() -> None:
    issues = classify_exposure_path(
        "/.env",
        "https://example.com/.env",
        200,
        "DATABASE_URL=postgres://user:secret@db\nAPP_KEY=super-secret",
        "text/plain",
    )

    assert len(issues) == 1
    assert issues[0].title == "Exposed .env file"
    assert issues[0].severity == "critical"
    assert "super-secret" not in (issues[0].evidence or "")
    assert "[redacted sensitive file content]" in (issues[0].evidence or "")


def test_exposed_git_head_is_high_severity() -> None:
    issues = classify_exposure_path(
        "/.git/HEAD",
        "https://example.com/.git/HEAD",
        200,
        "ref: refs/heads/main\n",
        "text/plain",
    )

    assert len(issues) == 1
    assert issues[0].title == "Exposed .git metadata"
    assert issues[0].severity == "high"
    assert "ref: refs/heads/main" in (issues[0].evidence or "")


def test_exposed_wp_config_backup_is_critical_and_redacted() -> None:
    issues = classify_exposure_path(
        "/wp-config.php.bak",
        "https://example.com/wp-config.php.bak",
        200,
        "define('DB_PASSWORD', 'secret-password'); define('DB_NAME', 'wordpress');",
        "text/plain",
    )

    assert len(issues) == 1
    assert issues[0].title == "Exposed WordPress config backup"
    assert issues[0].severity == "critical"
    assert "secret-password" not in (issues[0].evidence or "")


def test_safe_404_creates_no_finding() -> None:
    issues = classify_exposure_path(
        "/.env",
        "https://example.com/.env",
        404,
        "not found",
        "text/html",
    )

    assert issues == []


def test_sql_backup_detection() -> None:
    issues = classify_exposure_path(
        "/backup.sql",
        "https://example.com/backup.sql",
        200,
        "CREATE TABLE users (id int); INSERT INTO users VALUES (1);",
        "application/sql",
    )

    assert len(issues) == 1
    assert issues[0].title == "Exposed SQL backup"
    assert issues[0].severity == "critical"


def test_backup_archive_detection() -> None:
    issues = classify_exposure_path(
        "/backup.zip",
        "https://example.com/backup.zip",
        200,
        None,
        "application/zip",
    )

    assert len(issues) == 1
    assert issues[0].title == "Exposed backup archive"
    assert issues[0].severity == "high"


def test_dedupe_key_is_one_per_path() -> None:
    first = classify_exposure_path(
        "/.git/HEAD",
        "https://example.com/.git/HEAD",
        200,
        "ref: refs/heads/main\n",
        "text/plain",
    )[0]
    second = classify_exposure_path(
        "/.git/HEAD",
        "https://example.com/.git/HEAD",
        200,
        "ref: refs/heads/develop\n",
        "text/plain",
    )[0]

    assert first.dedupe_key == second.dedupe_key
