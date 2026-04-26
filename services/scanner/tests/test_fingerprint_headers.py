from app.scanner.fingerprints.headers import detect_from_headers


def test_server_header_detection() -> None:
    matches = detect_from_headers({"server": "nginx/1.25.5"})

    assert len(matches) == 1
    assert matches[0].product_name == "nginx"
    assert matches[0].version == "1.25.5"


def test_x_powered_by_framework_detection() -> None:
    matches = detect_from_headers({"x-powered-by": "Express"})

    assert len(matches) == 1
    assert matches[0].product_name == "Express"
    assert matches[0].detection_method == "response_header"


def test_apache_version_detected_only_when_explicit() -> None:
    matches = detect_from_headers({"server": "Apache/2.4.58 (Unix)"})

    assert len(matches) == 1
    assert matches[0].product_name == "Apache HTTP Server"
    assert matches[0].version == "2.4.58"


def test_apache_version_not_guessed_when_missing() -> None:
    matches = detect_from_headers({"server": "Apache"})

    assert len(matches) == 1
    assert matches[0].product_name == "Apache HTTP Server"
    assert matches[0].version is None


def test_php_version_detected_only_when_explicit() -> None:
    matches = detect_from_headers({"x-powered-by": "PHP/8.2.17"})

    assert len(matches) == 1
    assert matches[0].product_name == "PHP"
    assert matches[0].version == "8.2.17"


def test_php_version_not_guessed_when_missing() -> None:
    matches = detect_from_headers({"x-powered-by": "PHP"})

    assert len(matches) == 1
    assert matches[0].product_name == "PHP"
    assert matches[0].version is None
