from app.scanner.fingerprints.scripts import detect_from_script_src


def test_script_based_library_detection() -> None:
    html = '<script src="/static/js/jquery.min.js"></script>'
    matches = detect_from_script_src(html)

    assert len(matches) == 1
    assert matches[0].product_name == "jQuery"


def test_version_extraction_from_script_src() -> None:
    html = '<script src="https://cdn.example.com/react-18.3.1.min.js"></script>'
    matches = detect_from_script_src(html)

    assert len(matches) == 1
    assert matches[0].product_name == "React"
    assert matches[0].version == "18.3.1"


def test_jquery_version_extraction_from_filename() -> None:
    html = '<script src="/assets/jquery-3.7.1.min.js"></script>'
    matches = detect_from_script_src(html)

    assert len(matches) == 1
    assert matches[0].product_name == "jQuery"
    assert matches[0].version == "3.7.1"


def test_wordpress_version_extraction_from_script_query_string() -> None:
    html = '<script src="/wp-includes/js/wp-embed.min.js?ver=6.5.3"></script>'
    matches = detect_from_script_src(html)

    assert len(matches) == 1
    assert matches[0].product_name == "WordPress"
    assert matches[0].version == "6.5.3"


def test_js_library_version_extraction_from_query_string() -> None:
    html = '<script src="/assets/swiper.min.js?ver=11.0.5"></script>'
    matches = detect_from_script_src(html)

    assert len(matches) == 1
    assert matches[0].product_name == "Swiper"
    assert matches[0].version == "11.0.5"


def test_jquery_migrate_version_extraction_from_filename() -> None:
    html = '<script src="/assets/jquery-migrate-3.4.1.min.js"></script>'
    matches = detect_from_script_src(html)

    assert len(matches) == 1
    assert matches[0].product_name == "jQuery Migrate"
    assert matches[0].version == "3.4.1"


def test_bootstrap_version_extraction_from_query_string() -> None:
    html = '<script src="/assets/bootstrap.bundle.min.js?ver=5.3.3"></script>'
    matches = detect_from_script_src(html)

    assert len(matches) == 1
    assert matches[0].product_name == "Bootstrap"
    assert matches[0].version == "5.3.3"
