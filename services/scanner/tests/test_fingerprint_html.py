from app.scanner.fingerprints.html import detect_from_html


def test_meta_generator_extraction() -> None:
    html = '<meta name="generator" content="WordPress 6.5.2">'
    matches = detect_from_html(html)

    assert len(matches) == 1
    assert matches[0].product_name == "WordPress"
    assert matches[0].version == "6.5.2"
    assert matches[0].detection_method == "meta_generator"


def test_wordpress_version_from_core_asset_query_string() -> None:
    html = '<script src="/wp-includes/js/wp-emoji-release.min.js?ver=6.6.1"></script>'
    matches = detect_from_html(html)

    wordpress_matches = [
        match
        for match in matches
        if match.product_name == "WordPress" and match.version == "6.6.1"
    ]

    assert len(wordpress_matches) == 1
    assert wordpress_matches[0].version == "6.6.1"


def test_plugin_asset_query_string_does_not_create_wordpress_core_version() -> None:
    html = (
        '<script src="/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.35.5"></script>'
    )
    matches = detect_from_html(html)

    wordpress_core_matches = [
        match
        for match in matches
        if match.product_name == "WordPress"
        and match.category == "cms"
        and match.version == "3.35.5"
    ]

    assert wordpress_core_matches == []


def test_wordpress_plugin_slug_extraction() -> None:
    html = '<script src="/wp-content/plugins/contact-form-7/includes/js/index.js"></script>'
    matches = detect_from_html(html)

    plugin_matches = [
        match for match in matches if match.product_name == "WordPress Plugin: contact-form-7"
    ]
    assert len(plugin_matches) == 1
    assert plugin_matches[0].product_name == "WordPress Plugin: contact-form-7"
    assert plugin_matches[0].version is None


def test_wordpress_plugin_version_extraction_from_query_string() -> None:
    html = (
        '<script src="/wp-content/plugins/woocommerce/assets/js/frontend.min.js?ver=9.1.4"></script>'
    )
    matches = detect_from_html(html)

    plugin_matches = [
        match for match in matches if match.product_name == "WordPress Plugin: woocommerce"
    ]

    assert len(plugin_matches) == 1
    assert plugin_matches[0].version == "9.1.4"


def test_wordpress_theme_slug_extraction() -> None:
    html = '<link rel="stylesheet" href="/wp-content/themes/astra/style.css?ver=1.0.0">'
    matches = detect_from_html(html)

    theme_matches = [match for match in matches if match.category == "cms_theme"]
    assert len(theme_matches) == 1
    assert theme_matches[0].product_name == "WordPress Theme: astra"
    assert theme_matches[0].version == "1.0.0"


def test_elementor_plugin_asset_url_detection() -> None:
    html = '<script src="/wp-content/plugins/elementor/assets/js/frontend.min.js"></script>'
    matches = detect_from_html(html)

    elementor_matches = [match for match in matches if match.product_name == "Elementor"]

    assert len(elementor_matches) == 1
    assert elementor_matches[0].version is None


def test_elementor_class_based_detection() -> None:
    html = '<div class="page elementor-page elementor-section elementor-widget"></div>'
    matches = detect_from_html(html)

    elementor_matches = [match for match in matches if match.product_name == "Elementor"]

    assert len(elementor_matches) == 1
    assert elementor_matches[0].version is None
    assert elementor_matches[0].confidence_score == 0.6


def test_elementor_version_extraction_from_query_string() -> None:
    html = (
        '<link rel="stylesheet" href="/wp-content/plugins/elementor/assets/css/frontend.min.css?ver=3.27.3">'
    )
    matches = detect_from_html(html)

    elementor_matches = [
        match
        for match in matches
        if match.product_name == "Elementor" and match.version == "3.27.3"
    ]

    assert len(elementor_matches) == 1


def test_no_elementor_detection_from_jeg_elementor_kit_alone() -> None:
    html = (
        '<script src="/wp-content/plugins/jeg-elementor-kit/assets/js/frontend.min.js?ver=3.1.0"></script>'
    )
    matches = detect_from_html(html)

    elementor_matches = [match for match in matches if match.product_name == "Elementor"]
    jeg_matches = [
        match
        for match in matches
        if match.product_name == "WordPress Plugin: jeg-elementor-kit"
    ]

    assert elementor_matches == []
    assert len(jeg_matches) == 1


def test_meta_generator_prefers_single_wordpress_core_version() -> None:
    html = (
        '<meta name="generator" content="WordPress 6.9.4">'
        '<script src="/wp-includes/js/wp-emoji-release.min.js?ver=6.9.4"></script>'
        '<link rel="stylesheet" href="/wp-content/themes/astra/style.css?ver=1.2.0">'
    )
    matches = detect_from_html(html)

    wordpress_core_matches = [
        match for match in matches if match.product_name == "WordPress" and match.category == "cms"
    ]

    assert len(wordpress_core_matches) == 1
    assert wordpress_core_matches[0].version == "6.9.4"
    assert wordpress_core_matches[0].detection_method == "meta_generator"
