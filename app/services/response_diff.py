import re


def _get_value(response, name, default=None):
    if isinstance(response, dict):
        return response.get(name, default)
    return getattr(response, name, default)


def normalize_content(text):
    value = str(text or "")
    value = re.sub(r"\b\d{4}-\d{2}-\d{2}\b", "", value)
    value = re.sub(r"\b\d{2}:\d{2}:\d{2}\b", "", value)
    value = re.sub(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        "",
        value,
    )
    value = re.sub(r"\b[A-Za-z0-9_-]{32,}\b", "", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def compare_responses(baseline, test):
    baseline_status = _get_value(baseline, "status_code")
    test_status = _get_value(test, "status_code")
    status_code_changed = baseline_status != test_status

    baseline_body = _get_value(baseline, "body", "") or ""
    test_body = _get_value(test, "body", "") or ""
    baseline_size = len(str(baseline_body))
    test_size = len(str(test_body))

    if baseline_size:
        size_delta_percent = ((test_size - baseline_size) / baseline_size) * 100
    else:
        size_delta_percent = 100.0 if test_size else 0.0

    baseline_time = float(_get_value(baseline, "response_time_ms", 0) or 0)
    test_time = float(_get_value(test, "response_time_ms", 0) or 0)
    timing_delta_ms = test_time - baseline_time

    baseline_content = normalize_content(baseline_body)
    test_content = normalize_content(test_body)
    content_changed = baseline_content != test_content
    changed = status_code_changed or content_changed or size_delta_percent != 0

    abs_size_delta_percent = abs(size_delta_percent)
    abs_timing_delta_ms = abs(timing_delta_ms)
    confidence_signal = "none"
    signal_reason = "no meaningful change"
    if status_code_changed and content_changed:
        confidence_signal = "strong"
        signal_reason = "status code and content changed"
    elif abs_size_delta_percent >= 50:
        confidence_signal = "strong"
        signal_reason = "size changed by at least 50%"
    elif content_changed and abs_size_delta_percent >= 15:
        confidence_signal = "medium"
        signal_reason = "content changed with size delta of at least 15%"
    elif abs_timing_delta_ms >= 1000:
        confidence_signal = "medium"
        signal_reason = "timing changed by at least 1000 ms"
    elif content_changed:
        confidence_signal = "weak"
        signal_reason = "content changed"
    elif abs_size_delta_percent >= 5:
        confidence_signal = "weak"
        signal_reason = "size changed by at least 5%"

    summary_parts = []
    if confidence_signal != "none":
        summary_parts.append(f"{confidence_signal} signal: {signal_reason}")
    if status_code_changed:
        summary_parts.append(f"status_code {baseline_status} -> {test_status}")
    if size_delta_percent != 0:
        summary_parts.append(f"size_delta_percent {size_delta_percent:.2f}")
    if timing_delta_ms != 0:
        summary_parts.append(f"timing_delta_ms {timing_delta_ms:.2f}")
    if content_changed:
        summary_parts.append("content changed")

    return {
        "changed": changed,
        "status_code_changed": status_code_changed,
        "size_delta_percent": float(size_delta_percent),
        "timing_delta_ms": float(timing_delta_ms),
        "content_changed": content_changed,
        "confidence_signal": confidence_signal,
        "summary": "; ".join(summary_parts) if summary_parts else "no changes detected",
    }
