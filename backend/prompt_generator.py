from __future__ import annotations

from typing import Any


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def build_prompt(document_profile: dict[str, Any], user_prompt: str, output_format: str) -> str:
    document = document_profile or {}
    context = normalize_text(document.get("context")) or "general"
    target_audience = normalize_text(document.get("target_audience")) or "the intended audience"
    output_formats = normalize_text(document.get("output_formats"))
    custom_outputs = normalize_text(document.get("custom_outputs"))
    title = normalize_text(document.get("title")) or "uploaded document"
    original_name = normalize_text(document.get("original_name")) or "source file"
    mime_type = normalize_text(document.get("mime_type")) or "document"

    selected_formats = [item.strip() for item in output_formats.split(",") if item.strip()]
    selected_formats = selected_formats or ["Summary"]

    prompt = [
        "You are a content strategist generating output from a saved document profile.",
        f"Document title: {title}",
        f"Original file name: {original_name}",
        f"Content type: {mime_type}",
        f"Context: {context}",
        f"Target audience: {target_audience}",
        f"Selected output formats: {', '.join(selected_formats)}",
        f"Requested output format: {output_format}",
        f"User instruction: {user_prompt}",
    ]

    if custom_outputs:
        prompt.append(f"Custom output guidance: {custom_outputs}")

    prompt.append(
        "Write the result in a polished, audience-aware format that matches the chosen output style and the user's instruction."
    )
    return "\n".join(prompt)
