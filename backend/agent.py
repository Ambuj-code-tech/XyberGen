from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

def _normalize_env() -> None:
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if env_path.exists():
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):]
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ[key.strip()] = value.strip().strip('"\'')
    for key in ("GROQ_API_KEY", "OPENAI_API_KEY", "XYBERGEN_MODEL"):
        if key in os.environ:
            os.environ[key] = str(os.environ[key]).strip().strip('"\'')
    load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=True)


_normalize_env()

try:
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_groq import ChatGroq
except ImportError:  # pragma: no cover - optional dependency path
    ChatGroq = None

try:
    from langchain_openai import ChatOpenAI
except ImportError:  # pragma: no cover - optional dependency path
    ChatOpenAI = None

try:
    from langgraph.graph import END, START, StateGraph
except ImportError:  # pragma: no cover - optional dependency path
    StateGraph = None
    END = "END"
    START = "START"

ChatPromptTemplate = globals().get("ChatPromptTemplate", None)


_PROMPT_PATH = Path(__file__).resolve().with_name("prompt_generator.py")
build_prompt = None
if _PROMPT_PATH.exists():
    spec = importlib.util.spec_from_file_location("xybergen_prompt_generator", _PROMPT_PATH)
    if spec and spec.loader:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        build_prompt = getattr(module, "build_prompt", None)


def _fallback_document_output(document: dict[str, Any], user_prompt: str, output_format: str) -> str:
    context = str(document.get("context") or "general").strip() or "general"
    audience = str(document.get("target_audience") or "the intended audience").strip() or "the intended audience"
    title = str(document.get("title") or "Uploaded document").strip() or "Uploaded document"
    custom = str(document.get("custom_outputs") or "").strip()
    selected_format = (output_format or "Summary").strip() or "Summary"

    brief = user_prompt.strip() or f"Create a {selected_format.lower()} for {title}."
    custom_note = f" Additional guidance: {custom}." if custom else ""

    return (
        f"{selected_format}: {title}\n\n"
        f"This {context} update is designed for {audience} and highlights the most important information from the source material. "
        f"The goal is to keep the message clear, relevant, and action-focused while addressing the user request: {brief}.{custom_note}\n\n"
        f"Key points:\n"
        f"- Summarize the core issue or opportunity in plain language.\n"
        f"- Highlight the most relevant facts, risks, or next steps for {audience}.\n"
        f"- Keep the tone aligned with the {context} context and make the message easy to act on.\n\n"
        f"Overall message: the material should be framed as a concise, confident {selected_format.lower()} that helps {audience} understand what matters most and what action is expected next."
    )

def _build_llm():
    groq_key = str(os.getenv("GROQ_API_KEY") or "").strip()
    openai_key = str(os.getenv("OPENAI_API_KEY") or "").strip()
    model_name = str(os.getenv("XYBERGEN_MODEL") or "llama-3.3-70b-versatile").strip()

    if groq_key:
        if ChatGroq is not None:
            return ChatGroq(
                model=model_name or "llama-3.3-70b-versatile",
                temperature=0.3,
                api_key=groq_key,
            )
        if ChatOpenAI is not None:
            return ChatOpenAI(
                model=model_name or "llama-3.3-70b-versatile",
                temperature=0.3,
                api_key=groq_key,
                base_url="https://api.groq.com/openai/v1",
            )

    if openai_key and ChatOpenAI is not None:
        return ChatOpenAI(model=os.getenv("XYBERGEN_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini", temperature=0.3)

    return None


def _generate_with_langchain(document: dict[str, Any], user_prompt: str, output_format: str) -> str:
    if not build_prompt or ChatPromptTemplate is None:
        return _fallback_document_output(document, user_prompt, output_format)

    llm = _build_llm()
    if llm is None:
        return _fallback_document_output(document, user_prompt, output_format)

    prompt = build_prompt(document, user_prompt, output_format)
    template = ChatPromptTemplate.from_messages([
        ("system", "You are a senior content strategist."),
        ("user", "{prompt}"),
    ])
    chain = template | llm

    try:
        response = chain.invoke({"prompt": prompt})
        text = str(getattr(response, "content", response) or "").strip()
        return text or _fallback_document_output(document, user_prompt, output_format)
    except Exception:
        return _fallback_document_output(document, user_prompt, output_format)


def _build_langgraph_pipeline():
    if StateGraph is None:
        return None

    try:
        class DocumentState(dict):
            pass

        def prepare_state(state: dict[str, Any]) -> dict[str, Any]:
            document = state.get("document") or {}
            state["output_format"] = state.get("output_format") or "Summary"
            state["draft"] = _generate_with_langchain(
                document,
                state.get("user_prompt") or "",
                state["output_format"],
            )
            return state

        builder = StateGraph(DocumentState)
        builder.add_node("prepare", prepare_state)
        builder.add_edge(START, "prepare")
        builder.add_edge("prepare", END)
        return builder.compile()
    except Exception:
        return None


_LANGGRAPH_PIPELINE = _build_langgraph_pipeline()


def generate_document_output(document: dict[str, Any], user_prompt: str, output_format: str = "Summary") -> str:
    state: dict[str, Any] = {
        "document": document or {},
        "user_prompt": user_prompt,
        "output_format": output_format or "Summary",
    }

    if _LANGGRAPH_PIPELINE is not None:
        try:
            result = _LANGGRAPH_PIPELINE.invoke(state)
            draft = result.get("draft")
            if isinstance(draft, str) and draft.strip():
                return draft.strip()
        except Exception:
            pass

    return _generate_with_langchain(document or {}, user_prompt, output_format or "Summary")