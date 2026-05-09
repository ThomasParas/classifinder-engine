"""
ClassiFinder — Prompt Injection Markers (Phases 1 + 2)

Patterns for prompt-injection attacks against LLM applications, in two tiers:

Phase 1 (high-precision, confidence 0.85+):
- pi_role_hijack_marker — chat template control tokens
- pi_tool_call_injection — agent tool-call tag injection
- pi_jailbreak_persona — named jailbreak personas (DAN, AIM, etc.)
- pi_bidi_override — Unicode bidirectional override (Trojan Source)

Phase 2 (medium-precision, confidence 0.55–0.75):
- pi_zero_width_smuggling — runs of invisible Unicode
- pi_fake_assistant_turn — user input claiming to be the assistant
- pi_prompt_extraction — "reveal your system prompt" requests
- pi_instruction_override — "ignore previous instructions" family
- pi_persona_override — "you are now a..." / "pretend to be"
- pi_encoded_payload_marker — base64 + decode hint nearby

Design notes:
- These are syntactic markers, not vendor-issued credentials. Severity caps
  at "high" — no "critical" — since the consequence is "block the input,"
  not "rotate this key."
- Confidence base for phase 1 is 0.85+ (structurally rare tokens). Phase 2
  is 0.55–0.75 (natural-language markers with higher FP risk by design).
  Phase 2 patterns expect users to opt up min_confidence per product.
- Entropy threshold is 0.0 — entropy doesn't apply to natural language
  except for pi_encoded_payload_marker which gates on base64 entropy.
- The "secret" named group captures the matched marker text. value_preview
  in findings is the first 4 + last 4 chars, which is informative enough to
  identify what was caught (e.g., "<|im" ... "tem|>").
- ClassiFinder is layer 1: detect the structural marker. Semantic detection
  of indirect injections (benign-looking RAG docs that quietly redirect the
  model) requires LLM-in-the-loop and is left to LlamaGuard / PromptGuard.
"""

import re

from .registry import SecretPattern, register

# ===================================================
# 1. ROLE HIJACK — chat template control tokens
# ===================================================

ROLE_HIJACK_MARKER = SecretPattern(
    id="pi_role_hijack_marker",
    name="Role Hijack Token",
    description=(
        "Chat template control tokens (ChatML im_start/im_end, Llama [INST]"
        " / <<SYS>>, Llama 3 header tokens) appearing in user input. Used"
        " to fake a system or assistant turn and override the application's"
        " intended prompt structure."
    ),
    provider="prompt_injection",
    severity="high",
    # Independently authored — control tokens drawn from public OpenAI ChatML
    # (im_start/im_end/endoftext), Llama 2 instruction format ([INST]/<<SYS>>),
    # Llama 3 header tokens (begin_of_text/start_header_id/end_header_id/eot_id),
    # and Alpaca-style instruct format (### Instruction:/### Response:). The
    # (?<!`) / (?!`) lookarounds skip inline-code mentions in tech documentation.
    regex=re.compile(
        r"(?<!`)"
        r"(?P<secret>"
        r"<\|(?:im_start|im_end|endoftext|begin_of_text|start_header_id"
        r"|end_header_id|eot_id|system|user|assistant)\|>"
        r"|<<SYS>>|<</SYS>>"
        r"|\[INST\]|\[/INST\]"
        r"|^### (?:Instruction|Response|System)[: ]"
        r")"
        r"(?!`)",
        re.MULTILINE,
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,
    context_keywords=[],
    known_test_values=set(),
    recommendation=(
        "Block this input or strip the control tokens before passing to the"
        " LLM. Chat template tokens in user-submitted text are diagnostic of"
        " a deliberate attempt to inject a fake system or assistant turn."
        " Note: this pattern is tuned for user-input deployment surfaces"
        " (LangChain guard, FastAPI middleware). For RAG pre-indexing of"
        " LLM-internals documentation (HuggingFace tokenizer docs, chat-"
        " template tutorials), expect over-firing inside fenced code blocks"
        " — opt out via the types= filter for those use cases."
    ),
    tags=["prompt-injection", "role-hijack", "high-precision"],
)


# ===================================================
# 2. TOOL CALL INJECTION — fake agent actions
# ===================================================

TOOL_CALL_INJECTION = SecretPattern(
    id="pi_tool_call_injection",
    name="Tool Call Tag Injection",
    description=(
        "Literal tool-use, function-call, or chain-of-thought tags in user"
        " input. Attempts to fake a model-emitted tool call or reasoning"
        " trace. High severity in agent pipelines that parse model output"
        " for tool dispatch."
    ),
    provider="prompt_injection",
    severity="high",
    # Independently authored — tag names from public Anthropic Messages API
    # documentation (tool_use, tool_result), OpenAI legacy function-calling
    # docs (function_call), and chain-of-thought wrapper conventions
    # (thinking, reasoning). User input containing these tags is an attempt
    # to fake a model-emitted tool call or reasoning trace.
    regex=re.compile(
        r"(?P<secret>"
        r"</?(?:tool_use|tool_call|tool_result|function_call|thinking|reasoning)"
        r"\b[^>]*>"
        r")",
        re.IGNORECASE,
    ),
    confidence_base=0.85,
    entropy_threshold=0.0,
    context_keywords=[],
    known_test_values=set(),
    recommendation=(
        "Block or escape these tags before passing input to an agent loop."
        " Tool-call tags in user-submitted text are a known vector for"
        " prompt-injection attacks against tool-using agents. Note: this"
        " pattern over-fires on prompt-engineering documentation (e.g.,"
        " Anthropic's metaprompt tutorial) that contains literal tags as"
        " teaching examples — opt out via the types= filter when RAG-"
        " indexing such content."
    ),
    tags=["prompt-injection", "agent-attack", "high-precision"],
)


# ===================================================
# 3. JAILBREAK PERSONA — DAN, developer mode, etc.
# ===================================================

JAILBREAK_PERSONA = SecretPattern(
    id="pi_jailbreak_persona",
    name="Known Jailbreak Persona",
    description=(
        "References to canonical jailbreak personas (DAN, AIM, STAN,"
        " developer mode, god mode, evilGPT). High signal of intent to"
        " bypass model safety guardrails."
    ),
    provider="prompt_injection",
    severity="high",
    # Independently authored — persona names sourced from publicly disclosed
    # jailbreak corpora (HackAPrompt 2023, jailbreak_llms research dataset,
    # and the survey by Liu et al. 2024 "Jailbreaking ChatGPT via Prompt
    # Engineering"). Restricted to canonical persona names with stable
    # spellings: DAN, AIM, STAN, developer mode, god mode, evilGPT.
    regex=re.compile(
        r"(?P<secret>"
        r"\b(?:DAN|D\.A\.N\.)\s+(?:mode|prompt|persona)\b"
        r"|\bdo\s+anything\s+now\b"
        r"|\b(?:developer|god)\s+mode\s+(?:enabled|activated|on|engaged)\b"
        r"|\b(?:AIM|STAN|DUDE)\s+(?:mode|prompt|persona)\b"
        r"|\bevil[-_\s]?GPT\b"
        r"|\bjail[-\s]?broken\s+(?:mode|response|model|GPT|AI|version)\b"
        r")",
        re.IGNORECASE,
    ),
    confidence_base=0.85,
    entropy_threshold=0.0,
    context_keywords=["roleplay", "pretend", "hypothetical", "uncensored"],
    known_test_values=set(),
    recommendation=(
        "Block or escalate. These persona names are well-known jailbreak"
        " triggers documented in published security research. Note that"
        " documents *about* jailbreaking (security research, this very"
        " pattern's docs) will also match — opt out via types= filter for"
        " those use cases."
    ),
    tags=["prompt-injection", "jailbreak", "high-precision"],
)


# ===================================================
# 4. BIDI OVERRIDE — Trojan Source (CVE-2021-42574)
# ===================================================

BIDI_OVERRIDE = SecretPattern(
    id="pi_bidi_override",
    name="Bidirectional Override Character",
    description=(
        "Unicode bidirectional override characters (LRE/RLE/PDF/LRO/RLO and"
        " LRI/RLI/FSI/PDI). The Trojan Source attack vector — text renders"
        " one way and parses another. Almost never legitimate in English-"
        " language pipelines."
    ),
    provider="prompt_injection",
    severity="high",
    # Source: Boucher & Anderson, 2021, "Trojan Source: Invisible
    # Vulnerabilities" (CVE-2021-42574). Codepoints per Unicode 15.1
    # General Category Cf (Format).
    regex=re.compile(
        r"(?P<secret>[\u202a-\u202e\u2066-\u2069]+)",
    ),
    confidence_base=0.85,
    entropy_threshold=0.0,
    context_keywords=[],
    known_test_values=set(),
    recommendation=(
        "Strip BiDi control characters before passing input to the LLM."
        " For pipelines that legitimately handle right-to-left scripts"
        " (Arabic, Hebrew, Persian), opt out via the types= filter — this"
        " pattern is tuned for English-language deployment surfaces."
    ),
    tags=["prompt-injection", "encoding-attack", "trojan-source", "high-precision"],
)


# ===================================================
# PHASE 2 — medium-precision markers
# ===================================================
# Phase 2 patterns target natural-language markers where corpus distribution
# drives the FP rate. Confidence base is intentionally 0.55–0.75 so users
# can opt up min_confidence per deployment surface. Each pattern's
# recommendation field documents its known FP class.


# ===================================================
# 5. ZERO-WIDTH SMUGGLING — invisible Unicode runs
# ===================================================

ZERO_WIDTH_SMUGGLING = SecretPattern(
    id="pi_zero_width_smuggling",
    name="Zero-Width Unicode Smuggling",
    description=(
        "Runs of 3+ consecutive zero-width characters (U+200B/C/D, U+FEFF,"
        " U+2060). Used to hide instructions inside otherwise-innocent text."
    ),
    provider="prompt_injection",
    severity="medium",
    # Independently authored — Unicode points per Unicode 15.1 General
    # Category Cf (Format). Threshold of 3+ consecutive chosen empirically:
    # legitimate uses (e.g., ZWJ in emoji sequences) typically appear singly
    # or in pairs, while smuggling attacks pack longer runs.
    regex=re.compile(
        r"(?P<secret>[\u200b-\u200d\ufeff\u2060]{3,})",
    ),
    confidence_base=0.75,
    entropy_threshold=0.0,
    context_keywords=[],
    known_test_values=set(),
    recommendation=(
        "Strip zero-width characters before passing to the LLM. Even if"
        " benign (copy-paste artifact from formatted documents), they offer"
        " no value to the model. Known FP class: copy-paste from Word /"
        " Google Docs occasionally drags in BOM or ZWJ chars; the 3-char"
        " threshold rules out most accidental cases."
    ),
    tags=["prompt-injection", "encoding-attack", "phase-2"],
)


# ===================================================
# 6. FAKE ASSISTANT TURN — user input claiming to be assistant
# ===================================================

FAKE_ASSISTANT_TURN = SecretPattern(
    id="pi_fake_assistant_turn",
    name="Fake Assistant Turn",
    description=(
        "User input that begins with 'Assistant:', 'Claude:', 'GPT:' or"
        " similar role labels — attempts to fake the model's prior turn."
    ),
    provider="prompt_injection",
    severity="high",
    # Independently authored — pattern observed in indirect-injection
    # samples from Greshake et al. 2023 ("Not what you've signed up for");
    # user attempts to spoof an assistant message by prefixing input with
    # role labels. Anchored to start of input or after newline.
    regex=re.compile(
        r"(?:^|\n)\s*"
        r"(?P<secret>"
        # Specific AI-product / chatbot role labels. Words "model" and "ai"
        # are intentionally excluded — too common as Python identifiers
        # (dataclass fields, type annotations) and produce noisy FPs on code.
        r"(?:assistant|claude|gpt|chatgpt|chatbot|bot)"
        r"\s*[:>]\s*\S"
        r")",
        re.IGNORECASE,
    ),
    confidence_base=0.65,
    entropy_threshold=0.0,
    context_keywords=["roleplay", "pretend", "transcript"],
    known_test_values=set(),
    recommendation=(
        "Suspect — strip the role-label prefix before passing to the LLM,"
        " or refuse if the conversation is single-turn. Known FP class:"
        " transcripts pasted as user input ('here's my conversation with"
        " ChatGPT, what should I do next?') — high volume in customer-"
        " support and coding-assistant contexts. Tune min_confidence to"
        " 0.8 in support pipelines to suppress."
    ),
    tags=["prompt-injection", "role-hijack", "phase-2"],
)


# ===================================================
# 7. PROMPT EXTRACTION — "reveal your system prompt"
# ===================================================

PROMPT_EXTRACTION = SecretPattern(
    id="pi_prompt_extraction",
    name="System Prompt Extraction Attempt",
    description=(
        "Phrases asking the model to repeat, reveal, or print its system"
        " prompt, initial instructions, or hidden rules."
    ),
    provider="prompt_injection",
    severity="medium",
    # Independently authored — phrasings drawn from publicly disclosed
    # system-prompt extraction attempts (e.g., the 2023 Bing Chat "Sydney"
    # disclosure). Requires both an extraction verb and a target qualifier
    # within 40 chars to avoid matching plain "show me the message."
    regex=re.compile(
        r"(?P<secret>"
        r"\b(?:repeat|print|reveal|show|tell\s+me|output|display|reproduce|recite)"
        r"(?:[^.\n]{0,40})"
        r"\b(?:system|initial|original|hidden|secret)\s+"
        r"(?:prompt|instructions?|message|context|rules?|guidelines?)\b"
        r")",
        re.IGNORECASE,
    ),
    confidence_base=0.65,
    entropy_threshold=0.0,
    context_keywords=["jailbreak", "verbatim"],
    known_test_values=set(),
    recommendation=(
        "Review. Many products legitimately accept questions like 'what can"
        " you do?' which is adjacent to this — tune severity per product."
        " The regex requires a system/initial/original/hidden qualifier so"
        " 'show me the message' (without that qualifier) doesn't match."
    ),
    tags=["prompt-injection", "extraction", "phase-2"],
)


# ===================================================
# 8. INSTRUCTION OVERRIDE — "ignore previous instructions"
# ===================================================

INSTRUCTION_OVERRIDE = SecretPattern(
    id="pi_instruction_override",
    name="Instruction Override Phrase",
    description=(
        "Phrases that ask the model to ignore, disregard, or forget prior"
        " instructions. The textbook direct prompt injection trigger."
    ),
    provider="prompt_injection",
    severity="medium",
    # Independently authored — covers the canonical Greshake et al. 2023
    # direct injection family ("Not what you've signed up for") plus common
    # paraphrases. Confidence base 0.55 keeps it default-surfacing; users
    # tune up to 0.7+ to suppress dev/code-review FPs (see recommendation).
    regex=re.compile(
        r"(?P<secret>"
        r"\b(?:ignore|disregard|forget|override|bypass)"
        r"(?:\s+(?:all|the|your|any|every|those|these|previous|prior|above|earlier|preceding|original|initial|system|safety|ethical|moral|default|built-in|core))*"
        r"\s+(?:instructions?|prompts?|rules?|directives?|commands?|guidelines?|constraints?|filters?|policies)\b"
        r")",
        re.IGNORECASE,
    ),
    confidence_base=0.55,
    entropy_threshold=0.0,
    context_keywords=["jailbreak", "uncensored", "unrestricted", "no rules"],
    known_test_values=set(),
    recommendation=(
        "Review the input source. If user-submitted to an LLM pipeline,"
        " consider redacting or refusing. If from a trusted internal source,"
        " this may be a legitimate instruction. Known FP class: dev/code-"
        " review chat ('ignore the previous results and recompute'),"
        " engineering discussions ('disregard rule #3 from the spec'),"
        " general Slack-style chat. Tune min_confidence to 0.7+ to suppress"
        " unless context keywords boost confidence."
    ),
    tags=["prompt-injection", "instruction-override", "phase-2"],
)


# ===================================================
# 9. PERSONA OVERRIDE — "you are now a..."
# ===================================================

PERSONA_OVERRIDE = SecretPattern(
    id="pi_persona_override",
    name="Persona Override Attempt",
    description=(
        "Phrases that try to redefine the model's identity or role,"
        " e.g., 'you are now a hacker', 'pretend you are', 'act as'."
    ),
    provider="prompt_injection",
    severity="medium",
    # Independently authored — covers the persona-replacement family from
    # Schulhoff et al. 2024 "Ignore This Title" (HackAPrompt corpus). Lower
    # confidence because legitimate persona setup is common in roleplay
    # apps. Highest FP risk of the phase-2 set.
    regex=re.compile(
        r"(?P<secret>"
        r"\byou\s+are\s+(?:now|going\s+to\s+be)\s+(?:a|an|the)\b"
        r"|\bpretend\s+(?:to\s+be|that\s+you(?:\s+are)?)\b"
        r"|\bact\s+as\s+(?:a|an|if\s+you)\b"
        r"|\broleplay\s+as\b"
        r"|\bfrom\s+now\s+on\s+you(?:\s+will|\s+are|'re|\s+must)\b"
        r"|\bimagine\s+you\s+are\s+(?:a|an|the)\b"
        r")",
        re.IGNORECASE,
    ),
    # Confidence base 0.48 is intentionally below default min_confidence=0.5
    # so legitimate roleplay use ("Act as a VBA programmer", "Pretend to be a
    # tutor") does NOT surface by default. With even ONE attack-context
    # keyword nearby (jailbreak/uncensored/no-rules/ignore), confidence rises
    # to 0.50 and the finding surfaces. Phase-2 WildChat FP testing showed
    # 6.6 pure FPs per 5K user messages without this gating; with the
    # context-keyword gate the deployment-realistic FP rate drops to ~0.
    confidence_base=0.48,
    entropy_threshold=0.0,
    context_keywords=["jailbreak", "uncensored", "without restrictions", "no rules", "ignore"],
    known_test_values=set(),
    recommendation=(
        "Context-gated by design. Default scans (min_confidence=0.5) will"
        " not surface this finding unless attack-context keywords (jailbreak,"
        " uncensored, no rules, ignore) appear nearby. To enable persona-"
        " detection in deployment surfaces where roleplay is unusual, scan"
        " with min_confidence=0.4 or filter by types=['pi_persona_override'].\n"
        "Known FP class: legitimate creative-writing / tutoring / coding-"
        " assistant prompts ('Act as a senior engineer', 'Pretend to be a"
        " French tutor'). Without the context-keyword gate, fires at ~6.6/5K"
        " user messages on WildChat-4.8M."
    ),
    tags=["prompt-injection", "persona-override", "phase-2", "context-gated"],
)


# ===================================================
# 10. ENCODED PAYLOAD MARKER — base64 + decode hint
# ===================================================

ENCODED_PAYLOAD_MARKER = SecretPattern(
    id="pi_encoded_payload_marker",
    name="Encoded Payload with Decode Hint",
    description=(
        "Base64-shaped string adjacent to a 'decode' or 'base64' keyword."
        " Common pattern in indirect injections that smuggle instructions"
        " through encoding."
    ),
    provider="prompt_injection",
    severity="medium",
    # Independently authored — pattern observed in indirect injection
    # samples where the attacker base64-encodes the malicious instruction
    # and asks the model to decode and execute. Heuristic: 40+ chars of
    # base64 within ~100 chars of "decode"/"base64". Entropy gate 4.0
    # filters out non-base64 strings that happen to look base64-shaped.
    regex=re.compile(
        r"(?:decode|base64|b64|decrypt|deobfuscate)"
        r"(?:[^.\n]{0,100})"
        r"(?P<secret>[A-Za-z0-9+/]{40,}={0,2})",
        re.IGNORECASE,
    ),
    confidence_base=0.60,
    entropy_threshold=4.0,
    context_keywords=["execute", "run", "eval", "instructions"],
    known_test_values=set(),
    recommendation=(
        "Decode the payload and rescan. Known FP class: legitimate technical"
        " content explaining base64 ('here's how to base64-encode a string:"
        " ...' followed by an example). The execute/run/eval context keyword"
        " filter helps but won't eliminate. Note: overlaps with the engine's"
        " base64 decoder for secret detection — both can fire on the same"
        " span without double-counting because the scanner deduplicates"
        " overlapping findings."
    ),
    tags=["prompt-injection", "encoding-attack", "phase-2"],
)


register(
    ROLE_HIJACK_MARKER,
    TOOL_CALL_INJECTION,
    JAILBREAK_PERSONA,
    BIDI_OVERRIDE,
    ZERO_WIDTH_SMUGGLING,
    FAKE_ASSISTANT_TURN,
    PROMPT_EXTRACTION,
    INSTRUCTION_OVERRIDE,
    PERSONA_OVERRIDE,
    ENCODED_PAYLOAD_MARKER,
)
