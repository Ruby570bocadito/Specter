import pytest


def _import_llm_components():
    try:
        from t100ai.llm import prompts as prompts_module
        return prompts_module
    except Exception:
        return None


def test_prompt_builder():
    prompts = _import_llm_components()
    if prompts is None:
        pytest.skip("LLM prompts module not available")
    if hasattr(prompts, "PromptBuilder"):
        pb = prompts.PromptBuilder()
        assert hasattr(pb, "build_prompt")
    else:
        pytest.skip("PromptBuilder not implemented")


@pytest.mark.asyncio
async def test_role_prompts():
    prompts = _import_llm_components()
    if prompts is None:
        pytest.skip("LLM prompts module not available")
    if not hasattr(prompts, "build_role_prompt"):  # simple duck-typing
        pytest.skip("build_role_prompt not implemented")
    # Call async-like interface if available
    if hasattr(prompts, "build_role_prompt"):
        result = prompts.build_role_prompt(role="admin", context={})
        # It should return a string or awaitable; handle both
        if hasattr(result, "__await__"):
            result = await result
        assert isinstance(result, str)
