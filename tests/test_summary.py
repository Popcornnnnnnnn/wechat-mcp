# Copyright (C) 2026 wechat-mcp contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Comprehensive unit tests for wechat_mcp.summary schemas and 4-stage editorial pipeline."""
import pytest
from pydantic import ValidationError

from wechat_mcp.summary.pipeline import (
    MAX_INPUT_CHARS,
    ReferenceSummaryPipeline,
    SummaryPipeline,
    clean_json_response,
)
from wechat_mcp.summary.schema import (
    CheckStageSchema,
    Citation,
    SummaryPipelineResult,
    UnderstandStageSchema,
    VisualBlock,
    VisualStageSchema,
    WriteStageSchema,
)


def test_understand_stage_schema_validation():
    data = {
        "title": "Architecture Overview",
        "summary": "Deep dive into SQLite partitioning.",
        "entities": ["WeChat", "SQLite", "SQLCipher"],
        "key_points": ["Sharding reduces lock contention", "WAL mode improves read concurrency"],
        "language": "zh",
    }
    obj = UnderstandStageSchema(**data)
    assert obj.title == "Architecture Overview"
    assert obj.summary == "Deep dive into SQLite partitioning."
    assert "WeChat" in obj.entities
    assert len(obj.key_points) == 2


def test_understand_stage_missing_field_raises_validation_error():
    with pytest.raises(ValidationError):
        UnderstandStageSchema(title="Missing summary")


def test_citation_url_validation_success():
    cit = Citation(claim="Valid claim", url="https://example.com/doc", source_opened=True)
    assert cit.url == "https://example.com/doc"
    assert cit.confidence == 1.0


def test_citation_invalid_url_scheme_raises_value_error():
    with pytest.raises(ValidationError):
        Citation(claim="Invalid scheme", url="snippet-only://google.com")
    with pytest.raises(ValidationError):
        Citation(claim="Relative URL", url="/just/a/path")


def test_check_stage_schema_scoring():
    check = CheckStageSchema(
        verified=True,
        citations=[Citation(claim="C1", url="https://test.org")],
        rejected_claims=[],
        fact_check_score=1.0,
        status="ok",
    )
    assert check.verified is True
    assert check.fact_check_score == 1.0


def test_write_stage_schema_tones():
    for tone in ("technical", "executive", "casual", "bulletin"):
        write = WriteStageSchema(
            headline="Headline",
            editorial_summary="Summary",
            target_tone=tone,
            reading_time_minutes=2,
            key_takeaways=["T1"],
        )
        assert write.target_tone == tone

    with pytest.raises(ValidationError):
        WriteStageSchema(
            headline="Headline",
            editorial_summary="Summary",
            target_tone="unsupported_tone",
        )


def test_visual_stage_blocks():
    blocks = [
        VisualBlock(type="header", content="H1"),
        VisualBlock(type="text", content="Text"),
        VisualBlock(type="divider", content="---"),
    ]
    vis = VisualStageSchema(card_title="Card Title", card_blocks=blocks)
    assert vis.layout_valid is True
    assert vis.theme_color == "#07C160"
    assert len(vis.card_blocks) == 3


def test_clean_json_response_markdown_fences():
    raw = '```json\n{"title": "OK", "summary": "Valid"}\n```'
    cleaned = clean_json_response(raw)
    assert cleaned["title"] == "OK"

    raw2 = '```\n{"title": "Plain"}\n```'
    assert clean_json_response(raw2)["title"] == "Plain"


def test_pipeline_offline_mock_zero_credential():
    pipeline = SummaryPipeline(mock=True)
    result = pipeline.process("Article content regarding WeChat SQLite architectures.")
    assert isinstance(result, SummaryPipelineResult)
    assert result.status == "success"
    assert result.check.verified is True
    assert result.duration_ms > 0
    assert "Multi-Shard" in result.understand.title


def test_pipeline_empty_body_raises_value_error():
    pipeline = SummaryPipeline(mock=True)
    with pytest.raises(ValueError, match="Empty article body"):
        pipeline.run_stage_understand("   ")


def test_pipeline_input_truncation():
    pipeline = SummaryPipeline(mock=True)
    huge = "a " * (MAX_INPUT_CHARS + 1000)
    u = pipeline.run_stage_understand(huge)
    assert isinstance(u, UnderstandStageSchema)


def test_pipeline_check_timeout():
    pipeline = SummaryPipeline(mock=True)
    u = pipeline.run_stage_understand("Valid text")
    chk = pipeline.run_stage_check(u, timeout=True)
    assert chk.verified is False
    assert chk.status == "search_timed_out"
    assert len(chk.rejected_claims) == 1


def test_pipeline_unopened_source_rejection():
    pipeline = SummaryPipeline(mock=True)
    u = pipeline.run_stage_understand("Valid text")
    unopened = [{"claim": "Fake", "url": "https://unopened.com", "source_opened": False}]
    chk = pipeline.run_stage_check(u, citations=unopened)
    assert chk.verified is False
    assert len(chk.rejected_claims) == 1


def test_pipeline_special_characters_and_emojis():
    pipeline = SummaryPipeline(mock=True)
    special_text = "Emoji: 📊 🚀 ∑(x_i) = 1 עִבְרִית"
    u = pipeline.run_stage_understand(special_text)
    assert isinstance(u, UnderstandStageSchema)
    res = pipeline.process(special_text)
    assert res.status == "success"
