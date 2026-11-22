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

"""Pydantic v2 schemas for the 4-stage editorial summary pipeline."""
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlparse
from pydantic import BaseModel, ConfigDict, Field, field_validator


class UnderstandStageSchema(BaseModel):
    """Stage 1: Extract core themes, entities, and structured synopsis."""
    model_config = ConfigDict(extra="ignore")

    title: str = Field(..., min_length=1, description="Article or discussion title")
    summary: str = Field(..., min_length=1, description="Concise synopsis of the core discussion")
    entities: List[str] = Field(default_factory=list, description="Key named entities, technologies, or people")
    key_points: List[str] = Field(default_factory=list, description="Extracted bullet points")
    language: str = Field(default="zh", description="Primary content language")


class Citation(BaseModel):
    """Citation verified against primary external source."""
    model_config = ConfigDict(extra="ignore")

    claim: str = Field(..., min_length=1, description="Claim being cited or fact-checked")
    url: str = Field(..., description="Absolute HTTP/HTTPS URL")
    source_opened: bool = Field(default=True, description="Whether the primary source was opened")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Verification confidence score")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"Citation URL must be a valid http or https URL, got '{v}'")
        return v


class CheckStageSchema(BaseModel):
    """Stage 2: Fact-check verification gate."""
    model_config = ConfigDict(extra="ignore")

    verified: bool = Field(default=False, description="Whether fact check passed all verification gates")
    citations: List[Citation] = Field(default_factory=list, description="List of verified citations")
    rejected_claims: List[str] = Field(default_factory=list, description="List of rejected unverified claims or error reasons")
    fact_check_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Aggregate fact check score")
    status: Literal["ok", "fact_check_failed", "search_timed_out"] = Field(default="ok", description="Status code of fact-checking")


class WriteStageSchema(BaseModel):
    """Stage 3: Tone-adapted editorial summary generation."""
    model_config = ConfigDict(extra="ignore")

    headline: str = Field(..., min_length=1, description="Editorial headline")
    editorial_summary: str = Field(..., min_length=1, description="Draft editorial summary text")
    target_tone: Literal["technical", "executive", "casual", "bulletin"] = Field(default="technical", description="Tone adapted for group audience")
    reading_time_minutes: int = Field(default=1, ge=1, description="Estimated reading time in minutes")
    key_takeaways: List[str] = Field(default_factory=list, description="Bullet point takeaways")


class VisualBlock(BaseModel):
    """Block-level presentation unit for visual card."""
    model_config = ConfigDict(extra="ignore")

    type: Literal["header", "text", "quote", "divider", "metric"] = Field(..., description="Visual block type")
    content: str = Field(..., description="Text or content for the block")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Presentation metadata")


class VisualStageSchema(BaseModel):
    """Stage 4: Visual presentation card validation."""
    model_config = ConfigDict(extra="ignore")

    layout_valid: bool = Field(default=True, description="Whether layout passes validation constraints")
    card_template: str = Field(default="default_card", description="Card layout template ID")
    card_title: str = Field(..., min_length=1, description="Title displayed on the card")
    card_blocks: List[VisualBlock] = Field(default_factory=list, description="Ordered presentation blocks")
    theme_color: str = Field(default="#07C160", description="Theme color in hex format (WeChat green default)")


class SummaryPipelineResult(BaseModel):
    """Complete 4-stage pipeline execution result."""
    model_config = ConfigDict(extra="ignore")

    understand: UnderstandStageSchema
    check: CheckStageSchema
    write: WriteStageSchema
    visual: VisualStageSchema
    status: Literal["success", "fact_check_failed", "validation_error", "search_timed_out"] = Field(..., description="Pipeline execution status")
    duration_ms: float = Field(..., description="Execution duration in milliseconds")
