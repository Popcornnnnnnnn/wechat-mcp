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

"""Group Link Summary Pipeline module for wechat-mcp."""
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

__all__ = [
    "UnderstandStageSchema",
    "Citation",
    "CheckStageSchema",
    "WriteStageSchema",
    "VisualBlock",
    "VisualStageSchema",
    "SummaryPipelineResult",
    "SummaryPipeline",
    "ReferenceSummaryPipeline",
    "MAX_INPUT_CHARS",
    "clean_json_response",
]
