"""Performance Profiler for T-100AI Engine."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PerfStats:
    """Performance statistics for the engine."""
    total_input_processing_time: float = 0.0
    total_llm_response_time: float = 0.0
    total_command_execution_time: float = 0.0
    interaction_count: int = 0
    _start_times: dict[str, float] = field(default_factory=dict)

    def start(self, phase: str) -> None:
        """Start timing a phase."""
        self._start_times[phase] = time.time()

    def stop(self, phase: str) -> float:
        """Stop timing a phase and return elapsed time."""
        start = self._start_times.pop(phase, time.time())
        elapsed = time.time() - start
        if phase == "input_processing":
            self.total_input_processing_time += elapsed
        elif phase == "llm_response":
            self.total_llm_response_time += elapsed
        elif phase == "command_execution":
            self.total_command_execution_time += elapsed
        self.interaction_count += 1
        return elapsed

    def get_stats(self) -> dict[str, Any]:
        """Return performance statistics."""
        total = (
            self.total_input_processing_time
            + self.total_llm_response_time
            + self.total_command_execution_time
        )
        return {
            "total_time": round(total, 2),
            "input_processing": round(self.total_input_processing_time, 2),
            "llm_response": round(self.total_llm_response_time, 2),
            "command_execution": round(self.total_command_execution_time, 2),
            "interactions": self.interaction_count,
            "avg_time_per_interaction": round(total / max(1, self.interaction_count), 2),
        }

    def reset(self) -> None:
        """Reset all statistics."""
        self.total_input_processing_time = 0.0
        self.total_llm_response_time = 0.0
        self.total_command_execution_time = 0.0
        self.interaction_count = 0
        self._start_times.clear()
