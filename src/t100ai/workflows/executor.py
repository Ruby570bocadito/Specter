"""Workflow Executor - Executes multi-step security workflows."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class StepStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class WorkflowStep:
    name: str
    action: str
    params: dict[str, Any] = field(default_factory=dict)
    condition: Optional[str] = None
    status: StepStatus = StepStatus.PENDING
    result: Optional[dict] = None
    error: Optional[str] = None
    execution_time: float = 0.0


@dataclass
class WorkflowResult:
    name: str
    success: bool
    steps: list[WorkflowStep] = field(default_factory=list)
    total_time: float = 0.0
    error: Optional[str] = None


class WorkflowExecutor:
    """Executes multi-step security workflows with conditional branching."""

    def __init__(self) -> None:
        self._workflows: dict[str, list[WorkflowStep]] = {}
        self._current_result: Optional[WorkflowResult] = None
        self._cancelled = False

    async def run_workflow(self, name: str, params: dict[str, Any]) -> dict[str, Any]:
        """Run a workflow by name with given parameters."""
        from t100ai.workflows.definitions import BUILTIN_WORKFLOWS

        if name not in BUILTIN_WORKFLOWS:
            return {"success": False, "error": f"Workflow '{name}' not found"}

        wf_def = BUILTIN_WORKFLOWS[name]
        steps = [
            WorkflowStep(name=step, action=step, params={**params})
            for step in wf_def.get("steps", [])
        ]

        result = WorkflowResult(name=name, success=True, steps=steps)
        self._current_result = result
        self._cancelled = False
        start_time = time.time()

        for step in steps:
            if self._cancelled:
                step.status = StepStatus.SKIPPED
                continue

            if step.condition and not self._evaluate_condition(step.condition, result):
                step.status = StepStatus.SKIPPED
                continue

            step.status = StepStatus.RUNNING
            step_start = time.time()

            try:
                step_result = await self._execute_step(step)
                step.result = step_result
                step.status = StepStatus.COMPLETED
            except Exception as e:
                step.error = str(e)
                step.status = StepStatus.FAILED
                if wf_def.get("stop_on_failure", True):
                    result.success = False
                    break

            step.execution_time = time.time() - step_start

        result.total_time = time.time() - start_time
        self._current_result = result
        return {
            "success": result.success,
            "name": result.name,
            "total_time": round(result.total_time, 2),
            "steps": [
                {
                    "name": s.name,
                    "status": s.status.value,
                    "error": s.error,
                    "execution_time": round(s.execution_time, 2),
                }
                for s in result.steps
            ],
        }

    async def _execute_step(self, step: WorkflowStep) -> dict[str, Any]:
        """Execute a single workflow step."""
        await asyncio.sleep(0.01)
        return {"action": step.action, "params": step.params, "status": "completed"}

    def _evaluate_condition(self, condition: str, result: WorkflowResult) -> bool:
        """Evaluate a condition based on previous step results."""
        for step in result.steps:
            if step.name == condition and step.status == StepStatus.COMPLETED:
                return True
            if step.name == condition and step.status == StepStatus.FAILED:
                return False
        return True

    def list_workflows(self) -> list[dict[str, Any]]:
        """List available workflows."""
        from t100ai.workflows.definitions import BUILTIN_WORKFLOWS
        return [
            {
                "name": name,
                "description": wf.get("description", ""),
                "steps": wf.get("steps", []),
            }
            for name, wf in BUILTIN_WORKFLOWS.items()
        ]

    def get_status(self) -> dict[str, Any]:
        """Get current workflow execution status."""
        if self._current_result is None:
            return {"status": "idle"}
        return {
            "status": "running" if not all(s.status in (StepStatus.COMPLETED, StepStatus.FAILED, StepStatus.SKIPPED) for s in self._current_result.steps) else "completed",
            "workflow": self._current_result.name,
            "steps": [
                {"name": s.name, "status": s.status.value, "error": s.error}
                for s in self._current_result.steps
            ],
        }

    def cancel(self) -> None:
        """Cancel the current workflow execution."""
        self._cancelled = True
