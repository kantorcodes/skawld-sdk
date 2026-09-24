import { describe, expect, test } from "bun:test";
import { createHolGuardPreToolHook } from "./hol-guard-hook.js";

const ctx = () => ({
  session_id: "session-1",
  run_id: "run-1",
  cwd: "/tmp/project",
  signal: new AbortController().signal,
});

const input = (command = "git status") => ({
  tool_name: "Bash",
  tool_use_id: "tool-1",
  input: { command },
  summary: `Bash: ${command}`,
});

describe("HOL Guard PreToolUse example", () => {
  test("continues only on an authoritative allow", async () => {
    let received = "";
    const hook = createHolGuardPreToolHook(async (payload) => {
      received = payload;
      return JSON.stringify({
        policy_action: "allow",
        reason_code: "native_policy_allow",
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "allow",
        },
      });
    });

    expect(await hook(input(), ctx())).toEqual({ action: "continue" });
    expect(JSON.parse(received)).toEqual({
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command: "git status" },
    });
  });

  test("preserves a Guard review as ask", async () => {
    const hook = createHolGuardPreToolHook(async () =>
      JSON.stringify({
        policy_action: "review",
        reason_code: "native_pre_tool_review",
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "ask",
          permissionDecisionReason: "Guard review required",
        },
      }),
    );

    expect(await hook(input("bun add example"), ctx())).toEqual({ action: "ask" });
  });

  test("denies an explicit Guard block", async () => {
    const hook = createHolGuardPreToolHook(async () =>
      JSON.stringify({
        policy_action: "block",
        reason_code: "policy_block",
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason: "Policy denied the command",
        },
      }),
    );

    expect(await hook(input("rm -rf /tmp/example"), ctx())).toEqual({
      action: "deny",
      reason: "HOL Guard: Policy denied the command",
    });
  });

  test("denies an allow-shaped non-allow policy result", async () => {
    const hook = createHolGuardPreToolHook(async () =>
      JSON.stringify({
        policy_action: "warn",
        reason_code: "native_hook_worker_exception",
        reason: "Native review was unavailable.",
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "allow",
        },
      }),
    );

    expect(await hook(input(), ctx())).toEqual({
      action: "deny",
      reason: "HOL Guard: Native review was unavailable.",
    });
  });

  test("fails closed on malformed or unavailable Guard results", async () => {
    const malformed = createHolGuardPreToolHook(async () => "not json");
    const unavailable = createHolGuardPreToolHook(async () => {
      throw new Error("binary missing");
    });

    expect(await malformed(input(), ctx())).toEqual({
      action: "deny",
      reason: "HOL Guard: invalid hook JSON",
    });
    expect(await unavailable(input(), ctx())).toEqual({
      action: "deny",
      reason: "HOL Guard: binary missing",
    });
  });

  test("fails closed when Bash input has no command", async () => {
    const hook = createHolGuardPreToolHook(async () => {
      throw new Error("runner should not be called");
    });
    const badInput = {
      tool_name: "Bash",
      tool_use_id: "tool-1",
      input: {},
      summary: "Bash",
    };

    expect(await hook(badInput, ctx())).toEqual({
      action: "deny",
      reason: "HOL Guard: Bash command is missing",
    });
  });
});
