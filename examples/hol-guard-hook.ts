import { spawn } from "node:child_process";
import type { PreToolUseHook } from "../src/sdk.js";

const GUARD_TIMEOUT_MS = 9_000;

type GuardRunner = (payload: string, signal: AbortSignal) => Promise<string>;

interface GuardHookResponse {
  policy_action: string;
  reason_code: string;
  reason?: string;
  systemMessage?: string;
  hookSpecificOutput: {
    hookEventName: string;
    permissionDecision: string;
    permissionDecisionReason?: string;
  };
}

/**
 * Guard Skawld's Bash tool with HOL Guard before execution.
 *
 * Register the returned hook with matcher "Bash". Commands are sent to the
 * HOL Guard CLI on stdin, never as command-line arguments. Invalid, unavailable,
 * or denied Guard results fail closed. A Guard review result stays an `ask`, so
 * Skawld's existing permission flow can request human approval without widening
 * an explicit Guard deny.
 */
export function createHolGuardPreToolHook(
  run: GuardRunner = runHolGuard,
): PreToolUseHook {
  return async (input, ctx) => {
    if (input.tool_name !== "Bash") return;

    const command = input.input.command;
    if (typeof command !== "string" || command.trim() === "") {
      return { action: "deny", reason: "HOL Guard: Bash command is missing" };
    }

    let response: GuardHookResponse;
    try {
      const payload = JSON.stringify({
        hook_event_name: "PreToolUse",
        tool_name: "Bash",
        tool_input: { command },
      });
      response = parseGuardResponse(await run(payload, ctx.signal));
    } catch (error) {
      return { action: "deny", reason: `HOL Guard: ${message(error)}` };
    }

    const decision = response.hookSpecificOutput.permissionDecision;
    if (
      decision === "allow" &&
      response.policy_action === "allow" &&
      response.reason_code.trim() !== ""
    ) {
      return { action: "continue" };
    }

    if (
      decision === "ask" &&
      response.policy_action === "review" &&
      response.reason_code.trim() !== ""
    ) {
      return { action: "ask" };
    }

    const reason =
      response.hookSpecificOutput.permissionDecisionReason?.trim() ||
      response.reason?.trim() ||
      response.systemMessage?.trim() ||
      `policy action ${response.policy_action} returned ${decision}`;
    return { action: "deny", reason: `HOL Guard: ${reason}` };
  };
}

function parseGuardResponse(raw: string): GuardHookResponse {
  const text = raw.trim();
  if (text === "") throw new Error("empty hook response");

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("invalid hook JSON");
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("invalid hook response");
  }

  const value = parsed as Partial<GuardHookResponse>;
  const hook = value.hookSpecificOutput;
  if (!hook || typeof hook !== "object") {
    throw new Error("hook response has no hookSpecificOutput");
  }
  if (hook.hookEventName !== "PreToolUse") {
    throw new Error("unexpected hook response event");
  }
  if (typeof hook.permissionDecision !== "string" || hook.permissionDecision.trim() === "") {
    throw new Error("hook response has no permission decision");
  }
  if (typeof value.policy_action !== "string" || value.policy_action.trim() === "") {
    throw new Error("hook response has no policy action");
  }
  if (typeof value.reason_code !== "string" || value.reason_code.trim() === "") {
    throw new Error("hook response has no reason code");
  }

  return value as GuardHookResponse;
}

function runHolGuard(payload: string, signal: AbortSignal): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      "hol-guard",
      ["hook", "--harness", "claude-code", "--json"],
      { stdio: ["pipe", "pipe", "pipe"], windowsHide: true },
    );

    let stdout = "";
    let stderr = "";
    let settled = false;

    const cleanup = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
    };
    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    const finish = (value: string) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(value);
    };
    const stop = (reason: string) => {
      child.kill("SIGTERM");
      fail(new Error(reason));
    };
    const onAbort = () => stop("hook request aborted");
    const timer = setTimeout(
      () => stop(`hook timed out after ${GUARD_TIMEOUT_MS}ms`),
      GUARD_TIMEOUT_MS,
    );

    timer.unref?.();
    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener("abort", onAbort, { once: true });
    child.stdout!.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr!.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    child.once("error", (error) => fail(error));
    child.once("close", (code) => {
      if (code === 0) {
        finish(stdout);
        return;
      }
      fail(new Error(stderr.trim() || `hook process exited with code ${code ?? "unknown"}`));
    });
    child.stdin!.on("error", (error) => fail(error));
    child.stdin!.end(payload);
  });
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

// Agent configuration:
//
// hooks: {
//   preToolUse: [
//     { matcher: "Bash", hook: createHolGuardPreToolHook() },
//   ],
// }
