import { spawn } from "node:child_process";
import { realpathSync } from "node:fs";
import { delimiter, isAbsolute, relative, sep } from "node:path";
import type { PreToolUseHook } from "../src/sdk.js";

const GUARD_TIMEOUT_MS = 9_000;
const MAX_GUARD_OUTPUT_BYTES = 64 * 1024;

type GuardRunner = (payload: string, signal: AbortSignal, cwd: string) => Promise<string>;

interface GuardHookResponse {
  continue?: boolean;
  decision?: string;
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

    // Even a malformed Bash envelope must deny rather than throw from the hook.
    const command = input.input?.command;
    if (typeof command !== "string" || command.trim() === "") {
      return { action: "deny", reason: "HOL Guard: Bash command is missing" };
    }

    // An ambiguous or relative cwd could inspect a different project than Bash.
    if (typeof ctx?.cwd !== "string" || !isAbsolute(ctx.cwd)) {
      return { action: "deny", reason: "HOL Guard: Bash cwd must be an absolute path" };
    }

    let response: GuardHookResponse;
    try {
      const payload = JSON.stringify({
        hook_event_name: "PreToolUse",
        tool_name: "Bash",
        // Keep path-sensitive Guard inspection in the same directory as Skawld.
        cwd: ctx.cwd,
        tool_input: { command },
      });
      response = parseGuardResponse(await run(payload, ctx.signal, ctx.cwd));
    } catch (error) {
      return { action: "deny", reason: `HOL Guard: ${message(error)}` };
    }

    const decision = response.hookSpecificOutput.permissionDecision;
    const reasonCode = response.reason_code.trim();
    const topDecision = typeof response.decision === "string" ? response.decision.trim().toLowerCase() : undefined;
    const continuationStopped = Object.prototype.hasOwnProperty.call(response, "continue") && response.continue !== true;
    const conflictingDecision = Object.prototype.hasOwnProperty.call(response, "decision") &&
      (typeof response.decision !== "string" || (topDecision !== "allow" && topDecision !== "review"));
    // A native-exact error or review code is not itself permission to execute.
    const allowReason = reasonCode.startsWith("native_exact_safe_") ||
      reasonCode === "native_exact_introspection_command" ||
      reasonCode === "native_policy_allow" ||
      reasonCode === "native_custom_mcp_tool_allow";

    if (continuationStopped || conflictingDecision ||
        (topDecision === "review" && decision === "allow")) {
      return { action: "deny", reason: "HOL Guard explicitly stopped or returned an invalid verdict" };
    }

    if (
      decision === "allow" &&
      response.policy_action === "allow" &&
      allowReason
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

    // The JSON parser accepts optional human-readable fields from untrusted
    // Guard output. Never call string methods on unchecked values: a thrown
    // hook error could be treated as abstention by the host.
    const reason =
      safeReason(response.hookSpecificOutput.permissionDecisionReason) ||
      safeReason(response.reason) ||
      safeReason(response.systemMessage) ||
      `policy action ${response.policy_action} returned ${decision}`;
    return { action: "deny", reason: `HOL Guard: ${reason}` };
  };
}

function safeReason(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

// JSON.parse keeps the last duplicate key; an allow cannot replace a deny.
function containsDuplicateJsonKeys(raw: string): boolean {
  const frames: Array<{ isObject: boolean; expectKey: boolean; keys: Set<string> }> = [];
  for (let i = 0; i < raw.length;) {
    const char = raw[i];
    if (char === '"') {
      const start = i++;
      while (i < raw.length) {
        if (raw[i] === "\\") {
          i += 2;
          continue;
        }
        if (raw[i++] === '"') break;
      }
      const frame = frames[frames.length - 1];
      if (frame?.isObject && frame.expectKey) {
        // Decode escaped property names before comparing them.
        const key = JSON.parse(raw.slice(start, i)) as string;
        if (frame.keys.has(key)) return true;
        frame.keys.add(key);
        frame.expectKey = false;
      }
      continue;
    }
    if (char === "{") frames.push({ isObject: true, expectKey: true, keys: new Set() });
    else if (char === "[") frames.push({ isObject: false, expectKey: false, keys: new Set() });
    else if (char === "}" || char === "]") frames.pop();
    else if (char === "," && frames[frames.length - 1]?.isObject) {
      frames[frames.length - 1].expectKey = true;
    }
    i++;
  }
  return false;
}

function parseGuardResponse(raw: string): GuardHookResponse {
  if (Buffer.byteLength(raw, "utf8") > MAX_GUARD_OUTPUT_BYTES) {
    throw new Error("hook response exceeds 64 KiB");
  }
  const text = raw.trim();
  if (text === "") throw new Error("empty hook response");

  let parsed: unknown;
  try {
    if (containsDuplicateJsonKeys(text)) throw new Error("duplicate hook verdict key");
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

/**
 * Drop relative or empty PATH entries before changing into an agent worktree.
 * Otherwise a project-local executable could replace the intended Guard CLI.
 * Never fall back to the OS default search path when filtering removes all dirs.
 */
function isWithinWorktree(candidate: string, root: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

/**
 * The worktree may contain executable shims in absolute PATH directories.
 * Resolve symlinks and exclude those directories before starting Guard.
 * An absent or unresolvable directory cannot supply a trusted Guard binary.
 */
export function guardSpawnEnv(source: NodeJS.ProcessEnv, cwd?: string): NodeJS.ProcessEnv {
  let worktree: string | undefined;
  if (cwd !== undefined) {
    if (!isAbsolute(cwd)) throw new Error("hol-guard requires an absolute worktree directory");
    worktree = realpathSync(cwd);
  }
  const key = Object.keys(source).find((name) => name.toUpperCase() === "PATH");
  const absolutePath = (key ? source[key] ?? "" : "")
    .split(delimiter)
    .filter((entry) => {
      if (!entry || !isAbsolute(entry)) return false;
      if (!worktree) return true;
      try {
        return !isWithinWorktree(realpathSync(entry), worktree);
      } catch {
        return false;
      }
    })
    .join(delimiter);
  if (!absolutePath) throw new Error("hol-guard requires an absolute executable PATH");
  const sanitized = { ...source };
  for (const name of Object.keys(sanitized)) {
    if (name.toUpperCase() === "PATH") delete sanitized[name];
  }
  sanitized.PATH = absolutePath;
  return sanitized;
}

function runHolGuard(payload: string, signal: AbortSignal, cwd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    // Do not spawn after cancellation: an immediate return before attaching the
    // child error listener can otherwise crash the host on ENOENT.
    if (signal.aborted) {
      reject(new Error("hook request aborted"));
      return;
    }
    let env: NodeJS.ProcessEnv;
    try {
      env = guardSpawnEnv(process.env, cwd);
    } catch (error) {
      reject(error);
      return;
    }
    const child = spawn(
      "hol-guard",
      ["hook", "--harness", "claude-code", "--json"],
      { stdio: ["pipe", "pipe", "pipe"], windowsHide: true, cwd, env },
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
    // Attach every child error/stream listener before checking for a cancellation
    // that races with spawn. An ENOENT error can otherwise escape unhandled.
    child.stdout!.on("data", (chunk: Buffer) => {
      if (settled) return;
      stdout += chunk.toString("utf8");
      if (Buffer.byteLength(stdout, "utf8") > MAX_GUARD_OUTPUT_BYTES) {
        stop("hook stdout exceeds 64 KiB");
      }
    });
    child.stderr!.on("data", (chunk: Buffer) => {
      if (settled) return;
      stderr += chunk.toString("utf8");
      if (Buffer.byteLength(stderr, "utf8") > MAX_GUARD_OUTPUT_BYTES) {
        stop("hook stderr exceeds 64 KiB");
      }
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
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) {
      onAbort();
      return;
    }
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
