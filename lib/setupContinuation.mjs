// Intent contains identity and kind only. A failed command is never a queued operation.
import { randomUUID } from "node:crypto";

const KEY = "setup-continuations-v1";
const TTL = 60 * 60 * 1000;
const LIMIT = 100;

export function createSetupContinuation({ storage, locked, now, sendThread, authorized, ready, jobStatus }) {
  const transaction = (task) => locked(KEY, async () => {
    const stored = await storage.get(KEY);
    const entries = (Array.isArray(stored) ? stored : []).filter((entry) =>
      entry && typeof entry.at === "number" && entry.at <= now() && now() - entry.at < 24 * TTL);
    for (const entry of entries) if (entry.state === "pending" && now() - entry.at >= TTL) entry.state = "expired";
    let saved = JSON.stringify(stored ?? []);
    return task(entries, async () => {
      const value = entries.slice(-LIMIT);
      const encoded = JSON.stringify(value);
      if (encoded !== saved) {
        await storage.set(KEY, value);
        saved = encoded;
      }
    });
  });
  const record = (who, kind) => {
    if (who.kind !== "agent") return;
    return transaction(async (entries, save) => {
      if (!await authorized({ ownerThreadId: who.threadId, kind })) return;
      if (!entries.some((entry) => entry.ownerThreadId === who.threadId && entry.kind === kind && entry.state === "pending"))
        entries.push({ id: randomUUID(), ownerThreadId: who.threadId, threadId: who.sourceThreadId ?? who.threadId,
          kind, at: now(), state: "pending" });
      await save();
    });
  };
  const invalidate = (ownerThreadId) => transaction(async (entries, save) => {
    for (const entry of entries) if (entry.ownerThreadId === ownerThreadId) entry.state = "invalidated";
    await save();
  });
  const approve = (kind, jobId) => transaction(async (entries, save) => {
    for (const entry of entries) {
      if (entry.kind === kind && entry.state === "pending" && !entry.approved) {
        entry.approved = true;
        entry.jobId = jobId ?? null;
      }
    }
    await save();
  });
  const observe = (who, observedJob) => {
    if (who.kind !== "user") return;
    return transaction(async (entries, save) => {
      for (const entry of entries) {
        if (entry.state !== "pending" || !entry.approved ||
          (observedJob ? entry.jobId !== observedJob.job_id : who.threadId !== undefined && entry.ownerThreadId !== who.threadId)) continue;
        if (!await authorized(entry)) { entry.state = "invalidated"; continue; }
        const job = entry.jobId ? (observedJob ?? await jobStatus(entry.jobId)) : null;
        if (job && job.state !== "succeeded") {
          if (!["queued", "running"].includes(job.state)) entry.state = "invalidated";
          continue;
        }
        if (!await ready(entry.kind)) continue;
        // Persist before dispatch: a worker crash or ambiguous host reply must never replay a turn.
        entry.state = "uncertain";
        await save();
        try {
          if (sendThread) {
            await sendThread({ threadId: entry.threadId, idempotencyKey: `realm-setup-${entry.id}`,
              text: "Realm setup succeeded for this conversation. Reevaluate your current task and continue the requested private test only if it is still needed and authorized. Do not replay a previous click or command; inspect current state first." });
            entry.state = "sent";
          } else entry.state = "unavailable";
        } catch (error) {
          // threads.send is a separate project grant. Denial leaves setup successful and requires a manual retry.
          entry.state = error?.reason === "permission_denied" || error?.code === "permission_denied" ? "denied" : "uncertain";
        }
        await save();
      }
      await save();
      return entries.filter((entry) => observedJob ? entry.jobId === observedJob.job_id : who.threadId === undefined || entry.ownerThreadId === who.threadId)
        .slice(-10).map((entry) => ({ threadId: entry.threadId, ownerThreadId: entry.ownerThreadId, state: entry.state,
          manualContinuationRequired: ["unavailable", "denied", "uncertain", "expired"].includes(entry.state),
          message: ["unavailable", "denied", "uncertain", "expired"].includes(entry.state)
            ? "Automatic continuation was not confirmed; ask the agent to continue in the requesting thread. No old command was replayed."
            : entry.state === "sent" ? "Continuation notification sent; no old command was replayed." : "Setup continuation is pending or invalidated; ask the agent to continue manually if needed." }));
    });
  };
  return { record, invalidate, approve, observe };
}
