"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { Bot, Eraser, SendHorizonal, ShieldQuestion, Sparkles, User } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import { apiGet, apiSend } from "@/lib/api-client";
import { timeAgo } from "@/lib/ui-helpers";
import type { ChatHistory, CopilotChatResult, DashboardSummary } from "@/lib/types";
import { useCopilotStore } from "@/store/copilot-store";
import { cn } from "@/lib/utils";

interface ChatMsg {
  id: string;
  role: "user" | "assistant";
  content: string;
}

const FALLBACK_QUESTIONS = [
  "What is the highest-risk threat?",
  "Why is the top incident critical?",
  "What should we investigate first?",
  "Summarize all false positives.",
];

/** Three bouncing dots shown while the copilot is "thinking". */
function TypingDots() {
  return (
    <span className="inline-flex items-center gap-1" aria-label="Copilot is typing">
      <span className="soc-dot size-1.5 rounded-full bg-emerald-400" />
      <span className="soc-dot size-1.5 rounded-full bg-emerald-400" />
      <span className="soc-dot size-1.5 rounded-full bg-emerald-400" />
    </span>
  );
}

function Bubble({ msg }: { msg: ChatMsg }) {
  const isUser = msg.role === "user";
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className={cn("flex w-full items-start gap-2.5", isUser ? "justify-end" : "justify-start")}
    >
      {!isUser && (
        <span className="flex size-8 shrink-0 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/10">
          <Bot className="size-4 text-emerald-400" aria-hidden="true" />
        </span>
      )}
      <div
        className={cn(
          "max-w-[85%] rounded-xl border px-3.5 py-2.5 text-sm leading-relaxed sm:max-w-[75%]",
          isUser
            ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-50"
            : "border-border bg-card text-foreground/90"
        )}
        role={isUser ? undefined : "figure"}
        aria-label={isUser ? "Your message" : "Copilot message"}
      >
        <p className="whitespace-pre-wrap break-words">{msg.content}</p>
      </div>
      {isUser && (
        <span className="flex size-8 shrink-0 items-center justify-center rounded-lg border border-border bg-muted">
          <User className="size-4 text-muted-foreground" aria-hidden="true" />
        </span>
      )}
    </motion.div>
  );
}

export function AiCopilot() {
  const queryClient = useQueryClient();
  const [sessionMessages, setSessionMessages] = useState<ChatMsg[]>([]);
  const [input, setInput] = useState("");
  const [confirmingClear, setConfirmingClear] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  // chat history (loaded once; this session's messages live in local state)
  const historyQuery = useQuery({
    queryKey: ["chat"],
    queryFn: () => apiGet<ChatHistory>("/api/copilot/chat"),
  });

  const historyMessages: ChatMsg[] = (historyQuery.data?.messages ?? []).map((m) => ({
    id: m.id,
    role: m.role,
    content: m.content,
  }));
  const messages = [...historyMessages, ...sessionMessages];

  const sendMutation = useMutation({
    mutationFn: (text: string) =>
      apiSend<CopilotChatResult>("/api/copilot/chat", "POST", { message: text }),
    onSuccess: (data) => {
      setSessionMessages((prev) => [
        ...prev,
        { id: `a-${Date.now()}`, role: "assistant", content: data.reply },
      ]);
    },
    onError: (err: Error) => {
      toast.error("Copilot unavailable", {
        description: err.message.includes("502")
          ? "The analyst model service returned 502 — try again in a moment."
          : err.message,
      });
    },
  });

  const sending = sendMutation.isPending;

  const send = useCallback(
    (text: string) => {
      const trimmed = text.trim();
      if (!trimmed || sending) return;
      setSessionMessages((prev) => [
        ...prev,
        { id: `u-${Date.now()}`, role: "user", content: trimmed },
      ]);
      setInput("");
      sendMutation.mutate(trimmed);
    },
    [sending, sendMutation]
  );

  // auto-send triggered by Command Center quick questions
  const pendingQuestion = useCopilotStore((s) => s.pendingQuestion);
  const nonce = useCopilotStore((s) => s.nonce);
  const consumeQuestion = useCopilotStore((s) => s.consumeQuestion);

  useEffect(() => {
    if (nonce === 0) return;
    const q = pendingQuestion;
    if (q) {
      consumeQuestion();
      // send even while loading history — local state handles display
      const t = setTimeout(() => send(q), 150);
      return () => clearTimeout(t);
    }
  }, [nonce]);

  // auto-scroll to bottom on new content / typing state
  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages, sending]);

  const clearMutation = useMutation({
    mutationFn: () => apiSend<unknown>("/api/copilot/chat", "DELETE"),
    onSuccess: () => {
      setSessionMessages([]);
      queryClient.invalidateQueries({ queryKey: ["chat"] });
      toast.success("Conversation cleared");
    },
    onError: (err: Error) => {
      toast.error("Could not clear conversation", { description: err.message });
    },
  });

  // quick questions — first chip derives the top incident id dynamically
  const summaryQuery = useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: () => apiGet<DashboardSummary>("/api/dashboard/summary"),
    refetchInterval: 15_000,
  });
  const summary = summaryQuery.data;
  const topIncidentId = summary?.topIncidents[0]?.incidentId;
  const quickQuestions = [
    "What is the highest-risk threat?",
    topIncidentId ? `Why is ${topIncidentId} critical?` : FALLBACK_QUESTIONS[1],
    FALLBACK_QUESTIONS[2],
    FALLBACK_QUESTIONS[3],
  ];

  const contextChips = summary
    ? [
        { label: "incidents", value: `${summary.counts.open} open / ${summary.totalIncidents}` },
        { label: "genuine threats", value: `${summary.counts.genuineThreats}` },
        { label: "awaiting triage", value: `${summary.counts.unacknowledgedAlerts} alerts` },
        { label: "ai-analysed", value: `${summary.counts.analyzed}/${summary.totalIncidents}` },
      ]
    : [];

  return (
    <Card className="mx-auto flex w-full max-w-4xl flex-col gap-0 rounded-xl p-0">
      <div className="flex items-center justify-between gap-3 border-b border-border/70 px-4 py-4">
        <div className="flex items-center gap-3">
          <span className="flex size-9 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/10">
            <Bot className="size-5 text-emerald-400" aria-hidden="true" />
          </span>
          <div>
            <p className="text-sm font-semibold">SentinelAI Copilot</p>
            <p className="text-xs text-muted-foreground">
              Grounded in your live alerts, incidents and BLUF reports
            </p>
          </div>
        </div>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className={cn(
            "min-h-9 gap-1.5 text-muted-foreground hover:text-foreground",
            confirmingClear && "border border-red-500/40 bg-red-500/10 text-red-300 hover:bg-red-500/20 hover:text-red-200"
          )}
          disabled={clearMutation.isPending}
          onClick={() => {
            if (!confirmingClear) {
              setConfirmingClear(true);
              setTimeout(() => setConfirmingClear(false), 3000);
            } else {
              setConfirmingClear(false);
              clearMutation.mutate();
            }
          }}
          aria-label={confirmingClear ? "Confirm: clear conversation" : "Clear conversation"}
        >
          <Eraser className="size-3.5" aria-hidden="true" />
          {confirmingClear ? "Confirm?" : "Clear"}
        </Button>
      </div>

      {/* Live context strip — the data grounding the copilot's answers */}
      {contextChips.length > 0 && (
        <div
          className="flex flex-wrap items-center gap-x-4 gap-y-1.5 border-b border-border/70 bg-emerald-500/[0.04] px-4 py-2"
          aria-label="Copilot data context"
        >
          <span className="font-mono text-[9px] font-semibold uppercase tracking-[0.18em] text-emerald-400/70">
            context
          </span>
          {contextChips.map((c) => (
            <span key={c.label} className="flex items-baseline gap-1.5 font-mono text-[10px]">
              <span className="font-bold tabular-nums text-foreground/90">{c.value}</span>
              <span className="uppercase tracking-wider text-muted-foreground">{c.label}</span>
            </span>
          ))}
          {summary?.lastUpdated && (
            <span className="ml-auto hidden font-mono text-[10px] text-muted-foreground sm:inline">
              data as of {timeAgo(summary.lastUpdated)}
            </span>
          )}
        </div>
      )}

      <CardContent className="flex min-h-0 flex-1 flex-col gap-3 p-4">
        {/* Message list */}
        <div
          ref={scrollRef}
          className="soc-scroll flex max-h-[calc(100vh-22rem)] min-h-72 flex-1 flex-col gap-3 overflow-y-auto rounded-xl border border-white/5 bg-background/40 p-4"
          aria-live="polite"
          aria-label="Conversation"
        >
          {historyQuery.isLoading && messages.length === 0 ? (
            <div className="flex flex-col gap-3" aria-busy="true">
              <Skeleton className="ml-11 h-12 w-2/3 rounded-xl" />
              <Skeleton className="ml-auto h-9 w-1/3 rounded-xl" />
              <Skeleton className="ml-11 h-16 w-3/4 rounded-xl" />
            </div>
          ) : messages.length === 0 && !sending ? (
            <div className="flex h-full flex-col items-center justify-center gap-3 text-center">
              <span className="flex size-12 items-center justify-center rounded-xl border border-emerald-500/30 bg-emerald-500/10">
                <ShieldQuestion className="size-6 text-emerald-400" aria-hidden="true" />
              </span>
              <p className="text-sm font-medium">Ask about your threat landscape</p>
              <p className="max-w-sm text-xs leading-relaxed text-muted-foreground">
                The copilot reads correlated incidents, scores and BLUF reports — try a
                quick question below.
              </p>
            </div>
          ) : (
            messages.map((m) => <Bubble key={m.id} msg={m} />)
          )}
          {sending && (
            <div className="flex items-start gap-2.5">
              <span className="flex size-8 shrink-0 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/10">
                <Bot className="size-4 text-emerald-400" aria-hidden="true" />
              </span>
              <div className="flex items-center gap-2 rounded-xl border border-border bg-card px-3.5 py-3">
                <TypingDots />
                <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                  analyzing
                </span>
              </div>
            </div>
          )}
        </div>

        {/* Quick questions */}
        <div className="flex flex-wrap gap-1.5" aria-label="Suggested questions">
          {quickQuestions.map((q) => (
            <button
              key={q}
              type="button"
              onClick={() => send(q)}
              disabled={sending}
              className="inline-flex min-h-9 items-center gap-1.5 rounded-full border border-border bg-muted/50 px-3 text-xs text-foreground/85 transition-colors hover:border-emerald-500/40 hover:bg-emerald-500/10 hover:text-emerald-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
            >
              <Sparkles className="size-3 text-emerald-400/80" aria-hidden="true" />
              {q}
            </button>
          ))}
        </div>

        {/* Input */}
        <form
          className="flex items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            send(input);
          }}
        >
          <Textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) {
                e.preventDefault();
                send(input);
              }
            }}
            rows={1}
            placeholder="Ask the copilot… (Enter to send, Shift+Enter for newline)"
            aria-label="Message the AI copilot"
            className="min-h-11 max-h-36 flex-1 resize-none"
          />
          <Button
            type="submit"
            size="icon"
            className="size-11 shrink-0 border-emerald-500/50 bg-emerald-500/15 text-emerald-300 hover:bg-emerald-500/25 hover:text-emerald-200"
            disabled={sending || input.trim().length === 0}
            aria-label="Send message"
          >
            <SendHorizonal className="size-4" aria-hidden="true" />
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
