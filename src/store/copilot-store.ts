"use client";

import { create } from "zustand";

/**
 * Cross-component bridge for the AI Copilot tab.
 * Command Center quick-question buttons push a question here, then switch
 * to the Copilot tab; the Copilot consumes it and auto-sends.
 */
interface CopilotState {
  /** question waiting to be auto-sent by the Copilot tab (null = nothing pending) */
  pendingQuestion: string | null;
  /** increments on every askCopilot so repeated identical questions still trigger */
  nonce: number;
  askCopilot: (question: string) => void;
  consumeQuestion: () => void;
}

export const useCopilotStore = create<CopilotState>((set) => ({
  pendingQuestion: null,
  nonce: 0,
  askCopilot: (question: string) =>
    set((s) => ({ pendingQuestion: question, nonce: s.nonce + 1 })),
  consumeQuestion: () => set({ pendingQuestion: null }),
}));
