"use client";

import { create } from "zustand";
import { useCopilotStore } from "@/store/copilot-store";

export type SocTab = "command" | "feed" | "graph" | "analysis" | "copilot";

const TAB_KEY = "sentinelai.activeTab";
const TABS: SocTab[] = ["command", "feed", "graph", "analysis", "copilot"];

/** Read the persisted tab (client storage only — SSR falls back to "command"). */
export function loadSavedTab(): SocTab | null {
  if (typeof window === "undefined") return null;
  try {
    const saved = window.localStorage.getItem(TAB_KEY) as SocTab | null;
    return saved && TABS.includes(saved) ? saved : null;
  } catch {
    return null;
  }
}

function persistTab(tab: SocTab) {
  try {
    window.localStorage.setItem(TAB_KEY, tab);
  } catch {
    // storage blocked — tab just won't persist
  }
}

/**
 * Global SOC shell state: which tab is active + which incident is selected.
 * Lets any tab jump to another (e.g. incident row click → Analysis tab).
 * The active tab persists across reloads — restore it post-hydration via
 * loadSavedTab() (see Page) to avoid SSR/client markup mismatches.
 */
interface SocState {
  activeTab: SocTab;
  /** db id of the incident selected in the Analysis tab (null = auto-pick first) */
  selectedIncidentId: string | null;
  setActiveTab: (tab: SocTab) => void;
  selectIncident: (incidentDbId: string) => void;
  /** jump to Analysis tab with a specific incident */
  openIncident: (incidentDbId: string) => void;
  /** jump to Copilot tab with a pre-filled question */
  askQuestion: (question: string) => void;
}

export const useSocStore = create<SocState>((set) => ({
  activeTab: "command",
  selectedIncidentId: null,
  setActiveTab: (tab) => {
    persistTab(tab);
    set({ activeTab: tab });
  },
  selectIncident: (incidentDbId) => set({ selectedIncidentId: incidentDbId }),
  openIncident: (incidentDbId) => {
    persistTab("analysis");
    set({ selectedIncidentId: incidentDbId, activeTab: "analysis" });
  },
  askQuestion: (question) => {
    useCopilotStore.getState().askCopilot(question);
    persistTab("copilot");
    set({ activeTab: "copilot" });
  },
}));
