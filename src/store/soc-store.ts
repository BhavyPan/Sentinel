"use client";

import { create } from "zustand";
import { useCopilotStore } from "@/store/copilot-store";

export type SocTab = "command" | "feed" | "graph" | "analysis" | "copilot";

/**
 * Global SOC shell state: which tab is active + which incident is selected.
 * Lets any tab jump to another (e.g. incident row click → Analysis tab).
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
  setActiveTab: (tab) => set({ activeTab: tab }),
  selectIncident: (incidentDbId) => set({ selectedIncidentId: incidentDbId }),
  openIncident: (incidentDbId) =>
    set({ selectedIncidentId: incidentDbId, activeTab: "analysis" }),
  askQuestion: (question) => {
    useCopilotStore.getState().askCopilot(question);
    set({ activeTab: "copilot" });
  },
}));
