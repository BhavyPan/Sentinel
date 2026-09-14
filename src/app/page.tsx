"use client";

import { LayoutDashboard, Radio, Crosshair, Bot } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { SocHeader } from "@/components/soc/header";
import { SocFooter } from "@/components/soc/footer";
import { CommandCenter } from "@/components/soc/tabs/command-center";
import { ThreatFeed } from "@/components/soc/tabs/threat-feed";
import { IncidentAnalysis } from "@/components/soc/tabs/incident-analysis";
import { AiCopilot } from "@/components/soc/tabs/ai-copilot";
import { useSocStore, type SocTab } from "@/store/soc-store";
import { cn } from "@/lib/utils";

const TAB_ITEMS: {
  value: SocTab;
  label: string;
  icon: typeof Bot;
}[] = [
  { value: "command", label: "Command Center", icon: LayoutDashboard },
  { value: "feed", label: "Threat Feed", icon: Radio },
  { value: "analysis", label: "Incident Analysis", icon: Crosshair },
  { value: "copilot", label: "AI Copilot", icon: Bot },
];

export default function Page() {
  const activeTab = useSocStore((s) => s.activeTab);
  const setActiveTab = useSocStore((s) => s.setActiveTab);

  return (
    <div className="flex min-h-screen flex-col">
      <SocHeader />

      <main className="mx-auto w-full max-w-[1600px] flex-1 px-3 py-4 sm:px-6 sm:py-6">
        <Tabs
          value={activeTab}
          onValueChange={(v) => setActiveTab(v as SocTab)}
          className="gap-4 sm:gap-6"
        >
          <TabsList
            className="h-auto w-full justify-stretch gap-1 overflow-x-auto rounded-xl border border-white/8 bg-card/60 p-1 sm:mx-auto sm:w-fit sm:justify-center"
            role="tablist"
            aria-label="SOC sections"
          >
            {TAB_ITEMS.map(({ value, label, icon: Icon }) => (
              <TabsTrigger
                key={value}
                value={value}
                aria-label={label}
                className={cn(
                  "min-h-11 flex-1 gap-2 rounded-lg px-3 py-2 text-xs font-medium transition-colors sm:flex-none sm:px-5 sm:text-sm",
                  "data-[state=active]:bg-emerald-500/15 dark:data-[state=active]:bg-emerald-500/15",
                  "data-[state=active]:text-emerald-300 dark:data-[state=active]:text-emerald-300",
                  "data-[state=active]:border-emerald-500/40 dark:data-[state=active]:border-emerald-500/40",
                  "data-[state=active]:shadow-none dark:data-[state=active]:shadow-none"
                )}
              >
                <Icon className="size-4 shrink-0" aria-hidden="true" />
                <span className="hidden sm:inline">{label}</span>
                <span className="sr-only sm:hidden">{label}</span>
              </TabsTrigger>
            ))}
          </TabsList>

          <TabsContent value="command">
            <CommandCenter />
          </TabsContent>
          <TabsContent value="feed">
            <ThreatFeed />
          </TabsContent>
          <TabsContent value="analysis">
            <IncidentAnalysis />
          </TabsContent>
          <TabsContent value="copilot">
            <AiCopilot />
          </TabsContent>
        </Tabs>
      </main>

      <SocFooter />
    </div>
  );
}
