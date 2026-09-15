/** Keep the report and recommended actions consistent with an explicit analyst verdict. */
export function analystActions(classification: string): string[] {
  return classification === "False Positive"
    ? ["Verify the analyst rationale and close the case if confirmed benign", "Record a tuning recommendation for similar alerts"]
    : ["Review the correlated alert timeline and validate the analyst assessment", "Investigate the affected accounts and assets"];
}
export function reviewedBluf(bluf: string, classification: string): string {
  const conclusion = classification === "False Positive"
    ? "An analyst classified this incident as a false positive; retained evidence documents the review."
    : classification === "Genuine Threat"
      ? "An analyst confirmed this incident as a genuine threat requiring investigation."
      : "An analyst placed this incident under review; the classification remains provisional.";
  return bluf.replace(/^BOTTOM LINE:.*$/m, `BOTTOM LINE: ${conclusion}`)
    .replace(/^IMMEDIATE ACTION:.*$/m, `IMMEDIATE ACTION: ${analystActions(classification)[0]}`);
}
