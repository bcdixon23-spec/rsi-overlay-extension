import { wilderRsi } from "./rsi";
import { RsiState, RsiZone, Settings } from "./types";

export function evaluateRsi(
  closes: number[],
  settings: Pick<Settings, "oversold" | "overbought">,
  symbol: string,
  now: number,
): RsiState {
  const result = wilderRsi(closes, 14);
  if (!result) {
    return {
      symbol,
      rsi: null,
      zone: "neutral",
      updatedAt: now,
      error: `insufficient data (${closes.length} bars, need 15)`,
    };
  }

  return {
    symbol,
    rsi: result.rsi,
    zone: zoneFor(result.rsi, settings),
    updatedAt: now,
  };
}

function zoneFor(rsi: number, settings: Pick<Settings, "oversold" | "overbought">): RsiZone {
  if (rsi <= settings.oversold) return "oversold";
  if (rsi >= settings.overbought) return "overbought";
  return "neutral";
}

/** True only on a transition into a non-neutral zone — the debounce for alerts. */
export function shouldNotify(
  previous: RsiZone | undefined,
  next: RsiState,
): next is RsiState & { rsi: number; zone: "oversold" | "overbought" } {
  return next.zone !== "neutral" && next.zone !== previous;
}
