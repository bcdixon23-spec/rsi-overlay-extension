import { describe, expect, it } from "vitest";
import { evaluateRsi, shouldNotify } from "../evaluateRsi";

const settings = { oversold: 30, overbought: 70 };

describe("evaluateRsi", () => {
  it("flags insufficient data instead of throwing", () => {
    const state = evaluateRsi([1, 2, 3], settings, "SPY", 1000);
    expect(state.rsi).toBeNull();
    expect(state.zone).toBe("neutral");
    expect(state.error).toMatch(/insufficient data/);
  });

  it("classifies a known oversold series", () => {
    const closes = Array.from({ length: 20 }, (_, i) => 200 - i); // steadily falling
    const state = evaluateRsi(closes, settings, "SPY", 1000);
    expect(state.zone).toBe("oversold");
    expect(state.error).toBeUndefined();
  });

  it("classifies a known overbought series", () => {
    const closes = Array.from({ length: 20 }, (_, i) => 100 + i); // steadily rising
    const state = evaluateRsi(closes, settings, "SPY", 1000);
    expect(state.zone).toBe("overbought");
  });
});

describe("shouldNotify", () => {
  it("does not notify while zone stays neutral", () => {
    expect(shouldNotify("neutral", { symbol: "SPY", rsi: 50, zone: "neutral", updatedAt: 0 })).toBe(false);
  });

  it("notifies on transition from neutral into oversold", () => {
    expect(shouldNotify("neutral", { symbol: "SPY", rsi: 28, zone: "oversold", updatedAt: 0 })).toBe(true);
  });

  it("does not re-notify while already in the same zone", () => {
    expect(shouldNotify("oversold", { symbol: "SPY", rsi: 25, zone: "oversold", updatedAt: 0 })).toBe(false);
  });

  it("notifies again when crossing directly from oversold to overbought", () => {
    expect(shouldNotify("oversold", { symbol: "SPY", rsi: 75, zone: "overbought", updatedAt: 0 })).toBe(true);
  });
});
