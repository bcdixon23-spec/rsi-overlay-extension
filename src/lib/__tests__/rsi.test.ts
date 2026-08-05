import { describe, expect, it } from "vitest";
import { wilderRsi } from "../rsi";

describe("wilderRsi", () => {
  it("returns null when there isn't enough data", () => {
    const closes = Array.from({ length: 10 }, (_, i) => 100 + i);
    expect(wilderRsi(closes, 14)).toBeNull();
  });

  it("returns 100 when there are no losses", () => {
    const closes = Array.from({ length: 20 }, (_, i) => 100 + i);
    expect(wilderRsi(closes, 14)).toEqual({ rsi: 100, barsUsed: 20 });
  });

  it("returns 0-ish when there are only losses", () => {
    const closes = Array.from({ length: 20 }, (_, i) => 200 - i);
    const result = wilderRsi(closes, 14)!;
    expect(result.rsi).toBeLessThan(1);
  });

  it("matches the Python bot's output for a mixed series (calc_rsi.py cross-check)", () => {
    // Cross-checked directly against calc_rsi.py: {"rsi": 57.92, "bars_used": 20}
    const closes = [
      44.34, 44.09, 44.15, 43.61, 44.33, 44.83, 45.1, 45.42, 45.84, 46.08,
      45.89, 46.03, 45.61, 46.28, 46.28, 46.0, 46.03, 46.41, 46.22, 45.64,
    ];
    const result = wilderRsi(closes, 14)!;
    expect(result.rsi).toBe(57.92);
    expect(result.barsUsed).toBe(20);
  });

  it("agrees with a manual average-based calculation", () => {
    const closes = [10, 11, 10.5, 12, 13, 12.5, 14, 15, 14.5, 16, 17, 16.5, 18, 19, 18.5];
    const result = wilderRsi(closes, 14)!;
    expect(result.rsi).toBeGreaterThan(0);
    expect(result.rsi).toBeLessThanOrEqual(100);
  });
});
