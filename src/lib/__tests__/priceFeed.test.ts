import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchCloses } from "../priceFeed";

function mockFetch(body: unknown, ok = true, status = 200) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok,
      status,
      json: async () => body,
    }),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("fetchCloses", () => {
  it("extracts closes from a real-shaped Yahoo chart response", async () => {
    mockFetch({
      chart: {
        result: [
          {
            indicators: {
              quote: [{ close: [751.28, 747.71, 745.4, 751.71, 754.95] }],
            },
          },
        ],
        error: null,
      },
    });

    const closes = await fetchCloses("SPY", 30);
    expect(closes).toEqual([751.28, 747.71, 745.4, 751.71, 754.95]);
  });

  it("filters out null bars (halts/missing data)", async () => {
    mockFetch({
      chart: {
        result: [{ indicators: { quote: [{ close: [100, null, 102, null, 104] }] } }],
        error: null,
      },
    });

    const closes = await fetchCloses("SPY", 30);
    expect(closes).toEqual([100, 102, 104]);
  });

  it("respects the bars limit by taking the most recent entries", async () => {
    mockFetch({
      chart: {
        result: [{ indicators: { quote: [{ close: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] }] } }],
        error: null,
      },
    });

    const closes = await fetchCloses("SPY", 3);
    expect(closes).toEqual([8, 9, 10]);
  });

  it("throws when Yahoo returns an error payload for an invalid symbol", async () => {
    mockFetch({
      chart: { result: null, error: { description: "No data found, symbol may be delisted" } },
    });

    await expect(fetchCloses("NOTASYMBOL")).rejects.toThrow(/No data found/);
  });

  it("throws when the HTTP request itself fails", async () => {
    mockFetch({}, false, 502);
    await expect(fetchCloses("SPY")).rejects.toThrow(/502/);
  });
});
