const CHART_BASE_URL = "https://query1.finance.yahoo.com/v8/finance/chart/";

interface YahooChartResponse {
  chart: {
    result: Array<{
      indicators: {
        quote: Array<{ close: Array<number | null> }>;
      };
    }> | null;
    error: { description: string } | null;
  };
}

/**
 * Fetches the most recent daily closes for a symbol from Yahoo Finance's
 * public chart endpoint (no API key required). Decoupled from any single
 * broker/site so the RSI pipeline keeps working even if TradingView changes
 * its page markup.
 */
export async function fetchCloses(symbol: string, bars = 30): Promise<number[]> {
  const range = bars <= 30 ? "1mo" : "3mo";
  const url = `${CHART_BASE_URL}${encodeURIComponent(symbol)}?interval=1d&range=${range}`;

  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`price feed request failed: ${response.status}`);
  }

  const data = (await response.json()) as YahooChartResponse;
  if (data.chart.error) {
    throw new Error(`price feed error for "${symbol}": ${data.chart.error.description}`);
  }

  const result = data.chart.result?.[0];
  const rawCloses = result?.indicators.quote[0]?.close ?? [];
  const closes = rawCloses.filter((value): value is number => typeof value === "number");

  if (closes.length === 0) {
    throw new Error(`no price data returned for symbol "${symbol}"`);
  }

  return closes.slice(-bars);
}
