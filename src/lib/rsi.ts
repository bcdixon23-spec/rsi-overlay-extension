export interface RsiResult {
  rsi: number;
  barsUsed: number;
}

/**
 * Wilder's RSI, ported 1:1 from the Python bot's calc_rsi.py so both stay
 * in agreement. `period` bars of warmup are required beyond the first close.
 */
export function wilderRsi(closes: number[], period = 14): RsiResult | null {
  if (closes.length < period + 1) {
    return null;
  }

  const gains: number[] = [];
  const losses: number[] = [];
  for (let i = 1; i < closes.length; i++) {
    const change = closes[i] - closes[i - 1];
    gains.push(Math.max(change, 0));
    losses.push(Math.max(-change, 0));
  }

  let avgGain = sum(gains.slice(0, period)) / period;
  let avgLoss = sum(losses.slice(0, period)) / period;

  for (let i = period; i < gains.length; i++) {
    avgGain = (avgGain * (period - 1) + gains[i]) / period;
    avgLoss = (avgLoss * (period - 1) + losses[i]) / period;
  }

  if (avgLoss === 0) {
    return { rsi: 100, barsUsed: closes.length };
  }

  const rs = avgGain / avgLoss;
  const rsi = 100 - 100 / (1 + rs);
  return { rsi: round2(rsi), barsUsed: closes.length };
}

function sum(values: number[]): number {
  return values.reduce((total, value) => total + value, 0);
}

function round2(value: number): number {
  return Math.round(value * 100) / 100;
}
