export interface Settings {
  enabled: boolean;
  symbol: string;
  oversold: number;
  overbought: number;
}

export const DEFAULT_SETTINGS: Settings = {
  enabled: true,
  symbol: "SPY",
  oversold: 30,
  overbought: 70,
};

export type RsiZone = "oversold" | "overbought" | "neutral";

export interface RsiState {
  symbol: string;
  rsi: number | null;
  zone: RsiZone;
  updatedAt: number;
  error?: string;
}

export interface PanelPosition {
  left: number;
  top: number;
}
