import { DEFAULT_SETTINGS, PanelPosition, RsiState, Settings } from "./types";

const SETTINGS_KEY = "settings";
const RSI_STATE_KEY = "rsiState";
const PANEL_POSITION_KEY = "panelPosition";

export async function getSettings(): Promise<Settings> {
  const stored = await chrome.storage.local.get(SETTINGS_KEY);
  return { ...DEFAULT_SETTINGS, ...(stored[SETTINGS_KEY] as Partial<Settings> | undefined) };
}

export async function setSettings(settings: Settings): Promise<void> {
  await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
}

export async function getRsiState(): Promise<RsiState | null> {
  const stored = await chrome.storage.local.get(RSI_STATE_KEY);
  return (stored[RSI_STATE_KEY] as RsiState | undefined) ?? null;
}

export async function setRsiState(state: RsiState): Promise<void> {
  await chrome.storage.local.set({ [RSI_STATE_KEY]: state });
}

export async function getPanelPosition(): Promise<PanelPosition | null> {
  const stored = await chrome.storage.local.get(PANEL_POSITION_KEY);
  return (stored[PANEL_POSITION_KEY] as PanelPosition | undefined) ?? null;
}

export async function setPanelPosition(position: PanelPosition): Promise<void> {
  await chrome.storage.local.set({ [PANEL_POSITION_KEY]: position });
}

export function onRsiStateChanged(callback: (state: RsiState) => void): void {
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== "local") return;
    const change = changes[RSI_STATE_KEY];
    if (change?.newValue) {
      callback(change.newValue as RsiState);
    }
  });
}

export function onSettingsChanged(callback: (settings: Settings) => void): void {
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== "local") return;
    const change = changes[SETTINGS_KEY];
    if (change?.newValue) {
      callback(change.newValue as Settings);
    }
  });
}
