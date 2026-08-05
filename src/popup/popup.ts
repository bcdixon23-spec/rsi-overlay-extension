import { getRsiState, getSettings, onRsiStateChanged, setSettings } from "../lib/storage";
import { RsiState, Settings } from "../lib/types";

const enabledInput = document.getElementById("enabled") as HTMLInputElement;
const symbolInput = document.getElementById("symbol") as HTMLInputElement;
const oversoldInput = document.getElementById("oversold") as HTMLInputElement;
const overboughtInput = document.getElementById("overbought") as HTMLInputElement;
const statusEl = document.getElementById("status") as HTMLDivElement;
const currentEl = document.getElementById("current") as HTMLDivElement;
const saveButton = document.getElementById("save") as HTMLButtonElement;

function fillForm(settings: Settings): void {
  enabledInput.checked = settings.enabled;
  symbolInput.value = settings.symbol;
  oversoldInput.value = String(settings.oversold);
  overboughtInput.value = String(settings.overbought);
}

function readForm(): Settings {
  return {
    enabled: enabledInput.checked,
    symbol: symbolInput.value.trim().toUpperCase() || "SPY",
    oversold: clamp(Number(oversoldInput.value) || 30, 0, 100),
    overbought: clamp(Number(overboughtInput.value) || 70, 0, 100),
  };
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function renderCurrentState(state: RsiState | null): void {
  if (!state) {
    currentEl.textContent = "No data yet.";
    return;
  }
  if (state.error || state.rsi === null) {
    currentEl.textContent = `${state.symbol}: ${state.error ?? "no data"}`;
    return;
  }
  const age = Math.round((Date.now() - state.updatedAt) / 60000);
  const freshness = age <= 0 ? "just now" : `${age}m ago`;
  currentEl.textContent = `${state.symbol} RSI ${state.rsi.toFixed(1)} (${state.zone}) · updated ${freshness}`;
}

async function init(): Promise<void> {
  fillForm(await getSettings());
  renderCurrentState(await getRsiState());
  onRsiStateChanged(renderCurrentState);
}

saveButton.addEventListener("click", async () => {
  const settings = readForm();
  if (settings.oversold >= settings.overbought) {
    statusEl.style.color = "#e74c3c";
    statusEl.textContent = "Oversold must be lower than overbought.";
    return;
  }

  saveButton.disabled = true;
  statusEl.style.color = "#2ecc71";
  statusEl.textContent = "Saved.";
  currentEl.textContent = `Checking ${settings.symbol}…`;

  await setSettings(settings);

  saveButton.disabled = false;
  setTimeout(() => (statusEl.textContent = ""), 1500);
});

void init();
