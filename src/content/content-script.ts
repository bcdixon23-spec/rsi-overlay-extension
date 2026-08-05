import {
  getPanelPosition,
  getRsiState,
  getSettings,
  onRsiStateChanged,
  onSettingsChanged,
  setPanelPosition,
} from "../lib/storage";
import { PanelPosition, RsiState } from "../lib/types";

const PANEL_ID = "rsi-overlay-panel";
const DEFAULT_POSITION: PanelPosition = { left: 60, top: 60 };

function ensurePanel(): HTMLElement {
  const existing = document.getElementById(PANEL_ID);
  if (existing) return existing;

  const panel = document.createElement("div");
  panel.id = PANEL_ID;
  panel.innerHTML = `
    <div class="rsi-overlay-symbol"></div>
    <div class="rsi-overlay-value">—</div>
    <div class="rsi-overlay-zone"></div>
  `;
  document.body.appendChild(panel);
  return panel;
}

function render(panel: HTMLElement, state: RsiState | null): void {
  const symbolEl = panel.querySelector(".rsi-overlay-symbol")!;
  const valueEl = panel.querySelector(".rsi-overlay-value")!;
  const zoneEl = panel.querySelector(".rsi-overlay-zone")!;

  panel.classList.remove("zone-oversold", "zone-overbought", "zone-neutral");

  if (!state) {
    symbolEl.textContent = "RSI";
    valueEl.textContent = "—";
    zoneEl.textContent = "waiting for data…";
    panel.classList.add("zone-neutral");
    return;
  }

  symbolEl.textContent = state.symbol;
  panel.classList.add(`zone-${state.zone}`);

  if (state.error || state.rsi === null) {
    valueEl.textContent = "—";
    zoneEl.textContent = state.error ?? "no data";
    return;
  }

  valueEl.textContent = state.rsi.toFixed(1);
  zoneEl.textContent =
    state.zone === "oversold" ? "oversold" : state.zone === "overbought" ? "overbought" : "neutral";
}

function setVisible(panel: HTMLElement, visible: boolean): void {
  panel.style.display = visible ? "block" : "none";
}

function applyPosition(panel: HTMLElement, position: PanelPosition): void {
  panel.style.left = `${position.left}px`;
  panel.style.top = `${position.top}px`;
}

function clampToViewport(left: number, top: number, panel: HTMLElement): PanelPosition {
  const maxLeft = window.innerWidth - panel.offsetWidth;
  const maxTop = window.innerHeight - panel.offsetHeight;
  return {
    left: Math.min(Math.max(left, 0), Math.max(maxLeft, 0)),
    top: Math.min(Math.max(top, 0), Math.max(maxTop, 0)),
  };
}

function enableDragging(panel: HTMLElement): void {
  let dragStart: { pointerX: number; pointerY: number; panelLeft: number; panelTop: number } | null = null;

  panel.addEventListener("mousedown", (event) => {
    dragStart = {
      pointerX: event.clientX,
      pointerY: event.clientY,
      panelLeft: panel.offsetLeft,
      panelTop: panel.offsetTop,
    };
    panel.classList.add("dragging");
    event.preventDefault();
  });

  window.addEventListener("mousemove", (event) => {
    if (!dragStart) return;
    const next = clampToViewport(
      dragStart.panelLeft + (event.clientX - dragStart.pointerX),
      dragStart.panelTop + (event.clientY - dragStart.pointerY),
      panel,
    );
    applyPosition(panel, next);
  });

  window.addEventListener("mouseup", () => {
    if (!dragStart) return;
    dragStart = null;
    panel.classList.remove("dragging");
    void setPanelPosition({ left: panel.offsetLeft, top: panel.offsetTop });
  });
}

async function init(): Promise<void> {
  const panel = ensurePanel();
  const [settings, position] = await Promise.all([getSettings(), getPanelPosition()]);

  applyPosition(panel, position ?? DEFAULT_POSITION);
  setVisible(panel, settings.enabled);
  render(panel, await getRsiState());
  enableDragging(panel);

  onRsiStateChanged((state) => render(panel, state));
  onSettingsChanged((next) => setVisible(panel, next.enabled));
}

void init();
