import { evaluateRsi, shouldNotify } from "../lib/evaluateRsi";
import { fetchCloses } from "../lib/priceFeed";
import { getRsiState, getSettings, onSettingsChanged, setRsiState } from "../lib/storage";

const ALARM_NAME = "rsi-poll";
const POLL_PERIOD_MINUTES = 5;

async function runCheck(): Promise<void> {
  const settings = await getSettings();
  if (!settings.enabled) return;

  const previous = await getRsiState();

  try {
    const closes = await fetchCloses(settings.symbol);
    const next = evaluateRsi(closes, settings, settings.symbol, Date.now());
    await setRsiState(next);

    if (shouldNotify(previous?.zone, next)) {
      notify(next.symbol, next.rsi, next.zone);
    }
  } catch (err) {
    await setRsiState({
      symbol: settings.symbol,
      rsi: null,
      zone: "neutral",
      updatedAt: Date.now(),
      error: err instanceof Error ? err.message : String(err),
    });
  }
}

function notify(symbol: string, rsi: number, zone: "oversold" | "overbought"): void {
  chrome.notifications.create({
    type: "basic",
    iconUrl: "icons/icon128.png",
    title: `${symbol} RSI ${zone === "oversold" ? "oversold" : "overbought"}`,
    message: `RSI(14) is ${rsi.toFixed(1)} — crossed into ${zone === "oversold" ? "the oversold" : "the overbought"} zone.`,
  });
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(ALARM_NAME, { periodInMinutes: POLL_PERIOD_MINUTES });
  void runCheck();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM_NAME) {
    void runCheck();
  }
});

onSettingsChanged(() => {
  void runCheck();
});
