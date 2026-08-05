# RSI Overlay for TradingView

A free Chrome extension that overlays a live Wilder RSI(14) reading on TradingView charts, with threshold alerts.

Landing page / support / privacy policy: https://bcdixon23-spec.github.io/rsi-overlay-extension/

## Development

```
npm install
npm test          # run the unit test suite
npx tsc --noEmit   # type-check
npm run build      # bundle to dist/
```

Then load `dist/` as an unpacked extension via `chrome://extensions` (enable Developer mode first).

## Project structure

- `src/lib/` — pure logic: RSI calculation, price feed, storage helpers (unit tested)
- `src/background/` — service worker: polls price data, computes RSI, fires alerts
- `src/content/` — content script: renders the draggable overlay panel on TradingView
- `src/popup/` — settings popup
- `docs/` — GitHub Pages landing page, privacy policy
