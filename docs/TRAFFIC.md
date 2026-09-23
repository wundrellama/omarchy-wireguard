# Interface traffic

The connected panel and bar tooltip show download and upload rates in bytes per second, with binary units. They also show received and sent totals **since interface creation**. Opening the panel does not reset these totals. The bar remains shield-only. Inline bar rates are not implemented.

The first sample shows unknown rates (`—/s`). Interface recreation, a counter reset, or a sampling gap also clears the rate baseline. Real idle deltas show `0 B/s`. Disconnected or unknown status hides the traffic section. Failed or missing reads show unavailable values and clear the previous baseline. Counters do not prove protection.

## Data collection

`Service.qml` owns `TrafficService.qml`. The sampler runs once per second when the plugin is active and connected with a current profile ID.

The read-only `traffic.py` helper queries active NetworkManager (NM) NAME/UUID/TYPE/DEVICE fields. It requires the exact managed name `omarchy-wireguard-<currentProfile>` and one matching WireGuard interface. It reads the sysfs `ifindex`, `rx_bytes`, and `tx_bytes` values. It checks the mapping and interface index again before it returns JSON with a monotonic timestamp.

The helper does not read configurations, endpoints, or keys. It does not need elevated access or a backend change. Each NM query has a 0.7-second timeout. QML limits the child process to 2 seconds. A generation guard rejects late responses after status or profile changes. Data expires after 3 seconds without a fresh sample. The helper never selects another tunnel through a wildcard match.

## Tests

These tests do not install the plugin or change network settings:

```sh
python3 -B tests/plugin/test_traffic.py
node tests/plugin/traffic.test.js
node tests/plugin/traffic-service.test.js
python3 -B tests/plugin/traffic-offscreen.py
node tests/plugin/model.test.js
node tests/plugin/service.test.js
node tests/plugin/panel.test.js
python3 -B tests/plugin/picker-handoff.py
```

The offscreen probe runs the real QML Process and timers with a synthetic helper. It does not test live throughput or visual layout. Python tests use temporary sysfs fixtures. The preview supplies synthetic traffic. Older injected fixtures without `traffic` safely show unavailable values.

## Installation and visual checks

Deploy the **whole plugin directory**, including `Traffic.js`, `TrafficService.qml`, and `traffic.py`, with `Service.qml` and `BarWidget.qml`. Python 3 and `nmcli` are existing backend prerequisites. This feature does not need a privileged backend installation or restart.

Use the [non-networking preview](../tests/preview/README.md) for visual checks:

1. Open the preview panel.
2. Select the synthetic connected state.
3. Check the rates, totals, lifetime label, text wrapping, and tooltip.
4. Select the disabled and unknown states.
5. Check that the traffic section disappears.

Do not reconnect a real VPN only to test the layout. The traffic feature and the plugin identity migration are separate changes.
