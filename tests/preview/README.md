# Safe panel preview

This development-only fixture renders the real `plugin/BarWidget.qml` in the existing Omarchy shell with an injected synthetic service. The real Service is inactive. Every fixture action records an action name; none launches a process, installs a backend, accesses credentials, or changes networking. The panel explicitly says **PREVIEW ONLY**.

To stage a preview, copy `plugin/` and this `tests/preview/` directory preserving their relative paths into a separate user plugin directory named `wundrellama.wireguard-preview`, with this directory's `manifest.json` copied to that staging root. Do not overwrite the production manifest or install the privileged backend. Back up `~/.config/omarchy/shell.json` before enabling the preview. Validate the staging root with `omarchy plugin validate`, rescan, and enable only this separate preview ID. Existing VPN widgets can remain enabled.

Use the normal shell IPC target `wundrellama.wireguard-preview` to open/close the panel. The separate `wundrellama.wireguard-preview-controls` target exposes `scenario`, `review`, `label`, `submit`, `search`, `activate` and `inspect` for deterministic visual tests. Scenarios include `disabled`, `connecting`, `connected`, `failed` and `unknown`; these are simulated display states, not observed VPN state. `inspect` returns the recorded action, review values, selection and model state. The fixture keeps installation disabled; actual installation action guards are tested with inert process objects.

After editing a staged plugin, verify a new IPC marker before accepting its rendering as current. This host can retain cached QML after rescan, including cached directory listings that reject a newly created filename with `File name case mismatch`. A fresh staging directory/manifest ID loaded the updated fixture without restarting the shell; remove the older preview first and use the new manifest ID for panel IPC (the fixture-controls target stays fixed).

Verify long labels, optional geography, filtered selection, import naming, failed/unknown status and layout. Capture and inspect the actual running panel. Preview screenshots and action recordings are UI evidence only, not network verification.

After testing, close and disable the preview, remove only its bar entry if the host retains disabled entries, and move the staging directory out of the plugin search path. Compare the normalized shell configuration with the backup to ensure other widgets/settings were preserved. Do not replace the current file wholesale if the user made concurrent changes.
