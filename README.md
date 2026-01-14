# DNS Toggle (Windows 11)

A small Windows 11 GUI tool to quickly switch your DNS servers on a selected network adapter.

## What it does
- Shows your current DNS settings (IPv4)
- Lets you pick a network adapter from a dropdown
- Lets you switch DNS profiles with one click
- Includes a button to restore **Automatic DNS (DHCP)**
- Flushes DNS cache after changes (`ipconfig /flushdns`)
- Profiles can be added/edited/deleted from the GUI

## Default DNS Profiles
- **Cloudflare**: `1.1.1.1` / `1.0.0.1`
- **Custom**: `10.1.1.253` / `1.1.1.1`

## Requirements
- Windows 11
- Python 3.x (only needed if running the script)
- Administrator rights (required to change DNS)

## Run (Python)
```powershell
py dns_toggle_gui.pyw
