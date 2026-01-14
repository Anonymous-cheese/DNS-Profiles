# dns_toggle_gui.pyw
# Windows 11 DNS toggle GUI (IPv4 only) with:
# - Adapter dropdown (friendly names)
# - Profile dropdown (editable: add/edit/delete)
# - Apply selected profile, or set DHCP
# - Current DNS + status display
# - Self-elevation (UAC) for DNS changes
# - Profiles stored in dns_profiles.json next to this script
# - Error logging to dns_toggle.log

import ctypes
import json
import os
import re
import subprocess
import sys
import time
import tkinter as tk
from tkinter import ttk, messagebox

DEFAULT_ADAPTER = "Ethernet 2"
PROFILES_FILE = "dns_profiles.json"
LOG_FILE = "dns_toggle.log"

DEFAULT_PROFILES = [
    {"name": "Cloudflare", "primary": "1.1.1.1", "secondary": "1.0.0.1"},
    {"name": "Custom",     "primary": "10.1.1.253", "secondary": "1.1.1.1"},
]

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def app_dir() -> str:
    return os.path.dirname(os.path.abspath(sys.argv[0]))


def log_line(msg: str):
    try:
        path = os.path.join(app_dir(), LOG_FILE)
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    try:
        # Ensure we pass the script path and any args exactly
        exe = sys.executable
        params = " ".join([f'"{a}"' for a in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        sys.exit(0)
    except Exception as e:
        log_line(f"Failed to elevate: {e}")
        messagebox.showerror("Elevation Failed", f"Unable to request admin privileges.\n\n{e}")
        sys.exit(1)


def run_cmd(args, timeout=20):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, shell=False)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except subprocess.TimeoutExpired:
        return 124, "", "Command timed out"
    except Exception as e:
        return 1, "", str(e)


def run_powershell(ps_script: str, timeout=20):
    return run_cmd(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
        timeout=timeout
    )


def list_adapters():
    ps = r"""
    $a = Get-NetAdapter | Select-Object Name, Status, LinkSpeed | ConvertTo-Json -Depth 3
    $a
    """
    rc, out, err = run_powershell(ps, timeout=25)
    if rc != 0 or not out:
        return [], f"Failed to list adapters.\n{err or out}"

    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        adapters = [(x.get("Name", ""), x.get("Status", ""), str(x.get("LinkSpeed", "")))
                    for x in data if x.get("Name")]
        adapters.sort(key=lambda t: t[0].lower())
        return adapters, ""
    except Exception as e:
        return [], f"Failed to parse adapter list.\n{e}"


def netsh_show_dns(adapter_name: str):
    rc, out, err = run_cmd(["netsh", "interface", "ip", "show", "dnsservers", f'name={adapter_name}'])
    raw = out if out else err
    if rc != 0:
        return "Unknown", [], raw

    low = out.lower()
    if "configured through dhcp" in low:
        mode = "DHCP"
    elif "statically configured" in low or "static" in low:
        mode = "Static"
    else:
        mode = "Unknown"

    servers = []
    for line in out.splitlines():
        for token in line.replace(",", " ").split():
            if is_valid_ipv4(token) and token not in servers:
                servers.append(token)

    return mode, servers, out


def flush_dns():
    run_cmd(["ipconfig", "/flushdns"], timeout=20)


def set_dns_static(adapter_name: str, primary: str, secondary: str):
    rc1, out1, err1 = run_cmd(["netsh", "interface", "ip", "set", "dns", f'name={adapter_name}', "static", primary, "primary"])
    if rc1 != 0:
        return False, f"Failed setting primary DNS.\n{err1 or out1}"

    rc2, out2, err2 = run_cmd(["netsh", "interface", "ip", "add", "dns", f'name={adapter_name}', secondary, "index=2"])
    if rc2 != 0:
        return False, f"Primary set, but failed adding secondary DNS.\n{err2 or out2}"

    flush_dns()
    return True, "DNS updated and cache flushed."


def set_dns_dhcp(adapter_name: str):
    rc, out, err = run_cmd(["netsh", "interface", "ip", "set", "dns", f'name={adapter_name}', "dhcp"])
    if rc != 0:
        return False, f"Failed setting DNS to DHCP.\n{err or out}"

    flush_dns()
    return True, "DNS set to DHCP and cache flushed."


def is_valid_ipv4(s: str) -> bool:
    if not IPV4_RE.match(s or ""):
        return False
    parts = s.split(".")
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def load_profiles():
    path = os.path.join(app_dir(), PROFILES_FILE)
    if not os.path.exists(path):
        save_profiles(DEFAULT_PROFILES)
        return list(DEFAULT_PROFILES)

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Basic validation
        cleaned = []
        for p in data if isinstance(data, list) else []:
            name = str(p.get("name", "")).strip()
            primary = str(p.get("primary", "")).strip()
            secondary = str(p.get("secondary", "")).strip()
            if name and is_valid_ipv4(primary) and is_valid_ipv4(secondary):
                cleaned.append({"name": name, "primary": primary, "secondary": secondary})
        if not cleaned:
            cleaned = list(DEFAULT_PROFILES)
            save_profiles(cleaned)
        return cleaned
    except Exception as e:
        log_line(f"Failed to load profiles: {e}")
        save_profiles(DEFAULT_PROFILES)
        return list(DEFAULT_PROFILES)


def save_profiles(profiles):
    path = os.path.join(app_dir(), PROFILES_FILE)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(profiles, f, indent=2)


def classify_current(mode: str, servers: list[str], profiles):
    """
    Returns (status_line, match_name_or_None).
    """
    if mode == "DHCP":
        return "Mode: Automatic (DHCP)", None

    if mode == "Static":
        for p in profiles:
            if servers == [p["primary"], p["secondary"]]:
                return f"Mode: Static (matches profile: {p['name']})", p["name"]
        return "Mode: Static (no matching saved profile)", None

    return "Mode: Unknown", None


class ProfileDialog(tk.Toplevel):
    def __init__(self, parent, title, initial=None):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.result = None

        self.var_name = tk.StringVar(value=(initial["name"] if initial else ""))
        self.var_primary = tk.StringVar(value=(initial["primary"] if initial else ""))
        self.var_secondary = tk.StringVar(value=(initial["secondary"] if initial else ""))

        frm = ttk.Frame(self, padding=12)
        frm.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frm, text="Name:").grid(row=0, column=0, sticky="w", pady=(0, 6))
        ttk.Entry(frm, textvariable=self.var_name, width=34).grid(row=0, column=1, sticky="w", pady=(0, 6))

        ttk.Label(frm, text="Primary DNS:").grid(row=1, column=0, sticky="w", pady=6)
        ttk.Entry(frm, textvariable=self.var_primary, width=34).grid(row=1, column=1, sticky="w", pady=6)

        ttk.Label(frm, text="Secondary DNS:").grid(row=2, column=0, sticky="w", pady=6)
        ttk.Entry(frm, textvariable=self.var_secondary, width=34).grid(row=2, column=1, sticky="w", pady=6)

        btns = ttk.Frame(frm)
        btns.grid(row=3, column=0, columnspan=2, sticky="e", pady=(10, 0))

        ttk.Button(btns, text="Cancel", command=self._cancel).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(btns, text="Save", command=self._save).grid(row=0, column=1)

        self.bind("<Return>", lambda _e: self._save())
        self.bind("<Escape>", lambda _e: self._cancel())

        self.transient(parent)
        self.grab_set()
        self._center(parent)

    def _center(self, parent):
        self.update_idletasks()
        px = parent.winfo_rootx()
        py = parent.winfo_rooty()
        pw = parent.winfo_width()
        ph = parent.winfo_height()
        w = self.winfo_width()
        h = self.winfo_height()
        x = px + (pw - w) // 2
        y = py + (ph - h) // 2
        self.geometry(f"+{x}+{y}")

    def _cancel(self):
        self.result = None
        self.destroy()

    def _save(self):
        name = self.var_name.get().strip()
        primary = self.var_primary.get().strip()
        secondary = self.var_secondary.get().strip()

        if not name:
            messagebox.showerror("Validation", "Profile name is required.")
            return
        if not is_valid_ipv4(primary):
            messagebox.showerror("Validation", "Primary DNS must be a valid IPv4 address.")
            return
        if not is_valid_ipv4(secondary):
            messagebox.showerror("Validation", "Secondary DNS must be a valid IPv4 address.")
            return

        self.result = {"name": name, "primary": primary, "secondary": secondary}
        self.destroy()


class DnsToggleApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DNS Toggle (Windows 11)")
        self.geometry("720x420")
        self.minsize(720, 420)

        self.adapters = []
        self.profiles = load_profiles()

        self.selected_adapter = tk.StringVar(value=DEFAULT_ADAPTER)
        self.selected_profile = tk.StringVar(value=self.profiles[0]["name"] if self.profiles else "")
        self.current_dns = tk.StringVar(value="")
        self.current_status = tk.StringVar(value="")
        self.last_action = tk.StringVar(value="Ready.")

        self._build_ui()
        self._load_adapters()
        self._load_profiles_into_combo()
        self.refresh_status()

    def _build_ui(self):
        pad = {"padx": 12, "pady": 8}

        top = ttk.Frame(self)
        top.pack(fill="x", **pad)

        ttk.Label(top, text="Adapter:").pack(side="left")
        self.adapter_combo = ttk.Combobox(top, textvariable=self.selected_adapter, state="readonly", width=28)
        self.adapter_combo.pack(side="left", padx=(8, 18))
        self.adapter_combo.bind("<<ComboboxSelected>>", lambda _e: self.refresh_status())

        ttk.Button(top, text="Refresh", command=self.refresh_status).pack(side="left")

        prof = ttk.Frame(self)
        prof.pack(fill="x", **pad)

        ttk.Label(prof, text="DNS Profile:").pack(side="left")
        self.profile_combo = ttk.Combobox(prof, textvariable=self.selected_profile, state="readonly", width=28)
        self.profile_combo.pack(side="left", padx=(8, 10))

        ttk.Button(prof, text="Apply", command=self.apply_selected_profile).pack(side="left", padx=(0, 10))
        ttk.Button(prof, text="Set DHCP", command=self.apply_dhcp).pack(side="left")

        manage = ttk.Frame(self)
        manage.pack(fill="x", **pad)

        ttk.Button(manage, text="Add Profile", command=self.add_profile).pack(side="left", padx=(0, 10))
        ttk.Button(manage, text="Edit Profile", command=self.edit_profile).pack(side="left", padx=(0, 10))
        ttk.Button(manage, text="Delete Profile", command=self.delete_profile).pack(side="left")

        mid = ttk.Labelframe(self, text="Current Settings (IPv4)")
        mid.pack(fill="both", expand=True, **pad)

        ttk.Label(mid, text="DNS Servers:").grid(row=0, column=0, sticky="w", padx=10, pady=(12, 6))
        ttk.Label(mid, textvariable=self.current_dns).grid(row=0, column=1, sticky="w", padx=10, pady=(12, 6))

        ttk.Label(mid, text="Status:").grid(row=1, column=0, sticky="w", padx=10, pady=6)
        ttk.Label(mid, textvariable=self.current_status).grid(row=1, column=1, sticky="w", padx=10, pady=6)

        ttk.Label(mid, text="Last action:").grid(row=2, column=0, sticky="w", padx=10, pady=6)
        ttk.Label(mid, textvariable=self.last_action).grid(row=2, column=1, sticky="w", padx=10, pady=6)

        mid.grid_columnconfigure(1, weight=1)

    def _load_adapters(self):
        adapters, err = list_adapters()
        if err:
            messagebox.showerror("Error", err)
            return
        self.adapters = adapters
        names = [a[0] for a in adapters]
        self.adapter_combo["values"] = names

        if DEFAULT_ADAPTER in names:
            self.selected_adapter.set(DEFAULT_ADAPTER)
        else:
            up = [a[0] for a in adapters if a[1].lower() == "up"]
            self.selected_adapter.set(up[0] if up else (names[0] if names else ""))

    def _load_profiles_into_combo(self):
        names = [p["name"] for p in self.profiles]
        self.profile_combo["values"] = names

        # Preserve selection if possible
        current = self.selected_profile.get().strip()
        if current in names:
            self.selected_profile.set(current)
        else:
            self.selected_profile.set(names[0] if names else "")

    def get_adapter(self):
        name = self.selected_adapter.get().strip()
        return name if name else None

    def get_profile(self):
        name = self.selected_profile.get().strip()
        for p in self.profiles:
            if p["name"] == name:
                return p
        return None

    def refresh_status(self):
        adapter = self.get_adapter()
        if not adapter:
            self.current_dns.set("No adapter selected.")
            self.current_status.set("")
            return

        mode, servers, raw = netsh_show_dns(adapter)
        if mode == "Unknown" and not servers:
            self.current_dns.set("Unavailable")
            self.current_status.set("Unable to read DNS settings.")
            self.last_action.set((raw[:180] + "...") if raw and len(raw) > 180 else (raw or "Unknown error."))
            return

        self.current_dns.set(", ".join(servers) if servers else "(none shown)")
        status_line, match = classify_current(mode, servers, self.profiles)
        self.current_status.set(status_line)

        # If it matches a profile, update dropdown selection (helpful feedback)
        if match:
            self.selected_profile.set(match)

    def ensure_admin_or_prompt(self):
        if not is_admin():
            relaunch_as_admin()

    def apply_selected_profile(self):
        self.ensure_admin_or_prompt()
        adapter = self.get_adapter()
        prof = self.get_profile()
        if not adapter or not prof:
            return

        ok, msg = set_dns_static(adapter, prof["primary"], prof["secondary"])
        if ok:
            self.last_action.set(f"{adapter}: Applied profile '{prof['name']}'. {msg}")
            self.refresh_status()
        else:
            messagebox.showerror("Error", msg)
            self.last_action.set(f"{adapter}: Failed applying profile '{prof['name']}'.")

    def apply_dhcp(self):
        self.ensure_admin_or_prompt()
        adapter = self.get_adapter()
        if not adapter:
            return

        ok, msg = set_dns_dhcp(adapter)
        if ok:
            self.last_action.set(f"{adapter}: Set to Automatic (DHCP). {msg}")
            self.refresh_status()
        else:
            messagebox.showerror("Error", msg)
            self.last_action.set(f"{adapter}: Failed setting DHCP.")

    def add_profile(self):
        dlg = ProfileDialog(self, "Add DNS Profile")
        self.wait_window(dlg)
        if not dlg.result:
            return

        # Prevent duplicate names
        if any(p["name"].lower() == dlg.result["name"].lower() for p in self.profiles):
            messagebox.showerror("Validation", "A profile with that name already exists.")
            return

        self.profiles.append(dlg.result)
        self.profiles.sort(key=lambda p: p["name"].lower())
        save_profiles(self.profiles)
        self._load_profiles_into_combo()
        self.selected_profile.set(dlg.result["name"])
        self.last_action.set(f"Added profile '{dlg.result['name']}'.")

    def edit_profile(self):
        prof = self.get_profile()
        if not prof:
            return

        dlg = ProfileDialog(self, "Edit DNS Profile", initial=prof)
        self.wait_window(dlg)
        if not dlg.result:
            return

        # If name changed, ensure no conflict
        new_name = dlg.result["name"]
        if new_name.lower() != prof["name"].lower():
            if any(p["name"].lower() == new_name.lower() for p in self.profiles):
                messagebox.showerror("Validation", "A profile with that name already exists.")
                return

        prof.update(dlg.result)
        self.profiles.sort(key=lambda p: p["name"].lower())
        save_profiles(self.profiles)
        self._load_profiles_into_combo()
        self.selected_profile.set(new_name)
        self.last_action.set(f"Updated profile '{new_name}'.")

    def delete_profile(self):
        prof = self.get_profile()
        if not prof:
            return

        if not messagebox.askyesno("Confirm Delete", f"Delete profile '{prof['name']}'?"):
            return

        self.profiles = [p for p in self.profiles if p["name"] != prof["name"]]
        if not self.profiles:
            # Keep at least one sensible default
            self.profiles = list(DEFAULT_PROFILES)

        save_profiles(self.profiles)
        self._load_profiles_into_combo()
        self.last_action.set(f"Deleted profile '{prof['name']}'.")
        self.refresh_status()


def main():
    try:
        app = DnsToggleApp()
        app.mainloop()
    except Exception as e:
        log_line(f"Fatal error: {e}")
        # If GUI cannot load, fall back to a simple message
        try:
            messagebox.showerror("Fatal Error", f"The application encountered an error.\n\n{e}\n\nSee dns_toggle.log for details.")
        except Exception:
            pass


if __name__ == "__main__":
    main()
