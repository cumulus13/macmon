import subprocess
import re
import time
import requests
import argparse
import platform
import socket
# from gntp.notifier import GrowlNotifier  
from configset import configset
from pathlib import Path
import sys
from ctraceback import CTraceback
sys.excepthook = CTraceback()
# from gntplib import Publisher
import sendgrowl
from rich.console import Console
console = Console()

# WHITELIST_MAC = {
#     "00:11:22:33:44:55",
#     "aa:bb:cc:dd:ee:ff",
#     "b8:27:eb:12:34:56"
# }

class _ConfigMeta(type):
    def __getattr__(cls, section):
        return CONFIG.Section(section)

class CONFIG(metaclass=_ConfigMeta):
    CONFIGFILE = str(Path(__file__).parent / 'macmon.ini')
    CONFIGOBJ = configset(CONFIGFILE)

    class Section:
        def __init__(self, section):
            self._section = section

        def __getattr__(self, option):
            return CONFIG.CONFIGOBJ.get_config(self._section, option)

        def __setattr__(self, option, value):
            if option == "_section":
                super().__setattr__(option, value)
            else:
                if option in CONFIG.CONFIGOBJ.options(self._section):
                    CONFIG.CONFIGOBJ.write_config(self._section, option, value)
                else:
                    console.print("[white on blue]You must use 'write_config' to add new options.[/]")

    @staticmethod
    def get(section, option, default=None):
        """Get configuration value with a default fallback."""
        return CONFIG.CONFIGOBJ.get_config(section, option, default)
    
    @staticmethod
    def write(section, option, value):
        """Write configuration value."""
        CONFIG.CONFIGOBJ.write_config(section, option, value)

    @staticmethod
    def read(section = None, option = None):
        """Print all configuration from the config file."""
        if section:
            if option:
                value = CONFIG.CONFIGOBJ.get_config(section, option)
                print(f"[{section}]")
                print(f"  {option} = {value}")
            else:
                print(f"[{section}]")
                for opt in CONFIG.CONFIGOBJ.options(section):
                    value = CONFIG.CONFIGOBJ.get_config(section, opt)
                    print(f"  {opt} = {value}")
        else:
            for section in CONFIG.CONFIGOBJ.sections():
                print(f"[{section}]")
                for option in CONFIG.CONFIGOBJ.options(section):
                    value = CONFIG.CONFIGOBJ.get_config(section, option)
                    print(f"  {option} = {value}")
                print()
                
    @staticmethod
    def get_config(section, option):
        return CONFIG.CONFIGOBJ.get_config(section, option)
        
    @staticmethod
    def write_config(section, option, value):
        CONFIG.CONFIGOBJ.write_config(section, option, value)

    @staticmethod
    def get_config_as_list(section, option):
        value = CONFIG.CONFIGOBJ.get_config_as_list(section, option)
        if value:
            return value
        return []
    
WHITELIST_MAC = set(CONFIG.get_config_as_list('macmon', 'whitelist'))
BLACKLIST_MAC = set(CONFIG.get_config_as_list('macmon', 'blacklist'))

CHECK_INTERVAL = CONFIG.get_config('interval', 'seconds') or 30  # second
NTFY_TOPIC = CONFIG.get_config('ntfy', 'topic') or "macmon"
NTFY_URL = CONFIG.get_config_as_list('ntfy', 'url') or [f"https://ntfy.sh/{NTFY_TOPIC}"]

# growl = GrowlNotifier(
#     applicationName=CONFIG.get_config('growl', 'name') or "MAC Monitor",
#     notifications=[i.strip() for i in CONFIG.get_config('growl', 'event').split(",")] if CONFIG.get_config('growl', 'event') else ["Unknown Device"],
#     defaultNotifications=CONFIG.get_config('growl', 'default') or "Unknown Device"
# )

# growl = Publisher(
#     CONFIG.get_config('growl', 'name') or "MAC Monitor",
#     [i.strip() for i in CONFIG.get_config('growl', 'event').split(",")] if CONFIG.get_config('growl', 'event') else ["Unknown Device"]
# )

# try:
#     growl.register()
# except Exception as e:
#     print(f"[!] Growl registration error: {e}")
#     CTraceback(*sys.exc_info())


def get_mac_addresses():
    """Take the Mac Address from the 'ARP -A' output."""
    try:
        output = subprocess.check_output("arp -a", shell=True, text=True)
    except subprocess.CalledProcessError:
        return set()

    mac_regex = r"(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})"
    # macs = set(re.findall(mac_regex, output))
    # return {mac.lower() for mac in macs}
    macs_list = [mac[0].lower() for mac in re.findall(mac_regex, output)]
    macs = set(macs_list)
    return macs

def notify_growl(message):
    """Send notifications using Growl."""
    # print("[START] Send notifications using Growl.")
    try:
        # growl.notify(
        #     noteType="Unknown Device",
        #     title="Unknown device",
        #     description=message,
        #     sticky=True,
        #     priority=1,
        # )
        # growl.publish(
        #     CONFIG.get_config('growl', 'default') or "Unknown Device",
        #     CONFIG.get_config('growl', 'name') or "MAC Monitor",
        #     message,
        #     sticky=True,
        #     priority=1,
        # )
        sendgrowl.Growl().Publish(
            CONFIG.get_config('growl', 'name') or "MAC Monitor",
            CONFIG.get_config('growl', 'default') or "Unknown Device",
            CONFIG.get_config('growl', 'name') or "MAC Monitor",
            message,
            sticky=True,
            priority=1,
        )
        # print("[END] Send notifications using Growl.")
    except Exception as e:
        print(f"[!] Growl error: {e}")
        CTraceback(*sys.exc_info())

def notify_ntfy(message):
    """Send notifications using ntfy.sh."""
    # print("[START] Send notifications using ntfy.sh.")
    for url in NTFY_URL:
        if not url.startswith("https://ntfy.sh/"):
            print(f"[!] Invalid ntfy URL: {url}")
            continue
        # URL = url.rstrip('/') + '/' + NTFY_TOPIC.lstrip('/')
        # print(f"URL: {url}")
        try:
            requests.post(url, data=message.encode("utf-8"))
        except Exception as e:
            print(rf"[white on red]\[!][/] [black on #FFFFF00]Ntfy error:[/] [white on blue]{e}[/]")
    # print("[END] Send notifications using ntfy.sh.")
    
def monitor_network():
    seen = set()
    # if not WHITELIST_MAC:
    #     print("[!] No MAC addresses in whitelist. All unknown devices will be reported.")
    #     return
    # else:
    message = "[*] Starting Network Monitoring (Ctrl+C for Exit)..."
    print(f"{message}\n")
    notify_growl(message)
    notify_ntfy(message)
    print(f"[*] Whitelist MAC addresses: {', '.join(WHITELIST_MAC)}")
    while True:
        macs = get_mac_addresses()
        for mac in macs:
            if mac not in set(CONFIG.get_config_as_list('macmon', 'whitelist')) and mac not in set(CONFIG.get_config_as_list('macmon', 'detected')) and mac not in seen:
                message = f"Mac Address Unknown Detected: {mac}"
                print(f"[!] {message}")
                notify_growl(message)
                notify_ntfy(message)
                seen.add(mac)
            elif mac in set(CONFIG.get_config_as_list('macmon', 'blacklist')):
                message = f"Mac Address in Blacklist Detected: {mac}"
                print(f"[!] {message}")
                notify_growl(message)
                notify_ntfy(message)
                # seen.add(mac)
        # Cek apakah ada MAC yang sudah tidak terlihat lagi
        for mac in seen.copy():
            if mac not in macs:
                seen.remove(mac)
                message = f"Mac Address {mac} is no longer detected."
                print(f"[+] {message}")
                notify_growl(message)
                notify_ntfy(message)
        # Cek apakah ada MAC yang sudah tidak terlihat lagi di whitelist
        for mac in set(WHITELIST_MAC).copy():
            if mac not in macs:
                message = f"Mac Address {mac} is no longer in the network."
                print(f"[+] {message}")
                notify_growl(message)
                notify_ntfy(message)
                # Jika ada MAC yang sudah tidak terlihat lagi di whitelist, hapus dari whitelist
                next_whitelist = CONFIG.get_config_as_list('macmon', 'whitelist').copy().remove(mac)
                CONFIG.CONFIGOBJ.write_config('macmon', 'whitelist', next_whitelist)
                message = f"Removed {mac} from whitelist."
                print(f"[-] {message}")
                notify_growl(message)
                notify_ntfy(message)
        # Cek apakah ada MAC yang sudah tidak terlihat lagi di blacklist
        for mac in set(BLACKLIST_MAC).copy():
            if mac not in macs:
                message = f"Mac Address {mac} is no longer in the network."
                print(f"[+] {message}")
                notify_growl(message)
                notify_ntfy(message)
                # Jika ada MAC yang sudah tidak terlihat lagi di blacklist, hapus dari blacklist
                next_blacklist = CONFIG.get_config_as_list('macmon', 'blacklist').copy().remove(mac)
                CONFIG.CONFIGOBJ.write_config('macmon', 'blacklist', next_blacklist)
                message = f"Removed {mac} from blacklist."
                print(f"[-] {message}")
                notify_growl(message)
                notify_ntfy(message)
        # Cek apakah ada MAC yang sudah tidak terlihat lagi di detected
        for mac in set(CONFIG.get_config_as_list('macmon', 'detected')).copy():
            if mac not in macs:
                message = f"Mac Address {mac} is no longer in the network."
                print(f"[+] {message}")
                notify_growl(message)
                notify_ntfy(message)
                # Jika ada MAC yang sudah tidak terlihat lagi di detected, hapus dari detected
                try:
                    next_detected = CONFIG.get_config_as_list('macmon', 'detected').copy().remove(mac)
                    CONFIG.CONFIGOBJ.write_config('macmon', 'detected', next_detected)
                except Exception as e:
                    print(f"[!] Error removing {mac} from detected: {e}")
                    CTraceback(*sys.exc_info())
                message = f"Removed {mac} from detected."
                print(f"[-] {message}")
                notify_growl(message)
                notify_ntfy(message)
        
        # Down counter sebelum sleep
        interval = int(CONFIG.get_config('interval', 'seconds') or CHECK_INTERVAL or 30)
        for i in range(interval, 0, -1):
            print(f"[*] Next scan in {interval} seconds: {i} ", end="\r", flush=True)
            time.sleep(1)
        print(" " * 50, end="\r")  # Bersihkan baris setelah selesai

def find_mac_or_ip(query):
    """
    Look for a Mac Address or IP Address on the network and display the details.
    """
    system = platform.system().lower()
    if system == "windows":
        arp_cmd = "arp -a"
    else:
        arp_cmd = "arp -a"

    try:
        output = subprocess.check_output(arp_cmd, shell=True, text=True)
    except Exception as e:
        message = f"Failed to run '{arp_cmd}': {e}"
        print(f"[-] {message}")
        notify_growl(message)
        notify_ntfy(message)
        return

    mac_regex = r"(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})"
    ip_regex = r"(\d{1,3}(?:\.\d{1,3}){3})"

    # Normalisasi query (lowercase, ganti - ke :)
    norm_query = query.lower().replace('-', ':')
    found = False
    for line in output.splitlines():
        macs = re.findall(mac_regex, line)
        ips = re.findall(ip_regex, line)
        # Cek semua MAC di baris ini
        for mac_tuple in macs:
            mac = mac_tuple[0].lower().replace('-', ':')
            if norm_query == mac:
                found = True
                ip = ips[0] if ips else "(unknown)"
                device_name = ""
                try:
                    if ip != "(unknown)":
                        device_name = socket.gethostbyaddr(ip)[0]
                    else:
                        device_name = "(unknown)"
                except Exception:
                    device_name = "(unknown)"
                print(f"Details found:")
                print(f"  IP Address : {ip}")
                print(f"  MAC Address: {mac}")
                print(f"  Device Name: {device_name}")
                print(f"  ARP line   : {line.strip()}")
                print("-" * 40)
        # Cek semua IP di baris ini
        for ip in ips:
            if query == ip:
                found = True
                mac = macs[0][0].lower().replace('-', ':') if macs else "(unknown)"
                device_name = ""
                try:
                    device_name = socket.gethostbyaddr(ip)[0]
                except Exception:
                    device_name = "(unknown)"
                print(f"Details found:")
                print(f"  IP Address : {ip}")
                print(f"  MAC Address: {mac}")
                print(f"  Device Name: {device_name}")
                print(f"  ARP line   : {line.strip()}")
                print("-" * 40)
    if not found:
        print(f"[!] Not found: {query}")

def version():
    version_file = Path(__file__).parent / '__version__.py'
    if version_file.exists():
        import importlib.util
        spec = importlib.util.spec_from_file_location("__version__", str(version_file))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        print(f"MAC Monitor Version: {mod.version}")
    else:
        print("No version info found.")

def usage():
    parser = argparse.ArgumentParser(
        description="MAC Monitor Utility",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-f', '--find', metavar='MAC_OR_IP', help='Find Mac Address or IP Address on the Network')
    parser.add_argument('-g', '--generate', action='store_true', help='Generate a new configuration file with default values')
    parser.add_argument('-d', '--detect', action='store_true', help='Detect current MAC addresses on the network')
    parser.add_argument('-s', '--set', action='store_true', help='Set detected as whitelist')
    parser.add_argument('-r', '--read', action='store_true', help='Read and print the configuration file')
    parser.add_argument('-v', '--version', action='store_true', help='Show version information')
    parser.add_argument('-a', '--add', action='store', help = 'Add mac to whitelist')
    parser.add_argument('-b', '--blacklist', action = 'store', help = 'Add mac to blacklist')
    
    args = parser.parse_args()

    if args.find:
        find_mac_or_ip(args.find)
    elif args.version:
        version()
    elif args.read:
        print("[*] Reading configuration file...")
        CONFIG.read()
    elif args.generate:
        print("[*] Generating new configuration file with default values...")
        CONFIG.write_config('macmon', 'whitelist', "")
        CONFIG.write_config('macmon', 'blacklist', "")
        CONFIG.write_config('macmon', 'detected', " ".join(list(get_mac_addresses())))
        CONFIG.write_config('interval', 'seconds', str(CHECK_INTERVAL))
        CONFIG.write_config('ntfy', 'topic', NTFY_TOPIC)
        CONFIG.write_config('ntfy', 'url', "https://ntfy.sh/macmon")
        CONFIG.write_config('growl', 'name', "MAC Monitor")
        CONFIG.write_config('growl', 'event', "Unknown Device")
        CONFIG.write_config('growl', 'default', "Unknown Device")
        print("[+] Configuration file generated successfully.")
    elif args.detect:
        print("[*] Detecting current MAC addresses on the network...")
        macs = get_mac_addresses()
        if macs:
            print(f"Detected MAC addresses: {', '.join(macs)}")
            CONFIG.write_config('macmon', 'detected', " ".join(macs))
        else:
            message = "No MAC addresses detected."
            print(f"[!] {message}")
            notify_growl(message)
            notify_ntfy(message)
    elif args.set:
        print("[*] Setting detected MAC addresses as whitelist...")
        detected_macs = CONFIG.get_config_as_list('macmon', 'detected')
        if detected_macs:
            CONFIG.write_config('macmon', 'whitelist', " ".join(detected_macs))
            print(f"[+] Whitelist updated with detected MAC addresses: {', '.join(detected_macs)}")
        else:
            print("[!] No detected MAC addresses found to set as whitelist.")
    elif args.add:
        if args.add:
            mac_to_add = args.add.lower().replace(':', '-')
            if mac_to_add not in WHITELIST_MAC:
                CONFIG.write_config('macmon', 'whitelist', " ".join(list(WHITELIST_MAC) + [mac_to_add]))
                print(f"[+] Added {mac_to_add} to whitelist.")
                notify_growl(f"Added {mac_to_add} to whitelist.")
                notify_ntfy(f"Added {mac_to_add} to whitelist.")
            else:
                print(f"[!] {mac_to_add} is already in the whitelist.")
        else:
            print("[!] No MAC address provided to add to whitelist.")
    elif args.blacklist:
        if args.blacklist:
            mac_to_blacklist = args.blacklist.lower().replace(':', '-')
            if mac_to_blacklist not in BLACKLIST_MAC:
                CONFIG.write_config('macmon', 'blacklist', " ".join(list(BLACKLIST_MAC) + [mac_to_blacklist]))
                print(f"[+] Added {mac_to_blacklist} to blacklist.")
                notify_growl(f"Added {mac_to_blacklist} to blacklist.")
                notify_ntfy(f"Added {mac_to_blacklist} to blacklist.")
            else:
                print(f"[!] {mac_to_blacklist} is already in the blacklist.")
        else:
            print("[!] No MAC address provided to add to blacklist.")
    else:
        print('use -h or --help for more options.\n')
        monitor_network()

# === MAIN ===
if __name__ == "__main__":
    try:
        usage()
    except KeyboardInterrupt:
        print("\n[+] Monitoring is stopped.")
