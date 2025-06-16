import subprocess
import re
import time
import requests
import argparse
import platform
import socket
from configset import configset
from pathlib import Path
import sys
from ctraceback import CTraceback
sys.excepthook = CTraceback()
import sendgrowl
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live
from rich import box
import threading
from datetime import datetime

console = Console()

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
                    console.print("🚨 [bold red]You must use 'write_config' to add new options.[/]")

    @staticmethod
    def get(section, option, default=None):
        """Get configuration value with a default fallback."""
        return CONFIG.CONFIGOBJ.get_config(section, option, default)
    
    @staticmethod
    def write(section, option, value):
        """Write configuration value."""
        CONFIG.CONFIGOBJ.write_config(section, option, value)

    @staticmethod
    def read(section=None, option=None):
        """Print all configuration from the config file."""
        if section:
            if option:
                value = CONFIG.CONFIGOBJ.get_config(section, option)
                table = Table(title=f"📋 Configuration: [{section}]", box=box.ROUNDED)
                table.add_column("Option", style="cyan")
                table.add_column("Value", style="green")
                table.add_row(option, str(value))
                console.print(table)
            else:
                table = Table(title=f"📋 Configuration: [{section}]", box=box.ROUNDED)
                table.add_column("Option", style="cyan")
                table.add_column("Value", style="green")
                for opt in CONFIG.CONFIGOBJ.options(section):
                    value = CONFIG.CONFIGOBJ.get_config(section, opt)
                    table.add_row(opt, str(value))
                console.print(table)
        else:
            for section in CONFIG.CONFIGOBJ.sections():
                table = Table(title=f"📋 Configuration: [{section}]", box=box.ROUNDED)
                table.add_column("Option", style="cyan")
                table.add_column("Value", style="green")
                for option in CONFIG.CONFIGOBJ.options(section):
                    value = CONFIG.CONFIGOBJ.get_config(section, option)
                    table.add_row(option, str(value))
                console.print(table)
                console.print()
                
    @staticmethod
    def get_config(section, option):
        return CONFIG.CONFIGOBJ.get_config(section, option)
        
    @staticmethod
    def write_config(section, option, value):
        CONFIG.CONFIGOBJ.write_config(section, option, value)

    @staticmethod
    def get_config_as_list(section, option):
        value = CONFIG.CONFIGOBJ.get_config_as_list(section, option)
        return value if value else []

# Load configuration with better error handling
try:
    WHITELIST_MAC = set(CONFIG.get_config_as_list('macmon', 'whitelist'))
    BLACKLIST_MAC = set(CONFIG.get_config_as_list('macmon', 'blacklist'))
    CHECK_INTERVAL = int(CONFIG.get_config('interval', 'seconds') or 30)
    NTFY_TOPIC = CONFIG.get_config('ntfy', 'topic') or "macmon"
    NTFY_URL = CONFIG.get_config_as_list('ntfy', 'url') or [f"https://ntfy.sh/{NTFY_TOPIC}"]
except Exception as e:
    console.print(f"⚠️ [bold yellow]Warning: Error loading config: {e}[/]")
    WHITELIST_MAC = set()
    BLACKLIST_MAC = set()
    CHECK_INTERVAL = 30
    NTFY_TOPIC = "macmon"
    NTFY_URL = ["https://ntfy.sh/macmon"]

# Global variables for monitoring state
monitoring_active = False
scan_count = 0
start_time = None

def get_mac_addresses():
    """Extract MAC addresses from ARP table."""
    try:
        system = platform.system().lower()
        if system == "windows":
            output = subprocess.check_output("arp -a", shell=True, text=True)
        else:
            output = subprocess.check_output("arp -a", shell=True, text=True)
    except subprocess.CalledProcessError as e:
        console.print(f"❌ [bold red]Error running ARP command: {e}[/]")
        return set()

    mac_regex = r"(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})"
    macs_list = [mac[0].lower().replace('-', ':') for mac in re.findall(mac_regex, output)]
    return set(macs_list)

def normalize_mac(mac):
    """Normalize MAC address format."""
    return mac.lower().replace('-', ':')

def get_device_info(ip):
    """Get device hostname if possible."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown Device"

def notify_growl(message, title="MAC Monitor"):
    """Send notifications using Growl."""
    try:
        sendgrowl.Growl().Publish(
            CONFIG.get_config('growl', 'name') or "MAC Monitor",
            CONFIG.get_config('growl', 'default') or "Unknown Device",
            title,
            message,
            sticky=True,
            priority=1,
        )
    except Exception as e:
        console.print(f"🚨 [bold red]Growl error: {e}[/]")

def notify_ntfy(message, title="MAC Monitor"):
    """Send notifications using ntfy.sh."""
    for url in NTFY_URL:
        if not url.startswith("https://ntfy.sh/"):
            console.print(f"⚠️ [bold yellow]Invalid ntfy URL: {url}[/]")
            continue
        try:
            headers = {'Title': title}
            requests.post(url, data=message.encode("utf-8"), headers=headers, timeout=5)
        except Exception as e:
            console.print(f"🚨 [bold red]Ntfy error for {url}: {e}[/]")

def create_status_table(current_macs, seen_macs, whitelist, blacklist):
    """Create a status table for monitoring."""
    table = Table(title="🖥️ Network Monitor Status", box=box.ROUNDED)
    table.add_column("Category", style="cyan", width=15)
    table.add_column("Count", style="green", width=8)
    table.add_column("Details", style="white")
    
    table.add_row("🌐 Current MACs", str(len(current_macs)), ", ".join(sorted(current_macs)[:5]) + ("..." if len(current_macs) > 5 else ""))
    table.add_row("👁️ Seen Unknown", str(len(seen_macs)), ", ".join(sorted(seen_macs)[:3]) + ("..." if len(seen_macs) > 3 else ""))
    table.add_row("✅ Whitelist", str(len(whitelist)), ", ".join(sorted(whitelist)[:3]) + ("..." if len(whitelist) > 3 else ""))
    table.add_row("❌ Blacklist", str(len(blacklist)), ", ".join(sorted(blacklist)[:3]) + ("..." if len(blacklist) > 3 else ""))
    
    return table

def update_mac_list(section, mac_list, mac_to_remove):
    """Safely update MAC address lists."""
    try:
        updated_list = [mac for mac in mac_list if mac != mac_to_remove]
        if updated_list != mac_list:
            CONFIG.write_config('macmon', section, " ".join(updated_list))
            return True
    except Exception as e:
        console.print(f"❌ [bold red]Error updating {section}: {e}[/]")
    return False

def monitor_network():
    """Enhanced network monitoring with better visualization."""
    global monitoring_active, scan_count, start_time
    
    monitoring_active = True
    scan_count = 0
    start_time = datetime.now()
    seen = set()
    
    # Display startup message
    console.print(Panel.fit(
        "[bold green]🚀 MAC Monitor Started[/]\n"
        f"⏱️  Scan interval: {CHECK_INTERVAL} seconds\n"
        f"📊 Whitelist: {len(WHITELIST_MAC)} devices\n"
        f"🚫 Blacklist: {len(BLACKLIST_MAC)} devices",
        title="Network Monitor",
        border_style="green"
    ))
    
    # Send startup notification
    startup_msg = f"🚀 MAC Monitor started - Interval: {CHECK_INTERVAL}s"
    notify_growl(startup_msg)
    notify_ntfy(startup_msg)
    
    try:
        while monitoring_active:
            scan_count += 1
            current_time = datetime.now()
            
            console.print(f"\n🔍 [bold cyan]Scan #{scan_count} - {current_time.strftime('%H:%M:%S')}[/]")
            
            # Get current MAC addresses
            current_macs = get_mac_addresses()
            current_whitelist = set(CONFIG.get_config_as_list('macmon', 'whitelist'))
            current_blacklist = set(CONFIG.get_config_as_list('macmon', 'blacklist'))
            current_detected = set(CONFIG.get_config_as_list('macmon', 'detected'))
            
            # Check for new unknown devices
            for mac in current_macs:
                if (mac not in current_whitelist and 
                    mac not in current_detected and 
                    mac not in seen):
                    
                    message = f"🆕 Unknown device detected: {mac}"
                    console.print(f"[bold yellow]{message}[/]")
                    notify_growl(message, "Unknown Device")
                    notify_ntfy(message, "Unknown Device")
                    seen.add(mac)
                    
                    # Add to detected list
                    updated_detected = list(current_detected) + [mac]
                    CONFIG.write_config('macmon', 'detected', " ".join(updated_detected))
            
            # Check for blacklisted devices
            for mac in current_macs:
                if mac in current_blacklist:
                    message = f"🚫 Blacklisted device active: {mac}"
                    console.print(f"[bold red]{message}[/]")
                    notify_growl(message, "Blacklisted Device")
                    notify_ntfy(message, "Blacklisted Device")
            
            # Check for devices that left the network
            all_tracked = current_whitelist | current_blacklist | current_detected | seen
            for mac in all_tracked.copy():
                if mac not in current_macs:
                    # Device left network
                    if mac in seen:
                        seen.remove(mac)
                        message = f"👋 Unknown device left: {mac}"
                        console.print(f"[bold blue]{message}[/]")
                        notify_growl(message, "Device Left")
                        notify_ntfy(message, "Device Left")
                    
                    # Remove from detected list
                    if mac in current_detected:
                        if update_mac_list('detected', list(current_detected), mac):
                            message = f"🗑️ Removed {mac} from detected list"
                            console.print(f"[dim]{message}[/]")
            
            # Display status table
            status_table = create_status_table(current_macs, seen, current_whitelist, current_blacklist)
            console.print(status_table)
            
            # Countdown with progress bar
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task(f"⏳ Next scan in {CHECK_INTERVAL}s", total=CHECK_INTERVAL)
                for i in range(CHECK_INTERVAL):
                    if not monitoring_active:
                        break
                    progress.update(task, advance=1, description=f"⏳ Next scan in {CHECK_INTERVAL - i - 1}s")
                    time.sleep(1)
                    
    except KeyboardInterrupt:
        monitoring_active = False
        console.print("\n🛑 [bold red]Monitoring stopped by user[/]")
    finally:
        runtime = datetime.now() - start_time if start_time else None
        console.print(Panel.fit(
            f"[bold green]📊 Monitoring Summary[/]\n"
            f"⏱️  Runtime: {runtime}\n"
            f"🔍 Total scans: {scan_count}\n"
            f"👁️  Unknown devices seen: {len(seen)}",
            title="Session Complete",
            border_style="blue"
        ))
        
        # Send shutdown notification
        shutdown_msg = f"🛑 MAC Monitor stopped - Runtime: {runtime}, Scans: {scan_count}"
        notify_growl(shutdown_msg)
        notify_ntfy(shutdown_msg)

def find_mac_or_ip(query):
    """Enhanced MAC/IP lookup with better formatting."""
    console.print(f"🔍 [bold cyan]Searching for: {query}[/]")
    
    system = platform.system().lower()
    arp_cmd = "arp -a"

    try:
        output = subprocess.check_output(arp_cmd, shell=True, text=True)
    except Exception as e:
        console.print(f"❌ [bold red]Failed to run ARP command: {e}[/]")
        return

    mac_regex = r"(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})"
    ip_regex = r"(\d{1,3}(?:\.\d{1,3}){3})"

    norm_query = normalize_mac(query)
    found = False
    results = []

    for line in output.splitlines():
        macs = re.findall(mac_regex, line)
        ips = re.findall(ip_regex, line)
        
        # Check MACs
        for mac_tuple in macs:
            mac = normalize_mac(mac_tuple[0])
            if norm_query == mac:
                found = True
                ip = ips[0] if ips else "Unknown"
                device_name = get_device_info(ip) if ip != "Unknown" else "Unknown"
                results.append({
                    'type': 'MAC',
                    'ip': ip,
                    'mac': mac,
                    'device': device_name,
                    'line': line.strip()
                })
        
        # Check IPs
        for ip in ips:
            if query == ip:
                found = True
                mac = normalize_mac(macs[0][0]) if macs else "Unknown"
                device_name = get_device_info(ip)
                results.append({
                    'type': 'IP',
                    'ip': ip,
                    'mac': mac,
                    'device': device_name,
                    'line': line.strip()
                })

    if found:
        for result in results:
            table = Table(title=f"🎯 Found {result['type']} Match", box=box.ROUNDED)
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("🌐 IP Address", result['ip'])
            table.add_row("🔗 MAC Address", result['mac'])
            table.add_row("📱 Device Name", result['device'])
            table.add_row("📋 ARP Entry", result['line'])
            
            # Check if in lists
            if result['mac'] in WHITELIST_MAC:
                table.add_row("✅ Status", "[green]Whitelisted[/]")
            elif result['mac'] in BLACKLIST_MAC:
                table.add_row("❌ Status", "[red]Blacklisted[/]")
            else:
                table.add_row("❓ Status", "[yellow]Unknown[/]")
            
            console.print(table)
    else:
        console.print(f"❌ [bold red]Not found: {query}[/]")

def detect_current_devices():
    """Detect and display current devices with enhanced formatting."""
    console.print("🔍 [bold cyan]Detecting current devices...[/]")
    
    macs = get_mac_addresses()
    if not macs:
        console.print("❌ [bold red]No MAC addresses detected[/]")
        return
    
    table = Table(title="🖥️ Current Network Devices", box=box.ROUNDED)
    table.add_column("#", style="dim", width=4)
    table.add_column("MAC Address", style="cyan")
    table.add_column("Status", style="white")
    
    for i, mac in enumerate(sorted(macs), 1):
        if mac in WHITELIST_MAC:
            status = "[green]✅ Whitelisted[/]"
        elif mac in BLACKLIST_MAC:
            status = "[red]❌ Blacklisted[/]"
        else:
            status = "[yellow]❓ Unknown[/]"
        
        table.add_row(str(i), mac, status)
    
    console.print(table)
    
    # Update detected list
    CONFIG.write_config('macmon', 'detected', " ".join(macs))
    console.print(f"✅ [bold green]Updated detected list with {len(macs)} devices[/]")

def add_to_list(mac, list_type):
    """Add MAC to whitelist or blacklist with validation."""
    mac = normalize_mac(mac)
    
    # Validate MAC format
    mac_pattern = r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$'
    if not re.match(mac_pattern, mac):
        console.print(f"❌ [bold red]Invalid MAC address format: {mac}[/]")
        return
    
    current_list = set(CONFIG.get_config_as_list('macmon', list_type))
    
    if mac in current_list:
        console.print(f"⚠️ [bold yellow]{mac} is already in {list_type}[/]")
        return
    
    updated_list = list(current_list) + [mac]
    CONFIG.write_config('macmon', list_type, " ".join(updated_list))
    
    icon = "✅" if list_type == "whitelist" else "❌"
    console.print(f"{icon} [bold green]Added {mac} to {list_type}[/]")
    
    message = f"{icon} Added {mac} to {list_type}"
    notify_growl(message)
    notify_ntfy(message)

def version():
    """Display version information with styling."""
    version_file = Path(__file__).parent / '__version__.py'
    if version_file.exists():
        import importlib.util
        spec = importlib.util.spec_from_file_location("__version__", str(version_file))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        
        console.print(Panel.fit(
            f"[bold green]MAC Monitor[/]\n"
            f"Version: {mod.version}\n"
            f"Platform: {platform.system()} {platform.release()}",
            title="🔢 Version Info",
            border_style="blue"
        ))
    else:
        console.print("❌ [bold red]Version information not found[/]")

def generate_config():
    """Generate configuration file with better feedback."""
    console.print("⚙️ [bold cyan]Generating configuration file...[/]")
    
    try:
        CONFIG.write_config('macmon', 'whitelist', "")
        CONFIG.write_config('macmon', 'blacklist', "")
        CONFIG.write_config('macmon', 'detected', " ".join(list(get_mac_addresses())))
        CONFIG.write_config('interval', 'seconds', str(CHECK_INTERVAL))
        CONFIG.write_config('ntfy', 'topic', NTFY_TOPIC)
        CONFIG.write_config('ntfy', 'url', "https://ntfy.sh/macmon")
        CONFIG.write_config('growl', 'name', "MAC Monitor")
        CONFIG.write_config('growl', 'event', "Unknown Device")
        CONFIG.write_config('growl', 'default', "Unknown Device")
        
        console.print("✅ [bold green]Configuration file generated successfully[/]")
        console.print(f"📁 [dim]Location: {CONFIG.CONFIGFILE}[/]")
    except Exception as e:
        console.print(f"❌ [bold red]Error generating config: {e}[/]")

def usage():
    """Enhanced argument parsing with better help."""
    parser = argparse.ArgumentParser(
        description="🖥️ MAC Monitor - Network Device Monitoring Utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Start monitoring
  %(prog)s -f aa:bb:cc:dd:ee:ff     # Find specific MAC
  %(prog)s -f 192.168.1.100         # Find specific IP
  %(prog)s -d                       # Detect current devices
  %(prog)s -a aa:bb:cc:dd:ee:ff     # Add to whitelist
  %(prog)s -b aa:bb:cc:dd:ee:ff     # Add to blacklist
        """
    )
    
    parser.add_argument('-f', '--find', metavar='MAC_OR_IP', 
                       help='🔍 Find MAC or IP address in network')
    parser.add_argument('-g', '--generate', action='store_true', 
                       help='⚙️ Generate configuration file with defaults')
    parser.add_argument('-d', '--detect', action='store_true', 
                       help='🔍 Detect current MAC addresses on network')
    parser.add_argument('-s', '--set', action='store_true', 
                       help='✅ Set detected devices as whitelist')
    parser.add_argument('-r', '--read', action='store_true', 
                       help='📋 Read and display configuration')
    parser.add_argument('-v', '--version', action='store_true', 
                       help='🔢 Show version information')
    parser.add_argument('-a', '--add', metavar='MAC', 
                       help='✅ Add MAC address to whitelist')
    parser.add_argument('-b', '--blacklist', metavar='MAC', 
                       help='❌ Add MAC address to blacklist')
    
    args = parser.parse_args()

    if args.find:
        find_mac_or_ip(args.find)
    elif args.version:
        version()
    elif args.read:
        console.print("📋 [bold cyan]Reading configuration...[/]")
        CONFIG.read()
    elif args.generate:
        generate_config()
    elif args.detect:
        detect_current_devices()
    elif args.set:
        console.print("✅ [bold cyan]Setting detected devices as whitelist...[/]")
        detected_macs = CONFIG.get_config_as_list('macmon', 'detected')
        if detected_macs:
            CONFIG.write_config('macmon', 'whitelist', " ".join(detected_macs))
            console.print(f"✅ [bold green]Whitelist updated with {len(detected_macs)} devices[/]")
        else:
            console.print("❌ [bold red]No detected devices found[/]")
    elif args.add:
        add_to_list(args.add, 'whitelist')
    elif args.blacklist:
        add_to_list(args.blacklist, 'blacklist')
    else:
        console.print(Panel.fit(
            "[bold green]🖥️ MAC Monitor[/]\n"
            "[dim]Use -h or --help for options[/]\n"
            "[dim]Starting network monitoring...[/]",
            title="Welcome",
            border_style="green"
        ))
        monitor_network()

# === MAIN ===
if __name__ == "__main__":
    try:
        usage()
    except KeyboardInterrupt:
        console.print("\n🛑 [bold red]Program interrupted by user[/]")
        sys.exit(0)
    except Exception as e:
        console.print(f"💥 [bold red]Unexpected error: {e}[/]")
        CTraceback(*sys.exc_info())
        sys.exit(1)