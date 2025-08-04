import random
import ipaddress
from colorama import Fore, Style, init

init(autoreset=True)

def get_user_ips():
    raw_input = input(Fore.YELLOW + "Enter IPs to compare against (separated by space or comma):\n> ")
    ip_strings = [ip.strip() for ip in raw_input.replace(",", " ").split()]
    valid_ips = set()

    for ip in ip_strings:
        try:
            valid_ips.add(str(ipaddress.ip_address(ip)))
        except ValueError:
            print(Fore.RED + f"Invalid IP skipped: {ip}")
    return valid_ips

def get_user_config():
    while True:
        try:
            count = int(input(Fore.YELLOW + "How many IP addresses do you want to generate?\n> "))
            if count > 0:
                break
        except ValueError:
            print(Fore.RED + "Enter a valid number.")
    
    while True:
        version = input(Fore.YELLOW + "Generate IPv4, IPv6, or both? (Enter: ipv4 / ipv6 / both):\n> ").lower()
        if version in {"ipv4", "ipv6", "both"}:
            break
        print(Fore.RED + "Invalid input. Choose 'ipv4', 'ipv6', or 'both'.")
    
    return count, version

def generate_random_ip(ipv6=False):
    if ipv6:
        return ":".join(f"{random.randint(0, 0xffff):x}" for _ in range(8))
    else:
        return ".".join(str(random.randint(0, 255)) for _ in range(4))

def generate_and_compare(count, version, user_ips):
    generated_ips = []
    flagged_ips = []

    for _ in range(count):
        if version in {"ipv4", "both"}:
            ip4 = generate_random_ip(ipv6=False)
            generated_ips.append((ip4, "IPv4"))
            if ip4 in user_ips:
                flagged_ips.append((ip4, "IPv4"))

        if version in {"ipv6", "both"}:
            ip6 = generate_random_ip(ipv6=True)
            generated_ips.append((ip6, "IPv6"))
            if ip6 in user_ips:
                flagged_ips.append((ip6, "IPv6"))

    return generated_ips, flagged_ips

def main():
    print(Fore.CYAN + "=== IP Address Generator & Flag Detector ===")
    user_ips = get_user_ips()
    count, version = get_user_config()

    print(Fore.MAGENTA + "\n[*] Generating and checking IPs...\n")
    generated, flagged = generate_and_compare(count, version, user_ips)

    print(Fore.CYAN + "\n=== Generated IP Addresses ===")
    for ip, ip_type in generated:
        color = Fore.RED if (ip, ip_type) in flagged else Fore.GREEN
        print(color + f"- {ip} [{ip_type}]")

    print(Fore.CYAN + "\n=== Summary Report ===")
    print(f"{Fore.BLUE}Total IPs Generated: {len(generated)}")
    print(f"{Fore.RED if flagged else Fore.GREEN}Total Flagged IPs Detected: {len(flagged)}")

    if flagged:
        print(Fore.RED + "\nFlagged IPs:")
        for ip, ip_type in flagged:
            print(Fore.RED + f"- {ip} [{ip_type}]")
    else:
        print(Fore.GREEN + "No flagged IPs found.")

    print(Fore.CYAN + "\nThank you for using the IP Address Generator & Flag Detector. Have a nice day!")

if __name__ == "__main__":
    main()
