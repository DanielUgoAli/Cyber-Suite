import random

# Generate random IPv4
def generate_random_ipv4():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))

# Generate random IPv6
def generate_random_ipv6():
    return ":".join(f"{random.randint(0, 65535):x}" for _ in range(8))

# Ask user for IPs to compare against
def get_user_ips():
    user_input = input("Enter IPs to compare against (separated by space or comma):\n> ")
    return set(ip.strip() for ip in user_input.replace(",", " ").split() if ip.strip())

# Ask user for number of IPs and type
def get_user_config():
    while True:
        try:
            count = int(input("How many IP addresses do you want to generate?\n> "))
            break
        except ValueError:
            print("Please enter a valid number.")
    
    while True:
        version = input("Generate IPv4, IPv6, or both? (Enter: ipv4 / ipv6 / both):\n> ").lower()
        if version in ["ipv4", "ipv6", "both"]:
            break
        print("Please enter 'ipv4', 'ipv6', or 'both'.")
    
    return count, version

# Generate and compare IPs
def generate_and_compare(count, version, user_ips):
    generated_ips = []   # Format: (ip, type)
    masked_ips = []

    for _ in range(count):
        if version in ["ipv4", "both"]:
            ip4 = generate_random_ipv4()
            generated_ips.append((ip4, "IPv4"))
            if ip4 in user_ips:
                print(f"[!] MASKED: {ip4} matches an inputted IP.")
                masked_ips.append((ip4, "IPv4"))

        if version in ["ipv6", "both"]:
            ip6 = generate_random_ipv6()
            generated_ips.append((ip6, "IPv6"))
            if ip6 in user_ips:
                print(f"[!] MASKED: {ip6} matches an inputted IP.")
                masked_ips.append((ip6, "IPv6"))
    if version == "both":
        num_ipv4 = count // 2
        num_ipv6 = count - num_ipv4
        # Alternate adding IPv4 and IPv6 for better distribution
        for i in range(count):
            if i % 2 == 0 and num_ipv4 > 0:
                ip4 = generate_random_ipv4()
                generated_ips.append((ip4, "IPv4"))
                if ip4 in user_ips:
                    print(f"[!] MASKED: {ip4} matches an inputted IP.")
                    masked_ips.append((ip4, "IPv4"))
                num_ipv4 -= 1
            elif num_ipv6 > 0:
                ip6 = generate_random_ipv6()
                generated_ips.append((ip6, "IPv6"))
                if ip6 in user_ips:
                    print(f"[!] MASKED: {ip6} matches an inputted IP.")
                    masked_ips.append((ip6, "IPv6"))
                num_ipv6 -= 1
    elif version == "ipv4":
        for _ in range(count):
            ip4 = generate_random_ipv4()
            generated_ips.append((ip4, "IPv4"))
            if ip4 in user_ips:
                print(f"[!] MASKED: {ip4} matches an inputted IP.")
                masked_ips.append((ip4, "IPv4"))
    elif version == "ipv6":
        for _ in range(count):
            ip6 = generate_random_ipv6()
            generated_ips.append((ip6, "IPv6"))
            if ip6 in user_ips:
                print(f"[!] MASKED: {ip6} matches an inputted IP.")
                masked_ips.append((ip6, "IPv6"))
    return generated_ips, masked_ips

# === MAIN ===
if __name__ == "__main__":
    print("=== IP Address Generator & Mask Detector ===")
    user_ips = get_user_ips()
    count, version = get_user_config()

    print("\n[*] Generating and checking IPs...\n")
    generated, masked = generate_and_compare(count, version, user_ips)

    # Display all generated IPs with labels
    print("\n=== Generated IP Addresses ===")
    for ip, ip_type in generated:
        print(f"- {ip} [{ip_type}]")

    # Summary
    print("\n=== Summary Report ===")
    print(f"Total IPs Generated: {len(generated)}")
    print(f"Total Masked IPs Detected: {len(masked)}")

    if masked:
        print("\nMasked IPs:")
        for ip, ip_type in masked:
            print(f"- {ip} [{ip_type}]")
    else:
        print("No masked IPs found.")
    print("\nThank you for using the IP Address Generator & Mask detector. Have a nice day!")



