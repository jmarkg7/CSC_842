# suricata_rule_builder.py

def get_input(prompt, example=None, options=None):
    print("\n" + prompt)
    if example:
        print(f"Example: {example}")
    if options:
        print(f"Options: {', '.join(options)}")
    return input("Your input: ").strip()

def build_suricata_rule():
    print("🛡️ Suricata Rule Builder for Beginners 🛡️")
    print("This tool will guide you through building a basic Suricata IDS rule.\n")

    # Action
    action = get_input(
        "1. What action should Suricata take when this rule matches?",
        "alert, drop, reject, pass",
        ["alert", "drop", "reject", "pass"]
    )

    # Protocol
    protocol = get_input(
        "2. What protocol should this rule apply to?",
        "tcp, udp, icmp, ip",
        ["tcp", "udp", "icmp", "ip"]
    )

    # Source IP
    src_ip = get_input(
        "3. What is the source IP or network?",
        "192.168.1.0/24 or any"
    )

    # Source Port
    src_port = get_input(
        "4. What is the source port?",
        "80, 443, or any"
    )

    # Direction
    direction = get_input(
        "5. What is the traffic direction?",
        "-> (source to destination), <- (destination to source)",
        ["->", "<-"]
    )

    # Destination IP
    dst_ip = get_input(
        "6. What is the destination IP or network?",
        "any or 10.0.0.0/8"
    )

    # Destination Port
    dst_port = get_input(
        "7. What is the destination port?",
        "80, 443, or any"
    )

    # Message
    msg = get_input(
        "8. What message should be logged when this rule triggers?",
        "Possible malicious HTTP request"
    )

    # Content match
    content = get_input(
        "9. Do you want to match specific content in the packet payload?",
        "e.g., /etc/passwd (leave blank to skip)"
    )

    # SID
    sid = get_input(
        "10. Enter a unique SID (Suricata rule ID).",
        "e.g., 1000001"
    )

    # Rev
    rev = get_input(
        "11. Enter a revision number for this rule.",
        "Start with 1"
    )

    # Rule building
    rule = f"{action} {protocol} {src_ip} {src_port} {direction} {dst_ip} {dst_port} (msg:\"{msg}\""
    if content:
        rule += f"; content:\"{content}\""
    rule += f"; sid:{sid}; rev:{rev};)"

    print("\n✅ Your Suricata rule is ready:")
    print(rule)

    # Optionally write to file
    save = input("\nDo you want to save this rule to a file? (y/n): ").lower()
    if save == "y":
        filename = input("Enter filename (e.g., myrules.rules): ")
        with open(filename, "a") as f:
            f.write(rule + "\n")
        print(f"Rule saved to {filename}")

if __name__ == "__main__":
    build_suricata_rule()
