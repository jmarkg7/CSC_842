import win32evtlog
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime

def parse_windows_logins(user_filter=None):
    server = 'localhost'
    logtype = 'Security'
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    hand = win32evtlog.OpenEventLog(server, logtype)
    total = win32evtlog.GetNumberOfEventLogRecords(hand)

    login_events = []
    
    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            break
        for event in events:
            if event.EventID != 4624:
                continue

            data = event.StringInserts
            if not data or len(data) < 9:
                continue

            try:
                domain = data[6]
                username = data[5]
                full_user = f"{domain}\\{username}"
                logon_type = data[8]
            except IndexError:
                continue

            # Filter out system and anonymous logins
            if "system" in full_user.lower() or "anonymous" in full_user.lower():
                continue

            if user_filter and full_user.lower() != user_filter.lower():
                continue

            timestamp = event.TimeGenerated
            login_events.append({'user': full_user, 'timestamp': timestamp, 'logon_type': logon_type})

    win32evtlog.CloseEventLog(hand)
    return login_events

def visualize_logins(logins):
    df = pd.DataFrame(logins)
    if df.empty:
        print("No login events found.")
        return

    df['hour'] = df['timestamp'].dt.hour
    login_counts = df.groupby('hour').size()

    unique_users = sorted(df['user'].unique())
    user_display = ', '.join(unique_users[:5])
    if len(unique_users) > 5:
        user_display += f", +{len(unique_users) - 5} more"

    plt.figure(figsize=(10, 5))
    login_counts.plot(kind='bar', color='mediumseagreen')
    plt.title('Successful Logins by Hour of Day')
    plt.suptitle(f"Accounts: {user_display}", fontsize=10, y=0.94, color='dimgray')
    plt.xlabel('Hour (24-hour clock)')
    plt.ylabel('Number of Logins')
    plt.xticks(rotation=0)
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.show()

def main():
    user_filter = input("Enter full username to filter (e.g., WORKSTATION\\julian), or leave blank for all: ").strip()
    if user_filter == "":
        user_filter = None

    print("Parsing login events from the Windows Security log (Event ID 4624)...")
    logins = parse_windows_logins(user_filter)

    print(f"\nTotal successful logins found: {len(logins)}")
    if len(logins) > 0:
        unique_users = set(entry['user'] for entry in logins)
        print("Users found:")
        for user in unique_users:
            print(f" - {user}")

    visualize_logins(logins)

if __name__ == "__main__":
    main()
