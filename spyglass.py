import requests  # For HTTP requests
import re        # For pattern matching (emails & subdomains, and cleaning filenames)
from bs4 import BeautifulSoup  # For parsing HTML content
import socket    # For DNS resolving and port scanning
import time      # For measuring elapsed time
import csv       # For exporting results as CSV

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
}

def print_banner():
    print("""⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⡿⠛⠛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠛⠻⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣷⣤⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡤⠀⢀⣁⣠⣄⡉⠛⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⢠⣶⡿⠟⠛⠛⢿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⢰⣿⡏   ⠀ ⠙⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⢸⣿⡇  ⠀  ⠀⣸⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡈⢻⣷⣄   ⢀⣴⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠙⠻⢷⣶⣾⠿⠋⢰⣦⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣦⡄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠈⠛⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀""")
    print("            🔍  S P Y G L A S S")
    print("---------------------------------------------")
    print("       Your OSINT Reconnaissance Friend!\n")

def scan_ports(ip, ports=None):
    if ports is None:
        ports = [80, 443]
    open_ports = []
    for port in ports:
        try:
            sock = socket.create_connection((ip, port), timeout=1)
            open_ports.append(port)
            sock.close()
        except:
            continue
    return open_ports

def searchBing(domain, limit=10):
    search_results = []
    for page in range(0, limit, 10):
        url = f"https://www.bing.com/search?q={domain}&first={page}"
        try:
            res = requests.get(url, headers=HEADERS)
            soup = BeautifulSoup(res.text, 'html.parser')
            links = soup.find_all('a', href=True)
            for link in links:
                href = link['href']
                if domain in href and href.startswith("http"):
                    search_results.append(href)
        except:
            continue
    return list(set(search_results))

def getInfo(urls, domain):
    emails = set()
    subdomains = set()
    for url in urls:
        try:
            res = requests.get(url, timeout=5, headers=HEADERS)
            content = res.text
            emails.update(re.findall(rf"[a-zA-Z0-9._%+-]+@{domain}", content))
            subdomains.update(re.findall(rf"https?://([a-zA-Z0-9.-]+\.{domain})", content))
        except:
            continue
    return emails, subdomains

def scan_directories(subdomains, paths=None):
    if paths is None:
        paths = ["/admin", "/login", "/robots.txt", "/.env", "/.git", "/config", "/backup", "/db", "/test"]
    found_dirs = {}
    print("\nI'm scanning for sensitive directories on your subdomains...")
    if not subdomains:
        print("Hmm, looks like there aren't any subdomains to scan!\n")
        return found_dirs
    for sub in subdomains:
        url_base = f"http://{sub}"
        found_dirs[sub] = []
        for path in paths:
            full_url = url_base + path
            try:
                res = requests.get(full_url, headers=HEADERS, timeout=3)
                if res.status_code in [200, 401, 403]:
                    found_dirs[sub].append((path, res.status_code))
                    print(f"   [+] {full_url} => {res.status_code}")
            except requests.RequestException:
                continue
    if not any(found_dirs.values()):
        print("No sensitive directories found. Everything looks pretty safe!\n")
    return found_dirs

def geoip_lookup(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,query"
        res = requests.get(url, timeout=5)
        data = res.json()
        if data.get('status') == 'success':
            return data.get('country', 'N/A'), data.get('city', 'N/A')
        else:
            return 'N/A', 'N/A'
    except:
        return 'N/A', 'N/A'

def check_technologies(url):
    try:
        from builtwith import builtwith
    except ImportError:
        print("builtwith library not installed. You can install it with: pip install builtwith")
        return set()
    try:
        info = builtwith(url)
        techs = set()
        for category, values in info.items():
            for tech in values:
                techs.add(tech)
        return techs
    except Exception:
        return set()

def saveResultSearch(emails, subdomains, found_dirs, domain, geoip_results=None, tech_results=None):
    def clean_filename(s):
        return re.sub(r'[^a-zA-Z0-9_\-\.]', '_', s.split('://')[-1])
    fname = f"results_{clean_filename(domain)}.txt"
    with open(fname, "w") as f:
        f.write("Emails:\n")
        if emails:
            for email in emails:
                f.write(email + "\n")
        else:
            f.write("No emails found.\n")
        f.write("\nSubdomains:\n")
        if subdomains:
            for sub in subdomains:
                f.write(sub)
                if geoip_results and sub in geoip_results:
                    ip, country, city = geoip_results[sub]
                    f.write(f" ({ip}, {country}, {city})")
                if tech_results and sub in tech_results:
                    f.write(f" | Technologies: {', '.join(tech_results[sub])}")
                f.write("\n")
        else:
            f.write("No subdomains found.\n")
        f.write("\nFound Directories:\n")
        found_any = False
        for sub, dirs in found_dirs.items():
            if dirs:
                found_any = True
                f.write(f"\n{sub}\n")
                for path, code in dirs:
                    f.write(f"  {path} => {code}\n")
        if not found_any:
            f.write("No sensitive directories found.\n")

def save_results_html(emails, subdomains, found_dirs, domain, geoip_results=None, tech_results=None):
    def clean_filename(s):
        return re.sub(r'[^a-zA-Z0-9_\-\.]', '_', s.split('://')[-1])
    fname = f"results_{clean_filename(domain)}.html"
    html = f"""
    <html>
    <head>
        <title>Results for {domain}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 30px; }}
            h2 {{ color: #1a75cf; }}
            table, th, td {{ border: 1px solid #ccc; border-collapse: collapse; }}
            th, td {{ padding: 8px 12px; }}
            th {{ background: #f5f5f5; }}
        </style>
    </head>
    <body>
        <h2>Emails</h2>
        <ul>
            {''.join(f"<li>{email}</li>" for email in emails) if emails else "<li>No emails found.</li>"}
        </ul>
        <h2>Subdomains</h2>
        <table>
            <tr><th>Subdomain</th><th>IP</th><th>Country</th><th>City</th><th>Technologies</th></tr>
            {''.join(
                f"<tr><td>{sub}</td><td>{geoip_results[sub][0] if geoip_results and sub in geoip_results else ''}</td>"
                f"<td>{geoip_results[sub][1] if geoip_results and sub in geoip_results else ''}</td>"
                f"<td>{geoip_results[sub][2] if geoip_results and sub in geoip_results else ''}</td>"
                f"<td>{', '.join(tech_results[sub]) if tech_results and sub in tech_results else ''}</td></tr>"
                for sub in subdomains
            ) if subdomains else "<tr><td colspan='5'>No subdomains found.</td></tr>"}
        </table>
        <h2>Found Directories</h2>
        {''.join(
            f"<h4>{sub}</h4><ul>{''.join(f'<li>{path} &rarr; {code}</li>' for path, code in dirs)}</ul>"
            for sub, dirs in found_dirs.items() if dirs
        ) if found_dirs and any(found_dirs.values()) else "<p>No sensitive directories found.</p>"}
    </body>
    </html>
    """
    with open(fname, "w", encoding="utf-8") as f:
        f.write(html)

def save_results_csv(emails, subdomains, found_dirs, domain, geoip_results=None, tech_results=None):
    def clean_filename(s):
        return re.sub(r'[^a-zA-Z0-9_\-\.]', '_', s.split('://')[-1])
    fname = f"results_{clean_filename(domain)}.csv"
    with open(fname, "w", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Section", "Value1", "Value2", "Value3", "Value4", "Technologies"])
        if emails:
            for email in emails:
                writer.writerow(["Email", email, "", "", "", ""])
        else:
            writer.writerow(["Email", "No emails found", "", "", "", ""])
        if subdomains:
            for sub in subdomains:
                ip, country, city = geoip_results[sub] if geoip_results and sub in geoip_results else ("", "", "")
                techs = ", ".join(tech_results[sub]) if tech_results and sub in tech_results else ""
                writer.writerow(["Subdomain", sub, ip, country, city, techs])
        else:
            writer.writerow(["Subdomain", "No subdomains found", "", "", "", ""])
        found_any = False
        for sub, dirs in found_dirs.items():
            if dirs:
                found_any = True
                for path, code in dirs:
                    writer.writerow(["Directory", sub, path, code, "", ""])
        if not found_any:
            writer.writerow(["Directory", "No sensitive directories found", "", "", "", ""])

def sniff_packets(duration=10):
    try:
        from scapy.all import sniff
    except ImportError:
        print("Scapy is not installed. Install it using 'pip install scapy'")
        return
    print(f"Sniffing network packets for {duration} seconds...")
    packets = sniff(timeout=duration)
    print(f"Captured {len(packets)} packets.")
    protocols = {}
    for pkt in packets:
        proto = pkt.summary().split()[0]
        protocols[proto] = protocols.get(proto, 0) + 1
    print("\nPacket summary by protocol:")
    for proto, count in protocols.items():
        print(f" - {proto}: {count}")
    return packets

def findTheKeywords(file_path, keywords):
    results = {}
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        lines = file.readlines()
        for kw in keywords:
            results[kw] = {'count': 0, 'lines': [], 'snippets': []}
            for idx, line in enumerate(lines, 1):
                if kw in line:
                    results[kw]['count'] += line.count(kw)
                    results[kw]['lines'].append(idx)
                    results[kw]['snippets'].append(line.strip())
    return results

if __name__ == "__main__":
    print_banner()

    target = input("Enter a domain to search (e.g., example.com): ").strip()
    print("\nAlright, let's start looking for info on your domain...")
    start_time = time.time()

    links = searchBing(target, limit=20)
    print(f"\nI found {len(links)} links related to your domain." if links else "\nCouldn't find any links for your domain.")

    emails, subdomains = getInfo(links, target)

    print(f"\nEmails found ({len(emails)}):")
    if emails:
        for e in emails:
            print(" -", e)
    else:
        print("I couldn't find any emails. Maybe try another domain?")

    print(f"\nSubdomains found ({len(subdomains)}):")
    if subdomains:
        for s in subdomains:
            print(" -", s)
    else:
        print("No subdomains were detected. This domain seems secure.")

    scan_ports_flag = input("\nWould you like me to scan ports and get GeoIP info for subdomains? (y/n): ").strip().lower()
    geoip_results = {}
    if scan_ports_flag == "y" and subdomains:
        for sub in subdomains:
            try:
                ip = socket.gethostbyname(sub)
                country, city = geoip_lookup(ip)
                geoip_results[sub] = (ip, country, city)
                print(f" - {sub} ({ip}) is located in {city}, {country}")
                open_ports = scan_ports(ip)
                print(f"   Open ports: {open_ports if open_ports else 'No open ports detected'}")
            except socket.gaierror:
                geoip_results[sub] = ("N/A", "N/A", "N/A")
                print(f" - Couldn't resolve {sub} to an IP address.")
    elif scan_ports_flag == "y":
        print("No subdomains to scan for ports or GeoIP.")
    else:
        for sub in subdomains:
            geoip_results[sub] = ("N/A", "N/A", "N/A")

    scan_dirs_flag = input("\nWant me to check for sensitive directories? (y/n): ").strip().lower()
    if scan_dirs_flag == "y":
        found_dirs = scan_directories(subdomains)
    else:
        found_dirs = {}

    tech_results = {}
    print("\nNow, let's check what tech stacks these subdomains are running...")
    if subdomains:
        for sub in subdomains:
            url = f"http://{sub}"
            print(f"   Checking {sub} ...")
            techs = check_technologies(url)
            tech_results[sub] = techs
            if techs:
                print(f"     Technologies detected: {', '.join(techs)}")
            else:
                print("     Sorry, couldn't detect any technologies.")
    else:
        print("No subdomains found to analyze for technologies.")

    # Save results (clean filename to avoid errors)
    def clean_filename(s):
        return re.sub(r'[^a-zA-Z0-9_\-\.]', '_', s.split('://')[-1])
    clean_target = clean_filename(target)

    saveResultSearch(emails, subdomains, found_dirs, target, geoip_results, tech_results)
    print(f"\nYour results have been saved as: results_{clean_target}.txt")
    save_results_html(emails, subdomains, found_dirs, target, geoip_results, tech_results)
    print(f"HTML report: results_{clean_target}.html")
    save_results_csv(emails, subdomains, found_dirs, target, geoip_results, tech_results)
    print(f"CSV/Excel report: results_{clean_target}.csv")

    search_keywords_flag = input(
        "\nWould you like to search for specific keywords in your saved results? (y/n): ").strip().lower()
    if search_keywords_flag == "y":
        keywords_input = input("Enter keywords to search (separate with commas): ").strip()
        keywords = [kw.strip() for kw in keywords_input.split(",") if kw.strip()]
        if keywords:
            keyword_results = findTheKeywords(
                f"results_{clean_target}.txt", keywords)
            print("\nHere's what I found for your keywords:")
            for keyword, info in keyword_results.items():
                if info['count'] > 0:
                    print(f" - '{keyword}' found {info['count']} time(s):")
                    for idx, snippet in zip(info['lines'], info['snippets']):
                        print(f"    [Line {idx}]: {snippet}")
                else:
                    print(f" - '{keyword}' not found in the file.")
        else:
            print("You didn't enter any keywords.")

    print(f"\nAll done! Thanks for hanging out with SpyGlass.")
    print(f"Total scan time: {time.time() - start_time:.2f} seconds")
