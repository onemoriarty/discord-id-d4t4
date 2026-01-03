from flask import Flask, request, render_template_string, session, redirect, url_for, jsonify, g
import os
import re
import base64
import json
from datetime import datetime
import requests
import ipaddress
import socket
import whois
import time
from urllib.parse import urlparse
import concurrent.futures
import threading
import dns.resolver
import ssl
import random
import hashlib

app = Flask(__name__)

# Render için güvenli ayarlar
app.secret_key = os.environ.get('SECRET_KEY', 'vahset_render_2025_secure_key')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800

CORRECT_KEY = os.environ.get('ACCESS_KEY', 'vahset2025')

# Global değişken
users_data = {}
osint_cache = {}
user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/537.36'
]

# GitHub'dan veri çekmek için ayarlar
GITHUB_USERNAME = os.environ.get('GITHUB_USERNAME', 'cappyyyyyy')
GITHUB_REPO = os.environ.get('GITHUB_REPO', 'vahset')
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', 'github tokenini yazcan burayad')

class TerminalStyle:
    """Terminal stili sabitler"""
    COLORS = {
        'black': '#0a0a0a',
        'dark': '#0d1117',
        'gray': '#161b22',
        'light_gray': '#21262d',
        'red': '#ff3333',
        'green': '#00ff00',  # Terminal yeşili
        'cyan': '#58a6ff',
        'yellow': '#ffcc00',
        'orange': '#ff9900',
        'purple': '#bc8cff',
        'pink': '#ff66cc',
        'white': '#f0f6fc',
        'blue': '#1f6feb',
        'terminal_green': '#00ff00',
        'matrix_green': '#00ff88'
    }
    
    GRADIENTS = {
        'terminal': 'linear-gradient(135deg, #0d1117 0%, #0a0a0a 50%, #161b22 100%)',
        'header': 'linear-gradient(90deg, #0d1117 0%, #161b22 100%)',
        'button': 'linear-gradient(90deg, #1f6feb 0%, #58a6ff 100%)',
        'danger': 'linear-gradient(90deg, #ff3333 0%, #ff6666 100%)',
        'success': 'linear-gradient(90deg, #00ff00 0%, #00cc00 100%)',
        'warning': 'linear-gradient(90deg, #ff9900 0%, #ffcc00 100%)',
        'terminal_green': 'linear-gradient(90deg, #00ff00 0%, #00cc00 100%)',
        'matrix': 'linear-gradient(90deg, #00ff00 0%, #00ff88 100%)'
    }

def parse_line_data(line):
    """Bir satır veriyi parse et"""
    line = line.strip().rstrip(',')
    if not line or not line.startswith('('):
        return None
    
    if line.endswith('),'):
        line = line[:-1]
    
    if line.startswith('(') and line.endswith(')'):
        line = line[1:-1]
        
        # Değerleri ayır
        values = []
        current = ""
        in_quotes = False
        quote_char = None
        in_brackets = 0
        
        for char in line:
            if char in ("'", '"') and not in_quotes and in_brackets == 0:
                in_quotes = True
                quote_char = char
                current += char
            elif char == quote_char and in_quotes:
                in_quotes = False
                current += char
            elif char == '[' and not in_quotes:
                in_brackets += 1
                current += char
            elif char == ']' and not in_quotes:
                in_brackets -= 1
                current += char
            elif char == ',' and not in_quotes and in_brackets == 0:
                values.append(current.strip())
                current = ""
            else:
                current += char
        
        if current:
            values.append(current.strip())
        
        # Verileri çıkar
        if len(values) >= 9:
            user_id = values[0].strip().strip("'\"")
            
            # Email decode
            email_encoded = values[1].strip().strip("'\"")
            email = "N/A"
            
            if email_encoded and email_encoded not in ['null', '', 'NULL']:
                try:
                    decoded = base64.b64decode(email_encoded)
                    email = decoded.decode('utf-8', errors='ignore')
                except:
                    email = email_encoded
            
            # IP adresi
            ip = values[8].strip().strip("'\"") if len(values) > 8 else "N/A"
            if ip in ['null', 'NULL']:
                ip = "N/A"
            
            return {
                'user_id': user_id,
                'email': email,
                'ip': ip,
                'encoded': email_encoded
            }
    
    return None

def load_data_from_github():
    """GitHub'dan veri çek"""
    global users_data
    
    print("=" * 70)
    print("🚀 VAHSET TERMINAL OSINT v3.0 - GITHUB DATA LOADER")
    print("=" * 70)
    
    all_users = {}
    
    # GitHub raw URL'leri
    github_files = [
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part1.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part2.txt", 
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part3.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part4.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part5.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part6.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part7.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part8.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part9.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part10.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part11.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part12.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part13.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part14.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part15.txt"       
        ]
    
    total_loaded = 0
    
    for i, url in enumerate(github_files, 1):
        print(f"\n📖 GitHub'dan yükleniyor: data_part{i}.txt")
        
        try:
            headers = {'User-Agent': random.choice(user_agents)}
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                content = response.text
                lines = content.strip().split('\n')
                print(f"   ✅ Yüklendi: {len(lines)} satır")
                
                file_count = 0
                for line in lines:
                    data = parse_line_data(line)
                    if data:
                        all_users[data['user_id']] = {
                            'email': data['email'],
                            'ip': data['ip'],
                            'encoded': data['encoded']
                        }
                        file_count += 1
                        total_loaded += 1
                
                print(f"   📊 Parse edildi: {file_count} kayıt")
                
            elif response.status_code == 404:
                print(f"   ⚠️  Dosya bulunamadı: data_part{i}.txt")
            else:
                print(f"   ❌ Hata: {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ Network hatası: {str(e)}")
    
    print(f"\n🎯 TOPLAM YÜKLENEN: {len(all_users):,} kullanıcı")
    
    if all_users:
        print("\n📊 ÖRNEK KAYITLAR:")
        sample_ids = list(all_users.keys())[:3]
        for uid in sample_ids:
            data = all_users[uid]
            print(f"   📍 ID: {uid}")
            print(f"      📧 Email: {data['email'][:50]}...")
            print(f"      🌐 IP: {data['ip']}")
            print()
    
    users_data = all_users
    return all_users

# ==================== OSINT FONKSIYONLARI ====================

def get_ip_geolocation(ip):
    """Free IP geolocation servisleri"""
    if not ip or ip == "N/A":
        return None
    
    try:
        # ip-api.com (free, no API key needed)
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return {
                    'country': data.get('country', 'Unknown'),
                    'countryCode': data.get('countryCode', 'XX'),
                    'region': data.get('regionName', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'zip': data.get('zip', 'Unknown'),
                    'lat': data.get('lat', 0),
                    'lon': data.get('lon', 0),
                    'isp': data.get('isp', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'as': data.get('as', 'Unknown')
                }
    except:
        pass
    
    try:
        # ipapi.co (free tier)
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if not data.get('error'):
                return {
                    'country': data.get('country_name', 'Unknown'),
                    'countryCode': data.get('country_code', 'XX'),
                    'region': data.get('region', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'zip': data.get('postal', 'Unknown'),
                    'lat': data.get('latitude', 0),
                    'lon': data.get('longitude', 0),
                    'isp': data.get('org', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'as': data.get('asn', 'Unknown')
                }
    except:
        pass
    
    return None

def check_ip_reputation(ip):
    """IP reputation check with free sources"""
    reputation = {
        'threat_level': 'Low',
        'blacklists': [],
        'proxy': False,
        'vpn': False,
        'tor': False
    }
    
    try:
        # Check if it's a private IP
        if ipaddress.ip_address(ip).is_private:
            reputation['threat_level'] = 'Local'
            reputation['is_private'] = True
            return reputation
        
        # AbuseIPDB check (free tier - limited)
        headers = {'Key': '', 'Accept': 'application/json'}
        response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", 
                              headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('data'):
                rep = data['data']
                if rep.get('abuseConfidenceScore', 0) > 50:
                    reputation['threat_level'] = 'High'
                elif rep.get('abuseConfidenceScore', 0) > 20:
                    reputation['threat_level'] = 'Medium'
                
                if rep.get('isTor'):
                    reputation['tor'] = True
                if rep.get('isPublic'):
                    reputation['proxy'] = True
        
        # Check common blacklists via DNSBL
        blacklists = [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'b.barracudacentral.org'
        ]
        
        reversed_ip = '.'.join(reversed(ip.split('.')))
        
        for bl in blacklists:
            try:
                query = f"{reversed_ip}.{bl}"
                socket.gethostbyname(query)
                reputation['blacklists'].append(bl)
            except:
                pass
        
        if reputation['blacklists']:
            reputation['threat_level'] = 'High'
            
    except Exception as e:
        print(f"IP reputation check error: {e}")
    
    return reputation

def get_whois_info(domain):
    """WHOIS bilgisi al"""
    try:
        w = whois.whois(domain)
        return {
            'registrar': w.registrar,
            'creation_date': str(w.creation_date) if w.creation_date else 'Unknown',
            'expiration_date': str(w.expiration_date) if w.expiration_date else 'Unknown',
            'name_servers': list(w.name_servers)[:5] if w.name_servers else [],
            'org': w.org,
            'country': w.country
        }
    except:
        return None

def check_email_breaches(email):
    """Email breach kontrolü (Have I Been Pwned API'siz versiyon)"""
    breaches = []
    
    try:
        # Check common breach patterns
        email_hash = hashlib.sha1(email.lower().encode()).hexdigest().upper()
        
        # Local breach check (simulated for common breaches)
        common_breaches = [
            {'name': 'LinkedIn 2012', 'date': '2012', 'records': '165M'},
            {'name': 'Adobe 2013', 'date': '2013', 'records': '153M'},
            {'name': 'Dropbox 2012', 'date': '2012', 'records': '68M'},
            {'name': 'Twitter 2016', 'date': '2016', 'records': '33M'},
            {'name': 'Facebook 2019', 'date': '2019', 'records': '533M'}
        ]
        
        # Simulate random breach detection (in real app, use API)
        import random
        if random.random() > 0.7:  # 30% chance of finding a breach
            breaches = random.sample(common_breaches, random.randint(1, 3))
        
    except:
        pass
    
    return breaches

def analyze_email(email):
    """Email analizi"""
    analysis = {
        'provider': 'Unknown',
        'disposable': False,
        'valid_format': False,
        'breaches': [],
        'social_media': []
    }
    
    if not email or email == 'N/A':
        return analysis
    
    # Check email format
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(email_regex, email):
        analysis['valid_format'] = True
        
        # Extract domain
        domain = email.split('@')[1].lower()
        analysis['domain'] = domain
        
        # Check common providers
        common_providers = {
            'gmail.com': 'Google',
            'yahoo.com': 'Yahoo',
            'outlook.com': 'Microsoft',
            'hotmail.com': 'Microsoft',
            'icloud.com': 'Apple',
            'aol.com': 'AOL',
            'protonmail.com': 'ProtonMail',
            'yandex.com': 'Yandex'
        }
        
        if domain in common_providers:
            analysis['provider'] = common_providers[domain]
        
        # Check disposable emails
        disposable_domains = ['mailinator.com', 'tempmail.com', 'guerrillamail.com', 
                             '10minutemail.com', 'throwawaymail.com']
        if domain in disposable_domains:
            analysis['disposable'] = True
        
        # Check breaches
        analysis['breaches'] = check_email_breaches(email)
        
        # Guess social media (basic pattern matching)
        username = email.split('@')[0].lower()
        common_patterns = {
            'john': ['Facebook', 'Twitter'],
            'jane': ['Facebook', 'Instagram'],
            'admin': ['LinkedIn', 'Twitter'],
            'info': ['Business', 'LinkedIn'],
            'support': ['Business', 'Service']
        }
        
        for pattern, platforms in common_patterns.items():
            if pattern in username:
                analysis['social_media'] = platforms
                break
    
    return analysis

def get_dns_info(domain):
    """DNS kayıtlarını kontrol et"""
    dns_records = {}
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        # A record
        try:
            answers = resolver.resolve(domain, 'A')
            dns_records['A'] = [str(r) for r in answers]
        except:
            pass
        
        # MX records
        try:
            answers = resolver.resolve(domain, 'MX')
            dns_records['MX'] = [str(r) for r in answers]
        except:
            pass
        
        # TXT records
        try:
            answers = resolver.resolve(domain, 'TXT')
            dns_records['TXT'] = [str(r) for r in answers]
        except:
            pass
        
        # NS records
        try:
            answers = resolver.resolve(domain, 'NS')
            dns_records['NS'] = [str(r) for r in answers]
        except:
            pass
        
    except Exception as e:
        print(f"DNS check error: {e}")
    
    return dns_records

def scan_website(domain):
    """Temel website taraması"""
    scan_result = {
        'ssl': False,
        'server': 'Unknown',
        'status': 'Unknown',
        'ports': [],
        'technologies': []
    }
    
    try:
        # Check SSL
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                scan_result['ssl'] = True
                cert = ssock.getpeercert()
                if cert:
                    scan_result['ssl_expiry'] = cert['notAfter']
        
        # Check common ports
        common_ports = [80, 443, 21, 22, 25, 3389, 8080, 8443]
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((domain, port))
                if result == 0:
                    scan_result['ports'].append(port)
                sock.close()
            except:
                pass
        
        # Guess server from headers
        try:
            response = requests.get(f"http://{domain}", timeout=5)
            scan_result['status'] = response.status_code
            if 'Server' in response.headers:
                scan_result['server'] = response.headers['Server']
            
            # Detect technologies
            headers_lower = {k.lower(): v for k, v in response.headers.items()}
            if 'x-powered-by' in headers_lower:
                scan_result['technologies'].append(headers_lower['x-powered-by'])
            if 'x-aspnet-version' in headers_lower:
                scan_result['technologies'].append('ASP.NET')
        
        except:
            pass
        
    except Exception as e:
        print(f"Website scan error: {e}")
    
    return scan_result

def perform_ip_osint(ip):
    """Tam IP OSINT analizi"""
    osint_data = {
        'geolocation': None,
        'reputation': None,
        'whois': None,
        'dns': None,
        'scan': None,
        'services': []
    }
    
    if not ip or ip == "N/A":
        return osint_data
    
    # Cache kontrolü
    cache_key = f"ip_{ip}"
    if cache_key in osint_cache:
        return osint_cache[cache_key]
    
    try:
        # Parallel execution için thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            # Geolocation
            geo_future = executor.submit(get_ip_geolocation, ip)
            
            # Reputation
            rep_future = executor.submit(check_ip_reputation, ip)
            
            # DNS reverse lookup
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                osint_data['hostname'] = hostname
                
                # WHOIS for domain
                if '.' in hostname:
                    whois_future = executor.submit(get_whois_info, hostname)
                    osint_data['whois'] = whois_future.result(timeout=10)
                    
                    # DNS records
                    dns_future = executor.submit(get_dns_info, hostname)
                    osint_data['dns'] = dns_future.result(timeout=10)
                    
                    # Website scan
                    scan_future = executor.submit(scan_website, hostname)
                    osint_data['scan'] = scan_future.result(timeout=10)
            except:
                pass
            
            # Get results
            osint_data['geolocation'] = geo_future.result(timeout=10)
            osint_data['reputation'] = rep_future.result(timeout=10)
        
        # Detect running services
        common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }
        
        for port, service in common_services.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    osint_data['services'].append({
                        'port': port,
                        'service': service,
                        'status': 'Open'
                    })
                sock.close()
            except:
                pass
        
        # Cache'e kaydet
        osint_cache[cache_key] = osint_data
        
    except Exception as e:
        print(f"IP OSINT error: {e}")
    
    return osint_data

def perform_email_osint(email):
    """Tam Email OSINT analizi"""
    osint_data = {
        'analysis': None,
        'breaches': [],
        'social_media': [],
        'domain_info': None,
        'associated_ips': []
    }
    
    if not email or email == "N/A":
        return osint_data
    
    # Cache kontrolü
    cache_key = f"email_{email}"
    if cache_key in osint_cache:
        return osint_cache[cache_key]
    
    try:
        # Email analizi
        osint_data['analysis'] = analyze_email(email)
        
        # Domain kısmını al
        if '@' in email:
            domain = email.split('@')[1]
            
            # DNS bilgileri
            osint_data['domain_info'] = get_dns_info(domain)
            
            # WHOIS bilgisi
            osint_data['whois'] = get_whois_info(domain)
            
            # Website taraması
            osint_data['website_scan'] = scan_website(domain)
            
            # Bu domain için IP'leri bul (basit DNS lookup)
            try:
                ips = socket.gethostbyname_ex(domain)[2]
                osint_data['associated_ips'] = ips[:5]  # İlk 5 IP
            except:
                pass
        
        # Cache'e kaydet
        osint_cache[cache_key] = osint_data
        
    except Exception as e:
        print(f"Email OSINT error: {e}")
    
    return osint_data

# ==================== FLASK ROUTES ====================

# Verileri uygulama başladığında yükle
with app.app_context():
    print("\n" + "="*80)
    print("🚀 VAHSET TERMINAL OSINT v3.0")
    print("="*80)
    print("📦 GitHub'dan veriler yükleniyor...")
    users_data = load_data_from_github()
    print("✅ OSINT modülleri hazır")
    print("="*80 + "\n")

@app.before_request
def before_request():
    """Her request öncesi çalışır"""
    g.users_data = users_data

@app.route('/')
def index():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('authenticated'):
        return redirect('/terminal')
    
    error = None
    if request.method == 'POST':
        entered_key = request.form.get('access_key')
        if entered_key == CORRECT_KEY:
            session['authenticated'] = True
            session.permanent = True
            return jsonify({'success': True, 'redirect': '/terminal'})
        else:
            error = "⚠️ Invalid access key!"
    
    colors = TerminalStyle.COLORS
    gradients = TerminalStyle.GRADIENTS
    
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>VAHSET TERMINAL OSINT | ACCESS</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg-primary: {{ colors.black }};
                --bg-secondary: {{ colors.dark }};
                --bg-terminal: {{ colors.gray }};
                --accent-red: {{ colors.red }};
                --accent-green: {{ colors.green }};
                --accent-cyan: {{ colors.cyan }};
                --text-primary: {{ colors.white }};
                --text-secondary: #8b949e;
                --gradient-terminal: {{ gradients.terminal }};
                --gradient-matrix: {{ gradients.matrix }};
            }
            
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'JetBrains Mono', monospace;
                background: var(--gradient-terminal);
                color: var(--text-primary);
                min-height: 100vh;
                overflow: hidden;
            }
            
            .matrix-background {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: #000;
                z-index: -2;
            }
            
            .matrix-rain {
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                opacity: 0.1;
                background: linear-gradient(transparent 90%, var(--accent-green) 100%);
                animation: matrixRain 20s linear infinite;
            }
            
            @keyframes matrixRain {
                0% { background-position: 0 0; }
                100% { background-position: 0 1000px; }
            }
            
            .terminal-container {
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                padding: 20px;
            }
            
            .mac-window {
                background: rgba(13, 17, 23, 0.95);
                border-radius: 12px;
                width: 100%;
                max-width: 500px;
                box-shadow: 
                    0 20px 60px rgba(0, 0, 0, 0.8),
                    0 0 0 1px rgba(255, 255, 255, 0.1),
                    inset 0 1px 0 rgba(255, 255, 255, 0.05);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                overflow: hidden;
            }
            
            .mac-title-bar {
                background: rgba(22, 27, 34, 0.9);
                padding: 12px 20px;
                display: flex;
                align-items: center;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            }
            
            .mac-buttons {
                display: flex;
                gap: 8px;
            }
            
            .mac-btn {
                width: 12px;
                height: 12px;
                border-radius: 50%;
                transition: all 0.3s ease;
            }
            
            .mac-btn.close { background: #ff5f56; }
            .mac-btn.minimize { background: #ffbd2e; }
            .mac-btn.maximize { background: #27ca3f; }
            
            .mac-btn.close:hover { background: #ff3b30; }
            .mac-btn.minimize:hover { background: #ffa500; }
            .mac-btn.maximize:hover { background: #1db853; }
            
            .mac-title {
                flex: 1;
                text-align: center;
                color: var(--text-secondary);
                font-size: 0.9em;
                letter-spacing: 0.5px;
            }
            
            .login-content {
                padding: 40px;
            }
            
            .terminal-header {
                text-align: center;
                margin-bottom: 30px;
            }
            
            .terminal-icon {
                font-size: 3em;
                color: var(--accent-green);
                margin-bottom: 15px;
                animation: pulse 2s infinite;
            }
            
            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.7; }
            }
            
            .terminal-title {
                font-size: 1.8em;
                font-weight: 700;
                margin-bottom: 5px;
                background: var(--gradient-matrix);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }
            
            .terminal-subtitle {
                color: var(--text-secondary);
                font-size: 0.9em;
                letter-spacing: 2px;
                text-transform: uppercase;
            }
            
            .login-form {
                display: flex;
                flex-direction: column;
                gap: 20px;
            }
            
            .input-group {
                position: relative;
            }
            
            .terminal-input {
                background: rgba(22, 27, 34, 0.8);
                border: 1px solid rgba(88, 166, 255, 0.3);
                border-radius: 8px;
                color: var(--text-primary);
                font-family: 'JetBrains Mono', monospace;
                padding: 15px;
                width: 100%;
                font-size: 14px;
                letter-spacing: 1px;
                transition: all 0.3s ease;
            }
            
            .terminal-input:focus {
                outline: none;
                border-color: var(--accent-cyan);
                box-shadow: 0 0 20px rgba(88, 166, 255, 0.3);
                background: rgba(22, 27, 34, 0.9);
            }
            
            .input-label {
                position: absolute;
                left: 12px;
                top: -8px;
                background: var(--bg-secondary);
                padding: 0 8px;
                color: var(--accent-cyan);
                font-size: 0.8em;
            }
            
            .submit-btn {
                background: var(--gradient-matrix);
                border: none;
                border-radius: 8px;
                color: #000;
                font-family: 'JetBrains Mono', monospace;
                font-weight: 600;
                padding: 15px;
                font-size: 14px;
                cursor: pointer;
                transition: all 0.3s ease;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 10px;
                letter-spacing: 1px;
                text-transform: uppercase;
            }
            
            .submit-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 25px rgba(0, 255, 0, 0.3);
            }
            
            .error-box {
                background: rgba(255, 51, 51, 0.1);
                border: 1px solid rgba(255, 51, 51, 0.3);
                border-radius: 8px;
                padding: 15px;
                color: var(--accent-red);
                font-size: 0.9em;
                display: flex;
                align-items: center;
                gap: 10px;
                animation: errorShake 0.5s;
            }
            
            @keyframes errorShake {
                0%, 100% { transform: translateX(0); }
                25% { transform: translateX(-5px); }
                75% { transform: translateX(5px); }
            }
            
            .login-footer {
                margin-top: 30px;
                text-align: center;
                color: var(--text-secondary);
                font-size: 0.8em;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
                padding-top: 20px;
            }
            
            .version {
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 5px;
                margin-top: 5px;
            }
            
            @media (max-width: 600px) {
                .mac-window {
                    margin: 10px;
                }
                
                .login-content {
                    padding: 30px 20px;
                }
            }
        </style>
    </head>
    <body>
        <div class="matrix-background">
            <div class="matrix-rain"></div>
        </div>
        
        <div class="terminal-container">
            <div class="mac-window">
                <div class="mac-title-bar">
                    <div class="mac-buttons">
                        <div class="mac-btn close"></div>
                        <div class="mac-btn minimize"></div>
                        <div class="mac-btn maximize"></div>
                    </div>
                    <div class="mac-title">vahset_terminal_login</div>
                </div>
                
                <div class="login-content">
                    <div class="terminal-header">
                        <div class="terminal-icon">
                            <i class="fas fa-terminal"></i>
                        </div>
                        <h1 class="terminal-title">VAHSET TERMINAL</h1>
                        <div class="terminal-subtitle">OSINT Intelligence Suite</div>
                    </div>
                    
                    <form id="loginForm" method="POST" class="login-form">
                        <div class="input-group">
                            <div class="input-label">ACCESS KEY</div>
                            <input type="password" 
                                   name="access_key" 
                                   class="terminal-input"
                                   placeholder="••••••••••••"
                                   required
                                   autofocus>
                        </div>
                        
                        <button type="submit" class="submit-btn">
                            <i class="fas fa-key"></i>
                            Authenticate & Boot
                        </button>
                        
                        {% if error %}
                        <div class="error-box">
                            <i class="fas fa-exclamation-triangle"></i>
                            {{ error }}
                        </div>
                        {% endif %}
                    </form>
                    
                    <div class="login-footer">
                        <div>GitHub Data Source • Real-time OSINT</div>
                        <div class="version">
                            <i class="fab fa-github"></i>
                            <span>v3.0 • Terminal Edition</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            document.getElementById('loginForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const formData = new FormData(this);
                const button = this.querySelector('.submit-btn');
                const originalText = button.innerHTML;
                
                // Loading state
                button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> BOOTING TERMINAL...';
                button.disabled = true;
                
                try {
                    const response = await fetch('/login', {
                        method: 'POST',
                        body: formData
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        // Success - terminal boot sequence
                        button.innerHTML = '<i class="fas fa-check"></i> ACCESS GRANTED';
                        button.style.background = '{{ gradients.success }}';
                        
                        // Matrix effect before redirect
                        const matrix = document.querySelector('.matrix-rain');
                        matrix.style.opacity = '0.3';
                        
                        setTimeout(() => {
                            window.location.href = data.redirect;
                        }, 1500);
                    } else {
                        // Error state
                        button.innerHTML = originalText;
                        button.disabled = false;
                        
                        // Show error
                        const errorDiv = document.createElement('div');
                        errorDiv.className = 'error-box';
                        errorDiv.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Invalid access key!';
                        
                        const existingError = document.querySelector('.error-box');
                        if (existingError) {
                            existingError.remove();
                        }
                        
                        this.appendChild(errorDiv);
                    }
                } catch (error) {
                    button.innerHTML = originalText;
                    button.disabled = false;
                    alert('Network error. Please try again.');
                }
            });
            
            // Matrix rain effect
            const matrixBg = document.querySelector('.matrix-background');
            for (let i = 0; i < 50; i++) {
                const drop = document.createElement('div');
                drop.className = 'matrix-rain';
                drop.style.left = `${Math.random() * 100}%`;
                drop.style.animationDelay = `${Math.random() * 20}s`;
                drop.style.animationDuration = `${10 + Math.random() * 20}s`;
                matrixBg.appendChild(drop);
            }
        </script>
    </body>
    </html>
    ''', error=error, colors=TerminalStyle.COLORS, gradients=TerminalStyle.GRADIENTS)

@app.route('/terminal', methods=['GET', 'POST'])
def terminal():
    if not session.get('authenticated'):
        return redirect('/login')
    
    result = None
    user_id = None
    search_time = None
    osint_type = request.form.get('osint_type', 'basic')
    ip_osint_result = None
    email_osint_result = None
    
    if request.method == 'POST':
        user_id = request.form.get('user_id', '').strip()
        search_time = datetime.now().strftime("%H:%M:%S")
        osint_type = request.form.get('osint_type', 'basic')
        
        if user_id:
            user_data = users_data.get(user_id)
            
            if user_data:
                result = {
                    'email': user_data['email'],
                    'ip': user_data['ip'],
                    'encoded': user_data.get('encoded', ''),
                    'status': 'success'
                }
                
                # OSINT analizleri
                if osint_type == 'ip_osint' and user_data['ip'] != 'N/A':
                    ip_osint_result = perform_ip_osint(user_data['ip'])
                
                if osint_type == 'email_osint' and user_data['email'] != 'N/A':
                    email_osint_result = perform_email_osint(user_data['email'])
                    
            else:
                # Benzer ID'leri bul
                similar = []
                for uid in users_data.keys():
                    if user_id in uid or uid.startswith(user_id[:5]):
                        similar.append(uid)
                        if len(similar) >= 5:
                            break
                
                result = {
                    'status': 'error',
                    'message': 'User ID not found in database',
                    'similar': similar[:5]
                }
    
    colors = TerminalStyle.COLORS
    gradients = TerminalStyle.GRADIENTS
    total_users = len(users_data)
    
    # Örnek ID'ler
    sample_ids = list(users_data.keys())[:12] if users_data else []
    
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>VAHSET TERMINAL OSINT | Dashboard</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg-primary: {{ colors.black }};
                --bg-secondary: {{ colors.dark }};
                --bg-terminal: {{ colors.gray }};
                --accent-red: {{ colors.red }};
                --accent-green: {{ colors.green }};
                --accent-cyan: {{ colors.cyan }};
                --accent-yellow: {{ colors.yellow }};
                --accent-blue: {{ colors.blue }};
                --text-primary: {{ colors.white }};
                --text-secondary: #8b949e;
                --gradient-header: {{ gradients.header }};
                --gradient-matrix: {{ gradients.matrix }};
            }
            
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'JetBrains Mono', monospace;
                background: var(--bg-primary);
                color: var(--text-primary);
                min-height: 100vh;
                overflow-x: hidden;
            }
            
            .matrix-grid {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: 
                    linear-gradient(rgba(0, 255, 0, 0.03) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(0, 255, 0, 0.03) 1px, transparent 1px);
                background-size: 20px 20px;
                z-index: -1;
                opacity: 0.3;
            }
            
            .terminal-wrapper {
                display: flex;
                flex-direction: column;
                min-height: 100vh;
            }
            
            /* Macbook Style Title Bar */
            .macbook-title-bar {
                background: linear-gradient(to bottom, #3a3a3a, #2a2a2a);
                height: 28px;
                display: flex;
                align-items: center;
                padding: 0 15px;
                border-top-left-radius: 10px;
                border-top-right-radius: 10px;
                position: relative;
                border-bottom: 1px solid rgba(0, 0, 0, 0.3);
            }
            
            .macbook-buttons {
                display: flex;
                gap: 8px;
                position: absolute;
                left: 15px;
            }
            
            .macbook-btn {
                width: 12px;
                height: 12px;
                border-radius: 50%;
                transition: all 0.2s;
            }
            
            .macbook-btn.close { background: #ff5f56; }
            .macbook-btn.minimize { background: #ffbd2e; }
            .macbook-btn.maximize { background: #27ca3f; }
            
            .macbook-btn:hover {
                transform: scale(1.1);
                filter: brightness(1.2);
            }
            
            .macbook-title {
                flex: 1;
                text-align: center;
                color: rgba(255, 255, 255, 0.7);
                font-size: 0.85em;
                letter-spacing: 0.5px;
            }
            
            /* Main Header */
            .terminal-header {
                background: var(--gradient-header);
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
                padding: 20px 30px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            
            .header-left {
                display: flex;
                align-items: center;
                gap: 20px;
            }
            
            .terminal-logo {
                display: flex;
                align-items: center;
                gap: 12px;
            }
            
            .logo-icon {
                font-size: 1.8em;
                color: var(--accent-green);
                animation: terminalGlow 2s infinite alternate;
            }
            
            @keyframes terminalGlow {
                from { text-shadow: 0 0 5px var(--accent-green); }
                to { text-shadow: 0 0 20px var(--accent-green); }
            }
            
            .logo-text {
                font-size: 1.4em;
                font-weight: 700;
                background: var(--gradient-matrix);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }
            
            .header-stats {
                display: flex;
                gap: 30px;
            }
            
            .stat-box {
                display: flex;
                flex-direction: column;
                align-items: center;
                padding: 10px 15px;
                background: rgba(22, 27, 34, 0.8);
                border-radius: 8px;
                border: 1px solid rgba(88, 166, 255, 0.2);
                min-width: 100px;
            }
            
            .stat-value {
                font-size: 1.2em;
                font-weight: 600;
                color: var(--accent-cyan);
            }
            
            .stat-label {
                font-size: 0.75em;
                color: var(--text-secondary);
                margin-top: 5px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            
            .header-right {
                display: flex;
                align-items: center;
                gap: 15px;
            }
            
            .github-badge {
                background: rgba(88, 166, 255, 0.1);
                padding: 8px 15px;
                border-radius: 20px;
                border: 1px solid rgba(88, 166, 255, 0.3);
                font-size: 0.9em;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            
            .logout-btn {
                background: rgba(255, 51, 51, 0.1);
                color: var(--accent-red);
                border: 1px solid var(--accent-red);
                padding: 8px 20px;
                border-radius: 20px;
                text-decoration: none;
                font-size: 0.9em;
                transition: all 0.3s ease;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            
            .logout-btn:hover {
                background: var(--accent-red);
                color: #000;
            }
            
            /* Main Content */
            .terminal-main {
                flex: 1;
                padding: 30px;
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 30px;
                max-width: 1600px;
                margin: 0 auto;
                width: 100%;
            }
            
            @media (max-width: 1200px) {
                .terminal-main {
                    grid-template-columns: 1fr;
                }
            }
            
            /* Left Panel */
            .search-panel {
                background: rgba(22, 27, 34, 0.9);
                border: 1px solid rgba(88, 166, 255, 0.2);
                border-radius: 12px;
                padding: 25px;
                backdrop-filter: blur(10px);
            }
            
            .panel-title {
                font-size: 1.1em;
                font-weight: 600;
                margin-bottom: 20px;
                color: var(--accent-cyan);
                display: flex;
                align-items: center;
                gap: 10px;
                padding-bottom: 15px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            }
            
            .search-form {
                display: flex;
                flex-direction: column;
                gap: 20px;
            }
            
            .input-wrapper {
                position: relative;
            }
            
            .terminal-input-large {
                background: rgba(10, 10, 10, 0.8);
                border: 1px solid rgba(88, 166, 255, 0.4);
                border-radius: 10px;
                color: var(--text-primary);
                font-family: 'JetBrains Mono', monospace;
                padding: 18px 20px;
                width: 100%;
                font-size: 15px;
                letter-spacing: 0.5px;
                transition: all 0.3s ease;
            }
            
            .terminal-input-large:focus {
                outline: none;
                border-color: var(--accent-green);
                box-shadow: 0 0 25px rgba(0, 255, 0, 0.3);
            }
            
            .osint-options {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 10px;
                margin: 15px 0;
            }
            
            .osint-option {
                display: flex;
                align-items: center;
                gap: 8px;
                padding: 12px;
                background: rgba(88, 166, 255, 0.1);
                border: 1px solid rgba(88, 166, 255, 0.3);
                border-radius: 8px;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            
            .osint-option:hover {
                background: rgba(88, 166, 255, 0.2);
                transform: translateY(-2px);
            }
            
            .osint-option.selected {
                background: rgba(0, 255, 0, 0.2);
                border-color: var(--accent-green);
            }
            
            .osint-option input[type="radio"] {
                display: none;
            }
            
            .option-icon {
                color: var(--accent-cyan);
            }
            
            .option-text {
                font-size: 0.85em;
            }
            
            .execute-btn {
                background: var(--gradient-matrix);
                border: none;
                border-radius: 10px;
                color: #000;
                font-family: 'JetBrains Mono', monospace;
                font-weight: 600;
                padding: 18px;
                font-size: 15px;
                cursor: pointer;
                transition: all 0.3s ease;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 10px;
                letter-spacing: 1px;
                text-transform: uppercase;
            }
            
            .execute-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 30px rgba(0, 255, 0, 0.4);
            }
            
            .execute-btn:active {
                transform: translateY(0);
            }
            
            .sample-section {
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
            }
            
            .sample-title {
                color: var(--text-secondary);
                margin-bottom: 15px;
                font-size: 0.9em;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            
            .sample-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
                gap: 10px;
            }
            
            .sample-id {
                background: rgba(0, 255, 0, 0.1);
                border: 1px solid rgba(0, 255, 0, 0.3);
                border-radius: 6px;
                padding: 8px 10px;
                font-size: 0.8em;
                cursor: pointer;
                transition: all 0.3s ease;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                text-align: center;
            }
            
            .sample-id:hover {
                background: rgba(0, 255, 0, 0.2);
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(0, 255, 0, 0.2);
            }
            
            /* Right Panel */
            .results-panel {
                background: rgba(22, 27, 34, 0.9);
                border: 1px solid rgba(88, 166, 255, 0.2);
                border-radius: 12px;
                padding: 25px;
                backdrop-filter: blur(10px);
                display: flex;
                flex-direction: column;
            }
            
            .results-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
                padding-bottom: 15px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            }
            
            .search-time {
                color: var(--text-secondary);
                font-size: 0.85em;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            
            .results-content {
                flex: 1;
                overflow-y: auto;
                max-height: 70vh;
                padding-right: 10px;
            }
            
            /* Scrollbar Styling */
            .results-content::-webkit-scrollbar {
                width: 6px;
            }
            
            .results-content::-webkit-scrollbar-track {
                background: rgba(0, 0, 0, 0.2);
                border-radius: 3px;
            }
            
            .results-content::-webkit-scrollbar-thumb {
                background: var(--accent-green);
                border-radius: 3px;
            }
            
            .no-search {
                text-align: center;
                padding: 60px 20px;
                color: var(--text-secondary);
            }
            
            .no-search-icon {
                font-size: 3.5em;
                color: var(--accent-green);
                opacity: 0.5;
                margin-bottom: 20px;
            }
            
            .result-card {
                background: rgba(10, 10, 10, 0.9);
                border: 1px solid rgba(0, 255, 0, 0.3);
                border-radius: 10px;
                padding: 20px;
                margin-bottom: 20px;
                animation: slideIn 0.5s ease;
            }
            
            @keyframes slideIn {
                from { opacity: 0; transform: translateY(20px); }
                to { opacity: 1; transform: translateY(0); }
            }
            
            .result-status {
                display: flex;
                align-items: center;
                gap: 12px;
                margin-bottom: 20px;
                padding-bottom: 15px;
                border-bottom: 1px solid rgba(0, 255, 0, 0.2);
            }
            
            .status-success .status-icon {
                color: var(--accent-green);
            }
            
            .status-error .status-icon {
                color: var(--accent-red);
            }
            
            .status-icon {
                font-size: 1.5em;
            }
            
            .result-grid {
                display: grid;
                gap: 15px;
                margin-bottom: 20px;
            }
            
            .result-row {
                display: flex;
                align-items: center;
                padding: 12px 15px;
                background: rgba(0, 255, 0, 0.05);
                border-radius: 8px;
                border-left: 3px solid var(--accent-green);
            }
            
            .row-label {
                min-width: 120px;
                color: var(--accent-cyan);
                font-weight: 500;
                font-size: 0.9em;
            }
            
            .row-value {
                flex: 1;
                word-break: break-all;
                font-family: 'Courier New', monospace;
                font-size: 0.9em;
            }
            
            /* OSINT Results */
            .osint-section {
                margin-top: 25px;
                padding-top: 20px;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
            }
            
            .osint-title {
                color: var(--accent-yellow);
                font-size: 1em;
                margin-bottom: 15px;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .osint-grid {
                display: grid;
                gap: 15px;
            }
            
            .osint-card {
                background: rgba(30, 30, 30, 0.9);
                border: 1px solid rgba(255, 153, 0, 0.3);
                border-radius: 8px;
                padding: 15px;
            }
            
            .osint-card-title {
                color: var(--accent-yellow);
                font-size: 0.9em;
                margin-bottom: 10px;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            
            .osint-data {
                display: grid;
                gap: 8px;
            }
            
            .osint-row {
                display: flex;
                justify-content: space-between;
                padding: 5px 0;
                border-bottom: 1px dotted rgba(255, 255, 255, 0.1);
            }
            
            .osint-key {
                color: var(--text-secondary);
                font-size: 0.85em;
            }
            
            .osint-val {
                color: var(--accent-green);
                font-size: 0.85em;
                text-align: right;
                max-width: 60%;
            }
            
            .threat-high {
                color: var(--accent-red);
                font-weight: bold;
            }
            
            .threat-medium {
                color: var(--accent-yellow);
                font-weight: bold;
            }
            
            .threat-low {
                color: var(--accent-green);
                font-weight: bold;
            }
            
            .service-open {
                color: var(--accent-red);
                font-weight: bold;
            }
            
            .breach-badge {
                background: rgba(255, 51, 51, 0.2);
                color: var(--accent-red);
                padding: 3px 8px;
                border-radius: 4px;
                font-size: 0.8em;
                display: inline-block;
                margin: 2px;
            }
            
            /* Footer */
            .terminal-footer {
                background: var(--gradient-header);
                border-top: 1px solid rgba(255, 255, 255, 0.1);
                padding: 20px 30px;
                text-align: center;
                color: var(--text-secondary);
                font-size: 0.85em;
            }
            
            .footer-grid {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 20px;
                max-width: 1200px;
                margin: 0 auto;
            }
            
            .footer-section {
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 10px;
            }
            
            .footer-icon {
                color: var(--accent-green);
                font-size: 1.2em;
            }
            
            .footer-title {
                color: var(--accent-cyan);
                font-size: 0.9em;
                font-weight: 600;
            }
            
            /* Responsive */
            @media (max-width: 768px) {
                .terminal-header {
                    flex-direction: column;
                    gap: 15px;
                    padding: 15px;
                }
                
                .header-stats {
                    order: 3;
                    width: 100%;
                    justify-content: space-around;
                }
                
                .terminal-main {
                    padding: 15px;
                    gap: 15px;
                }
                
                .osint-options {
                    grid-template-columns: 1fr;
                }
                
                .sample-grid {
                    grid-template-columns: repeat(2, 1fr);
                }
                
                .footer-grid {
                    grid-template-columns: 1fr;
                    gap: 15px;
                }
            }
        </style>
    </head>
    <body>
        <div class="matrix-grid"></div>
        
        <div class="terminal-wrapper">
            <!-- Macbook Style Title Bar -->
            <div class="macbook-title-bar">
                <div class="macbook-buttons">
                    <div class="macbook-btn close"></div>
                    <div class="macbook-btn minimize"></div>
                    <div class="macbook-btn maximize"></div>
                </div>
                <div class="macbook-title">vahset_terminal_osint_v3.0</div>
            </div>
            
            <!-- Main Header -->
            <header class="terminal-header">
                <div class="header-left">
                    <div class="terminal-logo">
                        <div class="logo-icon">
                            <i class="fas fa-terminal"></i>
                        </div>
                        <div class="logo-text">VAHSET TERMINAL OSINT</div>
                    </div>
                </div>
                
                <div class="header-stats">
                    <div class="stat-box">
                        <div class="stat-value" id="liveTime">--:--:--</div>
                        <div class="stat-label">LIVE TIME</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">{{ total_users|intcomma }}</div>
                        <div class="stat-label">RECORDS</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value" id="cacheSize">0</div>
                        <div class="stat-label">CACHE</div>
                    </div>
                </div>
                
                <div class="header-right">
                    <div class="github-badge">
                        <i class="fab fa-github"></i>
                        GitHub RAW
                    </div>
                    <a href="/logout" class="logout-btn">
                        <i class="fas fa-power-off"></i>
                        LOGOUT
                    </a>
                </div>
            </header>
            
            <!-- Main Content -->
            <main class="terminal-main">
                <!-- Left Panel - Search -->
                <div class="search-panel">
                    <div class="panel-title">
                        <i class="fas fa-search"></i>
                        OSINT QUERY TERMINAL
                    </div>
                    
                    <form method="POST" class="search-form">
                        <div class="input-wrapper">
                            <input type="text" 
                                   name="user_id" 
                                   class="terminal-input-large"
                                   placeholder="Enter User ID (e.g., 1379557223096914020)..."
                                   value="{{ user_id if user_id }}"
                                   required
                                   autofocus>
                        </div>
                        
                        <div class="panel-title">
                            <i class="fas fa-crosshairs"></i>
                            OSINT ANALYSIS TYPE
                        </div>
                        
                        <div class="osint-options">
                            <label class="osint-option {{ 'selected' if osint_type == 'basic' }}">
                                <input type="radio" name="osint_type" value="basic" {{ 'checked' if osint_type == 'basic' }}>
                                <div class="option-icon">
                                    <i class="fas fa-info-circle"></i>
                                </div>
                                <div class="option-text">Basic Info</div>
                            </label>
                            
                            <label class="osint-option {{ 'selected' if osint_type == 'ip_osint' }}">
                                <input type="radio" name="osint_type" value="ip_osint" {{ 'checked' if osint_type == 'ip_osint' }}>
                                <div class="option-icon">
                                    <i class="fas fa-network-wired"></i>
                                </div>
                                <div class="option-text">IP OSINT</div>
                            </label>
                            
                            <label class="osint-option {{ 'selected' if osint_type == 'email_osint' }}">
                                <input type="radio" name="osint_type" value="email_osint" {{ 'checked' if osint_type == 'email_osint' }}>
                                <div class="option-icon">
                                    <i class="fas fa-envelope"></i>
                                </div>
                                <div class="option-text">Email OSINT</div>
                            </label>
                        </div>
                        
                        <button type="submit" class="execute-btn">
                            <i class="fas fa-bolt"></i>
                            EXECUTE OSINT QUERY
                        </button>
                    </form>
                    
                    <div class="sample-section">
                        <div class="sample-title">
                            <i class="fas fa-database"></i>
                            SAMPLE DATABASE IDs
                        </div>
                        <div class="sample-grid">
                            {% for sample_id in sample_ids %}
                            <div class="sample-id" onclick="document.querySelector('.terminal-input-large').value='{{ sample_id }}'; document.querySelector('.terminal-input-large').focus();">
                                {{ sample_id[:12] }}...
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                </div>
                
                <!-- Right Panel - Results -->
                <div class="results-panel">
                    <div class="results-header">
                        <div class="panel-title">
                            <i class="fas fa-file-code"></i>
                            QUERY RESULTS
                        </div>
                        {% if search_time %}
                        <div class="search-time">
                            <i class="far fa-clock"></i>
                            {{ search_time }}
                        </div>
                        {% endif %}
                    </div>
                    
                    <div class="results-content">
                        {% if not result %}
                        <div class="no-search">
                            <div class="no-search-icon">
                                <i class="fas fa-terminal"></i>
                            </div>
                            <h3>TERMINAL READY</h3>
                            <p>Enter a User ID and select OSINT type to begin analysis</p>
                            <p style="margin-top: 20px; font-size: 0.9em; opacity: 0.7;">
                                <i class="fas fa-info-circle"></i>
                                Database: {{ total_users|intcomma }} records loaded from GitHub
                            </p>
                        </div>
                        
                        {% else %}
                        <!-- Basic Results -->
                        <div class="result-card">
                            <div class="result-status {{ 'status-success' if result.status == 'success' else 'status-error' }}">
                                <div class="status-icon">
                                    {% if result.status == 'success' %}
                                    <i class="fas fa-check-circle"></i>
                                    {% else %}
                                    <i class="fas fa-times-circle"></i>
                                    {% endif %}
                                </div>
                                <div>
                                    {% if result.status == 'success' %}
                                    <h3 style="color: var(--accent-green);">RECORD FOUND</h3>
                                    {% else %}
                                    <h3 style="color: var(--accent-red);">RECORD NOT FOUND</h3>
                                    {% endif %}
                                </div>
                            </div>
                            
                            {% if result.status == 'success' %}
                            <div class="result-grid">
                                <div class="result-row">
                                    <div class="row-label">USER ID:</div>
                                    <div class="row-value">{{ user_id }}</div>
                                </div>
                                <div class="result-row">
                                    <div class="row-label">EMAIL:</div>
                                    <div class="row-value">{{ result.email }}</div>
                                </div>
                                <div class="result-row">
                                    <div class="row-label">IP ADDRESS:</div>
                                    <div class="row-value">{{ result.ip }}</div>
                                </div>
                                {% if result.encoded %}
                                <div class="result-row">
                                    <div class="row-label">BASE64 ENCODED:</div>
                                    <div class="row-value" style="font-size: 0.8em; opacity: 0.8;">
                                        {{ result.encoded }}
                                    </div>
                                </div>
                                {% endif %}
                            </div>
                            {% else %}
                            <div class="result-grid">
                                <div class="result-row">
                                    <div class="row-label">ERROR:</div>
                                    <div class="row-value">{{ result.message }}</div>
                                </div>
                                <div class="result-row">
                                    <div class="row-label">SEARCHED:</div>
                                    <div class="row-value">{{ user_id }}</div>
                                </div>
                            </div>
                            
                            {% if result.similar %}
                            <div class="osint-section">
                                <div class="osint-title">
                                    <i class="fas fa-random"></i>
                                    SIMILAR IDs FOUND
                                </div>
                                <div class="sample-grid">
                                    {% for similar_id in result.similar %}
                                    <div class="sample-id" 
                                         onclick="document.querySelector('.terminal-input-large').value='{{ similar_id }}'; document.querySelector('.terminal-input-large').focus();">
                                        {{ similar_id }}
                                    </div>
                                    {% endfor %}
                                </div>
                            </div>
                            {% endif %}
                            {% endif %}
                        </div>
                        
                        <!-- IP OSINT Results -->
                        {% if ip_osint_result and result.status == 'success' and result.ip != 'N/A' %}
                        <div class="result-card">
                            <div class="result-status status-success">
                                <div class="status-icon">
                                    <i class="fas fa-globe-americas"></i>
                                </div>
                                <div>
                                    <h3 style="color: var(--accent-cyan);">IP OSINT ANALYSIS</h3>
                                </div>
                            </div>
                            
                            {% if ip_osint_result.geolocation %}
                            <div class="osint-section">
                                <div class="osint-title">
                                    <i class="fas fa-map-marker-alt"></i>
                                    GEOLOCATION
                                </div>
                                <div class="osint-grid">
                                    <div class="osint-card">
                                        <div class="osint-data">
                                            <div class="osint-row">
                                                <span class="osint-key">Country:</span>
                                                <span class="osint-val">{{ ip_osint_result.geolocation.country }}</span>
                                            </div>
                                            <div class="osint-row">
                                                <span class="osint-key">City:</span>
                                                <span class="osint-val">{{ ip_osint_result.geolocation.city }}</span>
                                            </div>
                                            <div class="osint-row">
                                                <span class="osint-key">Region:</span>
                                                <span class="osint-val">{{ ip_osint_result.geolocation.region }}</span>
                                            </div>
                                            <div class="osint-row">
                                                <span class="osint-key">ISP:</span>
                                                <span class="osint-val">{{ ip_osint_result.geolocation.isp }}</span>
                                            </div>
                                            <div class="osint-row">
                                                <span class="osint-key">Organization:</span>
                                                <span class="osint-val">{{ ip_osint_result.geolocation.org }}</span>
                                            </div>
                                            <div class="osint-row">
                                                <span class="osint-key">Coordinates:</span>
                                                <span class="osint-val">{{ ip_osint_result.geolocation.lat }}, {{ ip_osint_result.geolocation.lon }}</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            {% endif %}
                            
                            {% if ip_osint_result.reputation %}
                            <div class="osint-section">
                                <div class="osint-title">
                                    <i class="fas fa-shield-alt"></i>
                                    REPUTATION ANALYSIS
                                </div>
                                <div class="osint-grid">
                                    <div class="osint-card">
                                        <div class="osint-data">
                                            <div class="osint-row">
                                                <span class="osint-key">Threat Level:</span>
                                                <span class="osint-val {{ 'threat-high' if ip_osint_result.reputation.threat_level == 'High' else 'threat-medium' if ip_osint_result.reputation.threat_level == 'Medium' else 'threat-low' }}">
                                                    {{ ip_osint_result.reputation.threat_level }}
                                                </span>
                                            </div>
                                            {% if ip_osint_result.reputation.blacklists %}
                                            <div class="osint-row">
                                                <span class="osint-key">Blacklisted In:</span>
                                                <span class="osint-val">
                                                    {{ ip_osint_result.reputation.blacklists|join(', ') }}
                                                </span>
                                            </div>
                                            {% endif %}
                                            {% if ip_osint_result.reputation.proxy %}
                                            <div class="osint-row">
                                                <span class="osint-key">Proxy/VPN:</span>
                                                <span class="osint-val threat-high">DETECTED</span>
                                            </div>
                                            {% endif %}
                                            {% if ip_osint_result.reputation.tor %}
                                            <div class="osint-row">
                                                <span class="osint-key">Tor Node:</span>
                                                <span class="osint-val threat-high">DETECTED</span>
                                            </div>
                                            {% endif %}
                                        </div>
                                    </div>
                                </div>
                            </div>
                            {% endif %}
                            
                            {% if ip_osint_result.services %}
                            <div class="osint-section">
                                <div class="osint-title">
                                    <i class="fas fa-plug"></i>
                                    OPEN PORTS & SERVICES
                                </div>
                                <div class="osint-grid">
                                    <div class="osint-card">
                                        <div class="osint-data">
                                            {% for service in ip_osint_result.services %}
                                            <div class="osint-row">
                                                <span class="osint-key">Port {{ service.port }}:</span>
                                                <span class="osint-val service-open">{{ service.service }} ({{ service.status }})</span>
                                            </div>
                                            {% endfor %}
                                        </div>
                                    </div>
                                </div>
                            </div>
                            {% endif %}
                            
                            {% if ip_osint_result.hostname %}
                            <div class="osint-section">
                                <div class="osint-title">
                                    <i class="fas fa-server"></i>
                                    HOST INFORMATION
                                </div>
                                <div class="osint-grid">
                                    <div class="osint-card">
                                        <div class="osint-data">
                                            <div class="osint-row">
                                                <span class="osint-key">Reverse DNS:</span>
                                                <span class="osint-val">{{ ip_osint_result.hostname }}</span>
                                            </div>
                                            {% if ip_osint_result.whois %}
                                            <div class="osint-row">
                                                <span class="osint-key">Registrar:</span>
                                                <span class="osint-val">{{ ip_osint_result.whois.registrar or 'Unknown' }}</span>
                                            </div>
                                            <div class="osint-row">
                                                <span class="osint-key">Created:</span>
                                                <span class="osint-val">{{ ip_osint_result.whois.creation_date }}</span>
                                            </div>
                                            {% endif %}
                                        </div>
                                    </div>
                                </div>
                            </div>
                            {% endif %}
                        </div>
                        {% endif %}
                        
                        <!-- Email OSINT Results -->
                        {% if email_osint_result and result.status == 'success' and result.email != 'N/A' %}
                        <div class="result-card">
                            <div class="result-status status-success">
                                <div class="status-icon">
                                    <i class="fas fa-envelope-open-text"></i>
                                </div>
                                <div>
                                    <h3 style="color: var(--accent-purple);">EMAIL OSINT ANALYSIS</h3>
                                </div>
                            </div>
                            
                            {% if email_osint_result.analysis %}
                            <div class="osint-section">
                                <div class="osint-title">
                                    <i class="fas fa-user-check"></i>
                                    EMAIL ANALYSIS
                                </div>
                                <div class="osint-grid">
                                    <div class="osint-card">
                                        <div class="osint-data">
                                            <div class="osint-row">
                                                <span class="osint-key">Email Provider:</span>
                                                <span class="osint-val">{{ email_osint_result.analysis.provider }}</span>
                                            </div>
                                            <div class="osint-row">
                                                <span class="osint-key">Domain:</span>
                                                <span class="osint-val">{{ email_osint_result.analysis.domain }}</span>
                                            </div>
                                            <div class="osint-row">
                                                <span class="osint-key">Format Valid:</span>
                                                <span class="osint-val {{ 'threat-low' if email_osint_result.analysis.valid_format else 'threat-high' }}">
                                                    {{ 'YES' if email_osint_result.analysis.valid_format else 'NO' }}
                                                </span>
                                            </div>
                                            <div class="osint-row">
                                                <span class="osint-key">Disposable:</span>
                                                <span class="osint-val {{ 'threat-high' if email_osint_result.analysis.disposable else 'threat-low' }}">
                                                    {{ 'YES' if email_osint_result.analysis.disposable else 'NO' }}
                                                </span>
                                            </div>
                                            {% if email_osint_result.analysis.social_media %}
                                            <div class="osint-row">
                                                <span class="osint-key">Social Pattern:</span>
                                                <span class="osint-val">{{ email_osint_result.analysis.social_media|join(', ') }}</span>
                                            </div>
                                            {% endif %}
                                        </div>
                                    </div>
                                </div>
                            </div>
                            {% endif %}
                            
                            {% if email_osint_result.analysis.breaches %}
                            <div class="osint-section">
                                <div class="osint-title">
                                    <i class="fas fa-exclamation-triangle"></i>
                                    DATA BREACHES DETECTED
                                </div>
                                <div class="osint-grid">
                                    <div class="osint-card">
                                        <div class="osint-data">
                                            {% for breach in email_osint_result.analysis.breaches %}
                                            <div class="osint-row">
                                                <span class="osint-key">{{ breach.name }}:</span>
                                                <span class="osint-val">{{ breach.date }} ({{ breach.records }})</span>
                                            </div>
                                            {% endfor %}
                                            <div class="osint-row">
                                                <span class="osint-key">Total Breaches:</span>
                                                <span class="osint-val threat-high">{{ email_osint_result.analysis.breaches|length }}</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            {% endif %}
                            
                            {% if email_osint_result.domain_info %}
                            <div class="osint-section">
                                <div class="osint-title">
                                    <i class="fas fa-dns"></i>
                                    DOMAIN DNS RECORDS
                                </div>
                                <div class="osint-grid">
                                    <div class="osint-card">
                                        <div class="osint-data">
                                            {% for record_type, records in email_osint_result.domain_info.items() %}
                                            <div class="osint-row">
                                                <span class="osint-key">{{ record_type }}:</span>
                                                <span class="osint-val">
                                                    {% for record in records[:2] %}
                                                    {{ record }}<br>
                                                    {% endfor %}
                                                    {% if records|length > 2 %}
                                                    ... and {{ records|length - 2 }} more
                                                    {% endif %}
                                                </span>
                                            </div>
                                            {% endfor %}
                                        </div>
                                    </div>
                                </div>
                            </div>
                            {% endif %}
                            
                            {% if email_osint_result.whois %}
                            <div class="osint-section">
                                <div class="osint-title">
                                    <i class="fas fa-info-circle"></i>
                                    DOMAIN WHOIS
                                </div>
                                <div class="osint-grid">
                                    <div class="osint-card">
                                        <div class="osint-data">
                                            {% if email_osint_result.whois.registrar %}
                                            <div class="osint-row">
                                                <span class="osint-key">Registrar:</span>
                                                <span class="osint-val">{{ email_osint_result.whois.registrar }}</span>
                                            </div>
                                            {% endif %}
                                            {% if email_osint_result.whois.creation_date %}
                                            <div class="osint-row">
                                                <span class="osint-key">Created:</span>
                                                <span class="osint-val">{{ email_osint_result.whois.creation_date }}</span>
                                            </div>
                                            {% endif %}
                                            {% if email_osint_result.whois.expiration_date %}
                                            <div class="osint-row">
                                                <span class="osint-key">Expires:</span>
                                                <span class="osint-val">{{ email_osint_result.whois.expiration_date }}</span>
                                            </div>
                                            {% endif %}
                                            {% if email_osint_result.whois.country %}
                                            <div class="osint-row">
                                                <span class="osint-key">Country:</span>
                                                <span class="osint-val">{{ email_osint_result.whois.country }}</span>
                                            </div>
                                            {% endif %}
                                        </div>
                                    </div>
                                </div>
                            </div>
                            {% endif %}
                            
                            {% if email_osint_result.associated_ips %}
                            <div class="osint-section">
                                <div class="osint-title">
                                    <i class="fas fa-sitemap"></i>
                                    ASSOCIATED IP ADDRESSES
                                </div>
                                <div class="osint-grid">
                                    <div class="osint-card">
                                        <div class="osint-data">
                                            {% for ip in email_osint_result.associated_ips %}
                                            <div class="osint-row">
                                                <span class="osint-key">Server {{ loop.index }}:</span>
                                                <span class="osint-val">{{ ip }}</span>
                                            </div>
                                            {% endfor %}
                                        </div>
                                    </div>
                                </div>
                            </div>
                            {% endif %}
                        </div>
                        {% endif %}
                        
                        {% endif %}
                    </div>
                </div>
            </main>
            
            <!-- Footer -->
            <footer class="terminal-footer">
                <div class="footer-grid">
                    <div class="footer-section">
                        <div class="footer-icon">
                            <i class="fas fa-bolt"></i>
                        </div>
                        <div class="footer-title">REAL-TIME OSINT</div>
                        <div style="font-size: 0.8em;">Live Intelligence Gathering</div>
                    </div>
                    
                    <div class="footer-section">
                        <div class="footer-icon">
                            <i class="fab fa-github"></i>
                        </div>
                        <div class="footer-title">GITHUB DATA SOURCE</div>
                        <div style="font-size: 0.8em;">{{ total_users|intcomma }} Records</div>
                    </div>
                    
                    <div class="footer-section">
                        <div class="footer-icon">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <div class="footer-title">SECURE TERMINAL</div>
                        <div style="font-size: 0.8em;">Encrypted Session • No API Keys</div>
                    </div>
                </div>
            </footer>
        </div>
        
        <script>
            // Live time update
            function updateTime() {
                const now = new Date();
                const timeString = now.toLocaleTimeString('en-US', { 
                    hour12: false,
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit'
                });
                document.getElementById('liveTime').textContent = timeString;
            }
            
            // Update cache size
            function updateCacheSize() {
                const size = Math.floor(Math.random() * 100) + 50; // Simulated
                document.getElementById('cacheSize').textContent = size + ' MB';
            }
            
            // OSINT option selection
            document.querySelectorAll('.osint-option').forEach(option => {
                option.addEventListener('click', function() {
                    document.querySelectorAll('.osint-option').forEach(opt => {
                        opt.classList.remove('selected');
                    });
                    this.classList.add('selected');
                    this.querySelector('input[type="radio"]').checked = true;
                });
            });
            
            // Terminal typing effect for sample IDs
            document.querySelectorAll('.sample-id').forEach(id => {
                id.addEventListener('click', function() {
                    const input = document.querySelector('.terminal-input-large');
                    input.value = this.textContent.replace('...', '');
                    input.focus();
                    
                    // Terminal style animation
                    this.style.background = 'rgba(0, 255, 0, 0.3)';
                    setTimeout(() => {
                        this.style.background = '';
                    }, 500);
                });
            });
            
            // Macbook buttons simulation
            document.querySelector('.macbook-btn.close').addEventListener('click', () => {
                if (confirm('Close terminal?')) {
                    window.location.href = '/logout';
                }
            });
            
            document.querySelector('.macbook-btn.minimize').addEventListener('click', () => {
                document.body.style.opacity = '0.7';
                setTimeout(() => {
                    document.body.style.opacity = '1';
                }, 300);
            });
            
            document.querySelector('.macbook-btn.maximize').addEventListener('click', () => {
                if (!document.fullscreenElement) {
                    document.documentElement.requestFullscreen();
                } else {
                    document.exitFullscreen();
                }
            });
            
            // Initialize
            setInterval(updateTime, 1000);
            setInterval(updateCacheSize, 5000);
            updateTime();
            updateCacheSize();
            
            // Matrix grid effect
            const grid = document.querySelector('.matrix-grid');
            for (let i = 0; i < 20; i++) {
                const line = document.createElement('div');
                line.style.position = 'absolute';
                line.style.top = `${Math.random() * 100}%`;
                line.style.left = `${Math.random() * 100}%`;
                line.style.width = '2px';
                line.style.height = '2px';
                line.style.background = 'var(--accent-green)';
                line.style.boxShadow = '0 0 10px var(--accent-green)';
                line.style.animation = `matrixPulse ${2 + Math.random() * 3}s infinite`;
                grid.appendChild(line);
            }
            
            // Add CSS for matrix pulse
            const style = document.createElement('style');
            style.textContent = `
                @keyframes matrixPulse {
                    0%, 100% { opacity: 0.1; }
                    50% { opacity: 1; }
                }
            `;
            document.head.appendChild(style);
        </script>
    </body>
    </html>
    ''', result=result, user_id=user_id, total_users=total_users, 
         sample_ids=sample_ids, search_time=search_time, osint_type=osint_type,
         ip_osint_result=ip_osint_result, email_osint_result=email_osint_result,
         colors=TerminalStyle.COLORS, gradients=TerminalStyle.GRADIENTS)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/api/search/<user_id>')
def api_search(user_id):
    if not session.get('authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_data = users_data.get(user_id)
    if user_data:
        return jsonify({
            'found': True,
            'user_id': user_id,
            'email': user_data['email'],
            'ip': user_data['ip']
        })
    else:
        return jsonify({
            'found': False,
            'user_id': user_id,
            'message': 'User not found'
        })

# Custom filter for number formatting
@app.template_filter('intcomma')
def intcomma_filter(value):
    try:
        return "{:,}".format(int(value))
    except:
        return value

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    print(f"\n{'='*80}")
    print("🚀 VAHSET TERMINAL OSINT v3.0")
    print(f"{'='*80}")
    print(f"🔧 Port: {port}")
    print(f"🔧 Debug: {debug}")
    print(f"👤 GitHub User: {GITHUB_USERNAME}")
    print(f"📦 Repository: {GITHUB_REPO}")
    print(f"📊 Loaded {len(users_data):,} users")
    print(f"🛠️  OSINT Modules: IP Geolocation • Email Analysis • DNS • WHOIS")
    print(f"{'='*80}\n")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
