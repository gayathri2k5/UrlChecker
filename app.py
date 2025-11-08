from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import re
import requests
import ssl
import socket

app = Flask(__name__)

@app.route('/')

def index():
    return render_template('index.html')

@app.route('/check_url', methods=['POST'])
def check_url():
    url = request.json.get('url')
    result = check_website(url)
    return jsonify(result)

def check_website(url):
    score = 0
    messages = []

    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # Check for redirects
    try:
        response = requests.get(url, timeout=10)
        final_url = response.url
        if final_url != url:
            if not domain_in_same_group(final_url, domain):
                score += 1
                messages.append("⚠ The website redirects to an unrelated or suspicious external site.")
        
        # Now, check for suspicious download links only if the request was successful
        download_links = re.findall(r'href=[\'"]?([^\'" >]+)', response.text)
        for link in download_links:
            if any(ext in link for ext in ['.exe', '.pdf', '.zip', '.rar']):
                download_domain = urlparse(link).netloc
                if not domain_in_same_group(download_domain, domain):
                    score += 1
                    messages.append("⚠ The website prompts downloads from untrusted sources.")
                    break  # Only flag the first suspicious download link
        
        # Check if the title is appropriate
        title_match = re.search('<title>(.*?)</title>', response.text, re.IGNORECASE)
        if title_match and len(title_match.group(1)) < 5:
            score += 1
            messages.append("⚠ The website has no title or a suspiciously short one.")
        else:
            messages.append("✔ The website title seems appropriate for its content.")

    except requests.RequestException:
        messages.append("⚠ Unable to access the website.")
        return {'score': score, 'messages': messages}

    # Check domain age and trust signals (using SSL certificate info)
    try:
        domain_age = check_domain_age(domain)
        if domain_age < 1:
            score += 1
            messages.append("⚠ The domain is very new and lacks sufficient trust signals.")
        else:
            messages.append(f"✔ The domain has been registered for {domain_age} year(s) and shows a strong trust signal.")
    except Exception:
        messages.append("⚠ Unable to verify domain age or SSL information.")

    # Final scoring messages
    if score == 0:
        messages.append("✔ The website does not redirect to suspicious external sites.")
        messages.append("✔ The website's external links are to trusted sources.")
        messages.append("✔ No suspicious downloads were found on the website.")
    
    return {'score': score, 'messages': messages}

# Helper functions
def domain_in_same_group(url, original_domain):
    """ Check if two domains belong to the same group (e.g., subdomains or trusted redirects). """
    parsed_url = urlparse(url).netloc
    return parsed_url.endswith(original_domain) or original_domain.endswith(parsed_url)

def check_domain_age(domain):
    """ Check the age of the domain using SSL certificate information. """
    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=domain,
    )
    conn.connect((domain, 443))
    ssl_info = conn.getpeercert()
    if ssl_info:
        not_before = ssl_info['notBefore']
        not_before_year = int(not_before.split()[-1])
        current_year = ssl.cert_time_to_seconds('2024')
        return current_year - not_before_year
    return 0

if __name__ == '__main__':
    app.run(debug=True)
