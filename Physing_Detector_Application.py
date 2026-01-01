import pandas as pd
import re
from urllib.parse import urlparse, parse_qs
import requests
from bs4 import BeautifulSoup
import whois
import datetime
import joblib
import tkinter as tk
from tkinter import ttk
import threading

def length(url):
    return 1 if len(url) >= 54 else 0

def has_symbol(url):
    return 1 if '@' in url else 0

def dot_count(url):
    return url.count('.')

def hyphen(url):
    domain = urlparse(url).hostname
    return 1 if '-' in domain else 0

def ip(url):
    match = re.search(
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
        r'([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'  # IPv4
        r'(?:http|https|ftp|mailto|file|data|irc)://([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}', url)  #IPv6
    return 1 if match else 0

all_keywords = [

# Account & Login
'login', 'signin', 'account', 'user', 'username', 'password', 
'credential', 'session', 'logon', 'auth',

# Urgency & Verification
'verify', 'update', 'confirm', 'validate', 'required', 'action', 
'alert', 'warning', 'authentication', 'webscr',

# Financial & Banking
'bank', 'banking', 'payment', 'bill', 'invoice', 'wallet', 'finance', 
'transaction', 'card', 'checkout',

# Security & Support
'secure', 'security', 'support', 'admin', 'service', 'online', 
'portal', 'help', 'webadmin', 'srv',

# Common Brands (often phished)
'paypal', 'chase', 'google', 'amazon', 'facebook', 'apple', 'microsoft'
]

def keywords(url):
    domain = urlparse(url).hostname
    return int(any(i in domain for i in all_keywords))

MALICIOUS_TLDS = [
    # High-Risk Generic TLDs
    'xyz', 'top', 'loan', 'club', 'gdn', 'work', 'info', 'biz', 
    'online', 'live', 'site', 'shop',
    
    # Abused Country-Code TLDs
    'tk', 'ml', 'ga', 'cf', 'gq', 'ru', 'cn', 'pw'
]

def tld(url):
    domain = urlparse(url).hostname
    return int(any(i in domain for i in MALICIOUS_TLDS))

def slash_count(url):
    return url.count('/')

def htps(url):
    return 0 if 'https' in url else 1

def int_str_ratio(url):
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return 0
            
        digit_count = sum(c.isdigit() for c in hostname)
        letter_count = sum(c.isalpha() for c in hostname)

        if letter_count == 0:
            return 0
            
        return digit_count / letter_count
    except:
        return 0

URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'rebrand.ly', 'buff.ly', 
    'is.gd', 'soo.gd', 'ow.ly', 'tiny.cc', 'amzn.to', 'youtu.be',
    'lnkd.in', 'fb.me', 'goo.gl', 'bit.do'
]

def shortner(url):
    domain = urlparse(url).hostname
    return int(any(i in domain for i in URL_SHORTENERS))

def query_count(url):
    parsed_url = urlparse(url)
    query_dict = parse_qs(parsed_url.query)
    return len(query_dict)

def rqst(url):

    features = {
        'is_unresponsive': 0,
        'has_http_error': 0,
        'suspicious_form_action': 0,
        'has_password_field': 0,
        'external_link_ratio': 0.0,
        'iframe_count': 0,
        'has_generic_title': 0,
        'has_no_description': 0,
        'right_click_disabled': 0
    }

    try:
        response = requests.get(
            url, 
            timeout=5, 
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        response.raise_for_status()
        html_text = response.text
        soup = BeautifulSoup(response.text, 'html.parser')

        if soup.find('input', attrs={'type': 'password'}):
            features['has_password_field'] = 1
        for form in soup.find_all('form'):
            action = form.get('action', '').lower()
            if not action or action.startswith('http'):
                features['suspicious_form_action'] = 1
                break
            
        all_links = soup.find_all('a', href=True)
        total_links = len(all_links)
        if total_links > 0:
            base_hostname = urlparse(url).hostname
            external_links = 0
            for link in all_links:
                link_hostname = urlparse(link['href']).hostname
                if link_hostname and base_hostname not in link_hostname:
                    external_links += 1
            features['external_link_ratio'] = external_links / total_links
        
        features['iframe_count'] = len(soup.find_all('iframe'))

        title = soup.title.string if soup.title else ''
        if not title or title.lower() in ['login', 'home', 'sign in']:
            features['has_generic_title'] = 1

        if not soup.find('meta', attrs={'name': 'description'}):
            features['has_no_description'] = 1

        if 'oncontextmenu="return false"' in html_text.lower():
            features['right_click_disabled'] = 1        

    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        features['is_unresponsive'] = 1
    except requests.exceptions.HTTPError:
        features['has_http_error'] = 1
    except requests.exceptions.RequestException:
        features['is_unresponsive'] = 1
    except Exception:
        features['is_unresponsive'] = 1

    return features

def who_is(url):
    try:
        host_name = urlparse(url).hostname
        if not host_name:
            return -1
        domain_info = whois.whois(host_name)
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date is None:
            return -1
        
        today = datetime.datetime.now()
        age = (today - creation_date).days

        return age
    
    except Exception:
        return -1
    
def get_all_features(url):
    features_list = []
    features_list.append(length(url))
    features_list.append(has_symbol(url))
    features_list.append(dot_count(url))
    features_list.append(hyphen(url))
    features_list.append(ip(url))
    features_list.append(keywords(url))
    features_list.append(tld(url))
    features_list.append(slash_count(url))
    features_list.append(htps(url))
    features_list.append(int_str_ratio(url))
    features_list.append(shortner(url))
    features_list.append(query_count(url))
    
    request_features = rqst(url)

    features_list.append(request_features['is_unresponsive'])
    features_list.append(request_features['has_http_error'])
    features_list.append(request_features['suspicious_form_action'])
    features_list.append(request_features['has_password_field'])
    features_list.append(request_features['external_link_ratio'])
    features_list.append(request_features['iframe_count'])
    features_list.append(request_features['has_generic_title'])
    features_list.append(request_features['has_no_description'])
    features_list.append(request_features['right_click_disabled'])    

    features_list.append(who_is(url))

    return features_list

try:
    model = joblib.load(r"C:\Users\HP\OneDrive\Desktop\Internship Practice\Project\Physing Websites Identifier\Physing Detector ML Model.joblib")
    TRAINING_COLUMNS = [
    'url_length',
    'has_@',
    'dot_count',
    'has_hyphen',
    'is_ip',
    'has_keyword',
    'malicious_tld',
    'slash_count',
    'https',
    'int_count_ratio',
    'url_shortner',
    'url_query',
    'is_unresponsive',
    'has_http_error',
    'suspicious_form_action',
    'has_password_field',
    'external_link_ratio',
    'iframe_count',
    'has_generic_title',
    'has_no_description',
    'right_click_disabled',
    'age'
    ]
    print('Model loaded successfully!!')
except FileNotFoundError:
    print("Error: Model not found.")
    exit()

if __name__ == "__main__":

    root = tk.Tk()
    root.geometry('500x400')
    root.title('Phishing Detection Application')

    l1 = tk.Label(root, text="Enter the url you want to check")
    l1.pack(padx=10,pady=20)

    f = tk.Frame(root)
    f.pack(padx=10,pady=10)

    e1 = tk.Entry(f, width=40)
    e1.pack(side=tk.LEFT)

    f1 = None
    b2 = None

    def X():
        global f1, b2

        e1.delete(0,tk.END)
        l2.config(text="")

        if f1:
            f1.destroy()
            f1 = None
        
        if b2:
            b2.destroy()
            b2 = None

    b = tk.Button(f, text="x", command=X)
    b.pack(side=tk.LEFT,padx=5)

    def process_url_thread():
        user_url = e1.get()
        try:
            features = get_all_features(user_url)
            live_df = pd.DataFrame([features], columns=TRAINING_COLUMNS)
            prediction = model.predict(live_df)[0]
            probability = model.predict_proba(live_df)[0]

            root.after(0, display_results, prediction, probability, features, None)

        except Exception as e:
            root.after(0, display_results, None, None, None, e)

    def display_results(prediction, probability, features, error):
        global f1, b2, visibility

        progress_bar.stop()
        progress_bar.pack_forget()

        b1.config(state=tk.NORMAL)

        if error :
            l2.config(text=f"An error has occured: {error}", fg='orange')
            return
        
        if prediction == 1:
            l2.config(text=f"Result: This URL is likely PHISHING (Confidence: {probability[1]:.2%})", fg="red")
        else:
            l2.config(text=f"Result: This URL is likely Legitimate (Confidence: {probability[0]:.2%})", fg="green")
          
        f1 = tk.Frame(root, bd=2, relief='groove')
        domain_age = features[21]
        https_used = 'No' if features[8] == 1 else 'Yes'
        has_keywords = 'Yes' if features[5] == 1 else 'No'
        has_malicious_tld = 'Yes' if features[6] == 1 else 'No'
        has_suspicious_form = 'Yes' if features[14] == 1 else 'No'
        has_password_field = 'Yes' if features[15] == 1 else 'No'
        
        tk.Label(f1, text=f"Domain age: {domain_age} days").pack(anchor='w',padx=10)
        tk.Label(f1, text=f"HTTPS used: {https_used}").pack(anchor='w',padx=10)
        tk.Label(f1, text=f"Suspicious keywords: {has_keywords}").pack(anchor='w',padx=10)
        tk.Label(f1, text=f"Suspicious TLD: {has_malicious_tld}").pack(anchor='w',padx=10)
        tk.Label(f1, text=f"Suspicious forms: {has_suspicious_form}").pack(anchor='w',padx=10)
        tk.Label(f1, text=f"Password field: {has_password_field}").pack(anchor='w',padx=10)
        
        def toggle_button():
            global visibility
            if visibility:
                f1.pack_forget()
                b2.config(text="Show Details ▼")
                visibility = False
            else:
                f1.pack(padx=10, pady=10, fill='x')
                b2.config(text="Hide Details ▲")
                visibility = True
        b2 = tk.Button(root, text="Show Details ▼", command=toggle_button)
        b2.pack(pady=5)
        visibility = False

    def check():
        global f1, b2

        if f1:
            f1.destroy()
        if b2:
            b2.destroy()
        
        b1.config(state=tk.DISABLED)

        l2.config(text="Checking URL, please wait...", fg='blue')
        progress_bar.pack(pady=5, padx=20, fill='x')
        progress_bar.start(10)

        thread = threading.Thread(target=process_url_thread)
        thread.daemon = True
        thread.start()

    b1 = tk.Button(root, text="Check", command=check)
    b1.pack(padx=10,pady=10)

    l2 = tk.Label(root, text="")
    l2.pack(padx=10,pady=10)

    progress_bar = ttk.Progressbar(root, orient='horizontal', mode='indeterminate')

    root.mainloop()

# https://secure.amazon.update-login.com
# http://facebok‑secure.account123.com
# https://trusted.com/get?url=https://phish.example/phishing-page
# http://login-google-security.comverify-account-login.xyz/
# https://amazon.in.verify-payment-refund-support.co/
# http://secure-paypal.com.user-authentication-login8765.com/
# https://microsoft-update-verification-login-support.info/
# http://netflix-login-authenticate-recovery-payments.net/
# https://bankofbaroda.secure-login-accountverification.xyz/
# http://hdfcbank-update-kys-confirmation-alert.com/
# http://icicibank.user-login-update-alert98765.net/