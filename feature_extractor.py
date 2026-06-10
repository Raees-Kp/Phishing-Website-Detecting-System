import requests
from bs4 import BeautifulSoup
import whois
from urllib.parse import urlparse
import re


def having_ip_address(url):
    domain = urlparse(url).netloc

    ip_pattern = r"^\d+\.\d+\.\d+\.\d+$"

    if re.match(ip_pattern, domain):
        return 1
    else:
        return -1


def url_length(url):

    if len(url) < 54:
        return -1

    elif len(url) <= 75:
        return 0

    else:
        return 1


def having_at_symbol(url):

    if "@" in url:
        return 1

    return -1

def prefix_suffix(url):

    domain = urlparse(url).netloc

    if "-" in domain:
        return 1

    return -1


def having_sub_domain(url):

    domain = urlparse(url).netloc

    parts = domain.split(".")

    if len(parts) <= 2:
        return -1

    elif len(parts) == 3:
        return 0

    else:
        return 1


def ssl_final_state(url):

    if url.startswith("https://"):
        return 1

    return -1


def shortining_service(url):

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "adf.ly"
    ]

    for service in shorteners:
        if service in url.lower():
            return 1

    return -1


def double_slash_redirecting(url):

    pos = url.rfind("//")

    if pos > 7:
        return 1

    return -1


def age_of_domain(url):

    try:
        domain = urlparse(url).netloc

        domain_info = whois.whois(domain)

        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            return 1
        else:
            return -1

    except:
        return -1
    

def dns_record(url):

    try:
        domain = urlparse(url).netloc

        domain_info = whois.whois(domain)

        if domain_info.domain_name:
            return 1
        else:
            return -1

    except:
        return -1
    

def domain_registration_length(url):

    try:
        domain = urlparse(url).netloc

        domain_info = whois.whois(domain)

        expiration_date = domain_info.expiration_date

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if expiration_date:
            return 1
        else:
            return -1

    except:
        return -1
    

def https_token(url):

    domain = urlparse(url).netloc.lower()

    if "https" in domain:
        return 1

    return -1


def abnormal_url(url):

    try:
        domain = urlparse(url).netloc

        domain_info = whois.whois(domain)

        if domain_info.domain_name:
            return -1
        else:
            return 1

    except:
        return 1


def redirect(url):

    if url.count("//") > 1:
        return 1

    return -1


def port(url):

    parsed = urlparse(url)

    if parsed.port:
        return 1

    return -1


def google_index(url):

    try:
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            return 1
        else:
            return -1

    except:
        return -1
    

def right_click(url):

    try:
        response = requests.get(url, timeout=5)

        if "event.button==2" in response.text:
            return 1

        return -1

    except:
        return -1
    

def iframe(url):

    try:
        response = requests.get(url, timeout=5)

        if "<iframe" in response.text.lower():
            return 1

        return -1

    except:
        return -1
    

def submitting_to_email(url):

    try:
        response = requests.get(url, timeout=5)

        if "mailto:" in response.text.lower():
            return 1

        return -1

    except:
        return -1


def on_mouseover(url):

    try:
        response = requests.get(url, timeout=5)

        if "onmouseover" in response.text.lower():
            return 1

        return -1

    except:
        return -1
    

def popup_window(url):

    try:
        response = requests.get(url, timeout=5)

        html = response.text.lower()

        if "alert(" in html:
            return 1

        return -1

    except:
        return -1
    

def favicon(url):

    try:
        response = requests.get(url, timeout=5)

        soup = BeautifulSoup(response.text, "html.parser")

        icon = soup.find("link", rel=lambda x: x and "icon" in x.lower())

        if icon:
            return -1

        return 1

    except:
        return 1
    

def request_url(url):

    try:
        response = requests.get(url, timeout=5)

        soup = BeautifulSoup(response.text, "html.parser")

        resources = soup.find_all(["img", "audio", "embed", "iframe"])

        if len(resources) == 0:
            return -1

        return 1

    except:
        return 1
    

def url_of_anchor(url):

    try:
        response = requests.get(url, timeout=5)

        soup = BeautifulSoup(response.text, "html.parser")

        anchors = soup.find_all("a")

        if len(anchors) == 0:
            return -1

        return 1

    except:
        return 1
    

def links_in_tags(url):

    try:
        response = requests.get(url, timeout=5)

        soup = BeautifulSoup(response.text, "html.parser")

        links = soup.find_all(["link", "script"])

        if len(links) == 0:
            return -1

        return 1

    except:
        return 1
    

def sfh(url):

    try:
        response = requests.get(url, timeout=5)

        soup = BeautifulSoup(response.text, "html.parser")

        forms = soup.find_all("form")

        if len(forms) == 0:
            return -1

        return 1

    except:
        return 1
    

def links_pointing_to_page(url):

    try:
        response = requests.get(url, timeout=5)

        soup = BeautifulSoup(response.text, "html.parser")

        links = soup.find_all("a")

        count = len(links)

        if count == 0:
            return -1
        elif count <= 2:
            return 0
        else:
            return 1

    except:
        return -1
    

def statistical_report(url):

    suspicious_domains = [
        "at.ua",
        "usa.cc",
        "baltazarpresentes.com.br",
        "pe.hu",
        "esy.es"
    ]

    domain = urlparse(url).netloc.lower()

    for bad_domain in suspicious_domains:
        if bad_domain in domain:
            return 1

    return -1


def extract_features(url):
    
    features = {}
    features["index "] = 0
    features["having_IPhaving_IP_Address "] = having_ip_address(url)
    features["URLURL_Length "] = url_length(url)
    features["Shortining_Service "] = shortining_service(url)
    features["having_At_Symbol "] = having_at_symbol(url)
    features["double_slash_redirecting "] = double_slash_redirecting(url)
    features["Prefix_Suffix "] = prefix_suffix(url)
    features["having_Sub_Domain "] = having_sub_domain(url)
    features["SSLfinal_State "] = ssl_final_state(url)
    features["Domain_registeration_length "] = domain_registration_length(url)
    features["Favicon "] = favicon(url)
    features["port "] = port(url)
    features["HTTPS_token "] = https_token(url)
    features["Request_URL "] = request_url(url)
    features["URL_of_Anchor "] = url_of_anchor(url)
    features["Links_in_tags "] = links_in_tags(url)
    features["SFH "] = sfh(url)
    features["Submitting_to_email "] = submitting_to_email(url)
    features["Abnormal_URL "] = abnormal_url(url)
    features["Redirect "] = redirect(url)
    features["on_mouseover "] = on_mouseover(url)
    features["RightClick "] = right_click(url)
    features["popUpWidnow "] = popup_window(url)
    features["Iframe "] = iframe(url)
    features["age_of_domain "] = age_of_domain(url)
    features["DNSRecord "] = dns_record(url)
    features["web_traffic "] = 0
    features["Page_Rank "] = 0
    features["Google_Index "] = google_index(url)
    features["Links_pointing_to_page "] = links_pointing_to_page(url)
    features["Statistical_report "] = statistical_report(url)
    print(features)
    return features