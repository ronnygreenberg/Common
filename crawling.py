from bs4 import BeautifulSoup
from Common.common import *
import urllib3
import requests

pass_403_headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:66.0) Gecko/20100101 Firefox/66.0", #'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:106.0) Gecko/20100101 Firefox/106.0' - might be better
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "DNT": "1", "Connection": "close",
    "Upgrade-Insecure-Requests": "1"}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def find_link(html, search):
    links = html.findAll('a')
    for link in links:
        href = link.attrs.get('href', '')
        if search in href:
            return href
    return None

def get_html_from_link(url):
    return BeautifulSoup(get_request(url).text, 'html.parser')
def get_html_from_file(file_path):
    return BeautifulSoup(read_file(file_path), 'html.parser')
def get_request(url, cookies=dict()):
    return requests.get(url, headers=pass_403_headers, verify=False, timeout=10, allow_redirects=True, cookies=cookies)

import logging
import http.client as http_client
def execute_this_to_print_request_before_sending():
    http_client.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

def wget(file_path, url):
    try:
        response = get_request(url)
        if response.status_code == 200:
            with open(file_path, 'wb') as f:
                f.write(response.content)
        else:
            print(f'failed for {url}, status_code: {response.status_code}')
    except Exception as e:
        print(f'failed for {url}, exception: {str(e)}')

def download_all_links_in_html(url):
    html = get_html_from_link(url)
    links = html.find_all('a')
    for link in links:
        link = link['href']
        wget(link.split('?')[0].split('/')[-1], link)