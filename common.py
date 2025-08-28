import os
import requests
import urllib3
import re
# import tldextract
from threading import Lock
import datetime
# from baseconv import BaseConverter
from uuid import UUID
from concurrent.futures import ThreadPoolExecutor, as_completed
import functools
import subprocess
import time
from urllib.parse import unquote
from tqdm import tqdm

project_root = os.path.dirname(os.path.abspath(__file__))

def read_list_of_dictionaries(path):
    for item in read_file(path):
        try:
            yield json.loads(item)
        except Exception as e:
            print(f'item that failed is: {item}')
            raise e

def write_lines_to_file(path, input_list, overwrite_file = False):
    write_text_to_file(path, '\n'.join(input_list), overwrite_file)

read_file_lock = Lock()
def read_file(path):
    read_file_lock.acquire()
    try:
        with open(path, 'r', encoding='utf-8') as file:
            for line in file:
                yield line
    finally:
        read_file_lock.release()

def read_file_special_case(path):
    content = ''
    for line in read_file(path):
        content += line + "\n"
    return content

file_write_lock = Lock()
def write_text_to_file(path, input, overwrite_file = False):
    file_write_lock.acquire()
    try:
        path = pathlib.Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        mode = 'a'
        if overwrite_file is True:
            mode = 'w'
        with open(path, mode, encoding='utf-8') as file:
            if input != "":
                file.write(input + '\n')
            else:
                file.write(input)
    finally:
        file_write_lock.release()

def benchmark_code(start,name):
    end = time.time()
    if round(end - start) > 0:
        write_text_to_file('benchmarks.txt', f'{datetime.datetime.now()}. took {round(end - start)}s for {name}')

def read_in_chunks(file_object, chunk_size=1024):
    #Lazy function (generator) to read a file piece by piece.
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data

import re
def run_regex(pattern, inputs):
    for input in inputs:
        result = re.compile(pattern).search(input)
        if result is not None:
            print(result.group(0))
        else:
            print(f'regex didn`t pass for line')

def get_domains_from_key(path):
    domains = []
    for line in read_file_lines(path):
        domains.append(tldextract.extract(line.split(': [')[0]).registered_domain) #keep this line!
    return list(set(domains))

import ast
def get_domains_from_value(line):
    urls = line.split(': ')[1]
    url_list = ast.literal_eval(urls)
    domains = []
    for url in url_list:
        domains.append(tldextract.extract(url).registered_domain)
    return domains

def get_domains_from_values(path):
    domain_counter = dict()
    for line in read_file_lines(path):
        line_domains = []  # one match per domain per line, similar to grep
        domains = get_domains_from_value(line)
        for domain in domains:
            if domain not in domain_counter:
                domain_counter[domain] = 0
            if not domain in line_domains:
                domain_counter[domain] += 1
                line_domains.append(domain)
    return domain_counter

place_holders = []
def load_placeholder_file_once():
    global place_holders
    if len(place_holders) == 0:
        place_holders = read_file_lines(rf'{root_project_path}\common/placeholders')

def print_list(some_list):
    for s in some_list:
        print(s)

def print_dict_with_list_value_unique(dict):
    for key in dict:
        print(key)
        print_list(dict[key])

def print_dict(dict):
    for key in dict:
        print(f'{key}: {dict[key]}')

def sort_counter_dict(counter_dict):
    return dict(sorted(counter_dict.items(), key=lambda item: len(counter_dict[item]), reverse=True))

def print_counter_dict(counter_dict):
    for key in counter_dict:#sort_counter_dict(counter_dict):
        print(f'{key}: {len(counter_dict[key])}')

def search_in_file(search, file_path):
    for i, line in enumerate(read_file_lines(file_path)):
        if search in line:
            return (i, line)
    return -1

def parse_grep_lines(lines):
    once = True
    results = dict()
    print_warning_once = True
    # try:
    for i, line in enumerate(lines):
        parts = line.split(': ', 1)
        key = parts[0]
        value = parts[1]
        while 'datetime' in value:
            if print_warning_once:
                print_warning_once = False
                print('removed datetime values from lines!!')
            index = value.index('datetime')
            end_index = value.index(')', index) + 2
            value = value.replace(value[index: end_index], '\'\'')
        values = ast.literal_eval(value)
        if key in results:
            if once:
                once = False
                print('merged keys in your list!')
            results[key].extend(values)
        else:
            results[key] = values
    #good if you parsing a very large file
    # except Exception as e:
    #     print(f'parse failed for line number {i} {line}, execption: {e}')
    #     return results
    return results

def parse_grep_file(file_path):
    return parse_grep_lines(read_file_lines(file_path))

pass_403_headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "DNT": "1", "Connection": "close",
    "Upgrade-Insecure-Requests": "1"}
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
def get_request(url):
    try:
        response = requests.get(url, headers=pass_403_headers, verify=False, timeout=10, allow_redirects=True)
        if response.status_code == 200:
            return [url, True, response]

        return [url, False, response.status_code]
    except Exception as e:
        return [url, False, e]

def get_last_modified_file(path):
    files = os.listdir(path)
    max_value = 0
    for file in files:
        file_path = fr'{path}/{file}'
        if os.path.isdir(file_path):
            continue
        last_modified = os.path.getmtime(file_path)
        if last_modified > max_value:
            max_value = last_modified
            last_file = file_path
    return last_file

def search_value_in_list(value, lines, exact = False):
    results = []
    for line in lines:
        if exact and value == line:
            results.append(line)
        elif not exact and value in line:
            results.append(line)
    return results

def search_list_in_list(a, b):
    results = []
    for b_item in b: #b first to maintain line order
        for a_item in a:
            if a_item in b_item:
                results.append(b_item)
    return results

def search_list_in_value(lines, value, exact = False):
    results = []
    for line in lines:
        if exact and value == line:
            results.append(line)
        elif not exact and line in value:
            results.append(line)
    return results

def search_regex(regex, value):
    compiled_regex = re.compile(regex)
    return compiled_regex.findall(value)

def dict_compare(d1, d2):
    d1_keys = set(d1.keys())
    d2_keys = set(d2.keys())
    shared_keys = d1_keys.intersection(d2_keys)
    added = d1_keys - d2_keys
    removed = d2_keys - d1_keys
    same = set(o for o in shared_keys if d1[o] == d2[o])
    for key in same:
        if list(set(d1[key]) - set(d2[key])):
            print(d2[key])
            print('---')
    # modified = {o : (d1[o], d2[o]) for o in shared_keys if d1[o] != d2[o]}
    return added, removed#, modified#, sameg

#key: values per line
import json

#https://stackoverflow.com/questions/32419433/attributeerror-datetime-date-object-has-no-attribute-dict
#https://stackoverflow.com/questions/3768895/how-to-make-a-class-json-serializable
def json_default(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, datetime.date):
        return dict(year=value.year, month=value.month, day=value.day)
    try:
        return value.__dict__
    except AttributeError:
        return str(value).replace('"', '\'')
def dumps_json(json_data):
    return json.dumps(json_data, default=json_default)

def dump_json(path, json_data, overwrite_file=False):
    write_text_to_file(path, dumps_json(json_data), overwrite_file)

def dump_json_overwrite(path, json_data, overwrite=True):
    write_text_to_file(path, json.dumps(json_data, indent=4, default=str), overwrite)

def dump_list_of_dictionaries(path, json_data, overwrite=False):
    write_text_to_file(path, "\n".join(json.dumps(i) for i in json_data), overwrite)

load_json_lock = Lock()
def load_json(path, encoding='utf-8'):
    load_json_lock.acquire()
    try:
        with open(path, 'r', encoding=encoding) as file:
            return json.load(file)
    except Exception as e:
        if '\'utf-8\' codec can\'t decode byte' in str(e) and encoding != 'utf-16':
            load_json_lock.release()
            return load_json(path, 'utf-16')
        raise e
    finally:
        if load_json_lock.locked():
            load_json_lock.release()

#not meant to deal with jsons with wrong format to prevent false negatives!
def load_json_or_default(json_path):
    if os.path.exists(json_path):
        return load_json(json_path)
    else:
        return {}

def find_in_dict_by_value(dict, search):
    matched_keys = []
    for key in dict:
        for value in dict[key]:
            if search == value:
                matched_keys.append(key)
    return matched_keys

def reverse_dictionary_string_value(dictionary):
    output = dict()
    for key in dictionary:
        output[dictionary[key]] = key
    return output

def reverse_dictionary_list_value(dictionary):
    new = dict()
    for key in dictionary:
        for value in dictionary[key]:
            new[value] = new.get(value, [])
            new[value].append(key)
    return new

def build_dictionary_from_list_of_dictionaries(list_of_dicts, key_to_use_as_key):
    output = dict()
    for dictionary in list_of_dicts:
        if key_to_use_as_key not in dictionary:
            continue

        if isinstance(dictionary[key_to_use_as_key], list):
            for member in dictionary[key_to_use_as_key]:
                output[member] = output.get(member, [])
                output[member].append(dictionary)
        elif isinstance(dictionary[key_to_use_as_key], dict):
            for member in dictionary[key_to_use_as_key].keys():
                output[member] = output.get(member, [])
                output[member].append(dictionary)
        else:
            output[dictionary[key_to_use_as_key]] = dictionary
    return output

def build_dictionary_from_list_of_dictionaries_with_value(list_of_dicts, key_to_use_as_key, key_to_use_as_value):
    output = dict()
    for dictionary in list_of_dicts:
        if key_to_use_as_key not in dictionary:
            continue

        if isinstance(dictionary[key_to_use_as_key], list):
            for member in dictionary[key_to_use_as_key]:
                output[member] = output.get(member, [])
                output[member].append(dictionary[key_to_use_as_value])
        elif isinstance(dictionary[key_to_use_as_key], dict):
            for member in dictionary[key_to_use_as_key].keys():
                output[member] = output.get(member, [])
                output[member].append(dictionary[key_to_use_as_value])
        else:
            output[dictionary[key_to_use_as_key]] = dictionary[key_to_use_as_value]
    return output

def find_nested_key(data, target, results, only_uniques = False):
    for key, value in data.items():
        if key == target:
            if isinstance(value, list):
                results.extend(value)
            elif value is not None:
                results.append(value)
        elif isinstance(value, list):
            for member in value:
                if isinstance(member, dict):
                    find_nested_key(member, target, results)
        elif isinstance(value, dict):
            find_nested_key(value, target, results)

    if not only_uniques:
        return results

    unique_results = list(set(results))
    if len(unique_results) == 1:
        return unique_results[0]
    return unique_results


#https://awsteele.com/blog/2020/09/26/aws-access-key-format.html
def get_account_number_from_iam_id(identifier):
    myconv = BaseConverter('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567') #not generic base32
    account_id = 2 * (int(myconv.decode(identifier[4:12])) - int(myconv.decode('QAAAAAAA')))
    if identifier[12] >= 'Q':
        account_id += 1
    return account_id


#slow because we use find_nested_key, because we don't know the exact location of the key in the dicts
def filter_dicts_by_value(dict_list, inner_key, search_value, exact_match=False):
    dicts = []
    for dict in dict_list:
        for value in find_nested_key(dict, inner_key, []):
            if exact_match or type(search_value) not in [str, list, dict]:
                if search_value == value:
                    dicts.append(dict)
            else:
                if search_value in value:
                    dicts.append(dict)
    #will return duplicate dicts if they contain the value multiple times, this is to prevent confusion
    return [i for n, i in enumerate(dicts) if i not in dicts[n + 1:]]

def get_key_by_value_from_dict(dict, search_value):
    keys = []
    for key in dict:
        for value in dict[key]:
            if search_value in value:
                keys.append(key)
    return list(set(keys))

def get_all_values_from_list_of_dicts(dict, key, delete_duplicates=True):
    values = []
    for member in dict:
        values.extend(find_nested_key(member, key, []))
    if delete_duplicates:
        return list(set(values))
    return values

def get_values_by_keys(dictionary_input, keys):
    results = []
    for member in dictionary_input:
        output = dict()
        for key in keys:
            output[key] = find_nested_key(member, key, [], True)
        results.append(output)
    return results

def merge_to_dict(d1, key, merge_object, merge_type):
    if key in d1:
        if merge_type == 'dict':
            for k2 in d1[key]:
                if k2 in merge_object:
                    original_len = len(d1[key][k2])
                    d1[key][k2].extend(merge_object[k2])
                    new_len = len(d1[key][k2])
                    if new_len < original_len:
                        raise Exception('merge deleted results!')
        elif merge_type == 'list':
            original_len = len(d1[key])
            d1[key] = d1[key] + merge_object
            new_len = len(d1[key])
            if new_len < original_len:
                raise Exception('merge deleted results!')
    else:
        d1[key] = merge_object
    return d1

def get_domains_from_urls(urls):
    domains = []
    for url in urls:
        domain = tldextract.extract(url).registered_domain
        if domain == '' or domain == ' ':
            print(url, 'couldnt extract domain')
        domains.append(domain)
    return list(set(domains))

def get_full_domain_for_url(url):
    extract_result = tldextract.extract(url)
    join_params = [extract_result.subdomain, extract_result.domain, extract_result.suffix]
    if extract_result.subdomain == '':
        join_params.pop(0)
    return '.'.join(join_params)

def json_encoder(o):
    if type(o) is datetime.date or type(o) is datetime.datetime:
        return o.isoformat()

import pathlib
def grep_code():
    for file in [os.path.join(dp, f) for dp, dn, filenames in os.walk('.', ) for f in filenames]:
        if 'site-packages' in file:
            continue

        if pathlib.Path(file).suffix not in ['', '.txt', '.py']:
            continue

        try:
            for line in read_file_lines(file):
                if 're.compile' in line.lower() or 'grep' in line.lower():
                    write_text_to_file('grep_code.txt', f'{file}: {line}')
        except Exception as e:
            pass
            #print('failed to read file', file, str(e))

def append_to_prop_if_not_already_there(dict, prop, value):
    dict[prop] = dict.get(prop, [])
    if value not in dict[prop]:
        dict[prop].append(value)

def get_files_in_dir(dir):
    return [os.path.join(dp, f) for dp, dn, filenames in os.walk(dir,) for f in filenames]

#https://stackoverflow.com/questions/53847404/how-to-check-uuid-validity-in-python
def is_valid_uuid(uuid_to_test, version=4):
    try:
        uuid_obj = UUID(uuid_to_test, version=version)
    except ValueError:
        return False
    return str(uuid_obj) == uuid_to_test

def enumerate_file_no_locks(path):
    i = -1
    for line in open(path, encoding='utf-8'):
        i += 1
        yield i, line
def substring(text, start, end):
    try:
        start = text.find(start) + len(start)
        end = text[start:].find(end)
        return text[start:start+end]
    except Exception as e:
        return -1

#DONT DELETE THIS SPECIFIC FUNCTION
def try_parse_float(data):
    try:
        return float(data)
    except ValueError:
        pass

#https://www.geeksforgeeks.org/find-average-list-python/
def avg(lst):
    if lst == []:
        raise Exception('lst is empty! no relevant foods!')
    return sum(lst) / len(lst)

# wrap the entire contents of func using try except Exception as e: traceback.format_exc()
def do_using_threads(threads_count, func, list_to_map, kwargs=None):
    if kwargs is None:
        kwargs = {}

    results = []
    with tqdm(total=len(list_to_map)) as pbar:
        with ThreadPoolExecutor(max_workers=threads_count) as pool:
            futures = [pool.submit(func, item, **kwargs) for item in list_to_map]
            for future in as_completed(futures):
                results.append(future.result())
                pbar.update(1)
    return results

def are_dicts_different(dict1, dict2):
    diff_dict1 = {key: dict1[key] for key in dict1 if key not in dict2}
    diff_dict2 = {key: dict2[key] for key in dict2 if key not in dict1}
    diff_values = {key: (dict1[key], dict2[key]) for key in dict1 if key in dict2 and dict1[key] != dict2[key]}
    return diff_dict1 is not {} and diff_dict2 is not {} and diff_values is not {}

def url_decode(thing):
    return unquote(thing)

def get_week_day(date):
    return date.weekday() + 2  # Weekday function starts with Monday as 0... so I added +2 to normalize

def append_with_lock(thingi, inserti, lock):
    with lock:
        thingi.append(inserti)

def add_with_lock(thingi, inserti, lock):
    with lock:
        thingi.add(inserti)