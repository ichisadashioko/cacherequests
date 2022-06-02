import os
import io
import re
import time
import urllib
import urllib.parse
import traceback
import stat
import gzip
import hashlib

import requests

########################################################################
### CACHE MANAGEMENT ###################################################
ROOT = os.path.dirname(os.path.realpath(__file__))
CACHE_ROOT_DIR = os.path.join(ROOT, 'cache')
HEADER_CONTENT_CACHE_DIR = os.path.join(CACHE_ROOT_DIR, 'headers')
BODY_CONTENT_CACHE_DIR = os.path.join(CACHE_ROOT_DIR, 'bodies')
REQUEST_CACHE_DIR = os.path.join(CACHE_ROOT_DIR, 'requests')

MAIN_DATABASE_CACHE_DIR = os.path.join(CACHE_ROOT_DIR, 'main_database')
MAX_CACHE_SIZE_BYTES = 16777216  # 16MB


def get_headers_content(md5_size_key: str):
    cache_filename = f'{md5_size_key}.gzip'
    cache_filepath = os.path.join(HEADER_CONTENT_CACHE_DIR, cache_filename)
    if not os.path.exists(cache_filepath):
        return None

    if not os.path.isfile(cache_filepath):
        return None

    with gzip.open(cache_filepath, 'rb') as infile:
        content_bs = infile.read()
        return content_bs


def get_body_content(md5_size_key: str):
    cache_filename = f'{md5_size_key}.gzip'
    cache_filepath = os.path.join(BODY_CONTENT_CACHE_DIR, cache_filename)
    if not os.path.exists(cache_filepath):
        return None

    if not os.path.isfile(cache_filepath):
        return None

    with gzip.open(cache_filepath, 'rb') as infile:
        content_bs = infile.read()
        return content_bs


def get_cached_response(
    url: str,
    method='GET',
    verbose=True,
):
    if not os.path.exists(MAIN_DATABASE_CACHE_DIR):
        return None

    if not os.path.isdir(MAIN_DATABASE_CACHE_DIR):
        return None

    child_filename_list = os.listdir(MAIN_DATABASE_CACHE_DIR)
    child_file_log_list = []
    for child_filename in child_filename_list:
        child_filepath = os.path.join(MAIN_DATABASE_CACHE_DIR, child_filename)
        file_stat = os.stat(child_filepath)
        if not stat.S_ISREG(file_stat.st_mode):
            continue

        modified_time_ns = file_stat.st_mtime_ns
        log_info = {
            'filename': child_filename,
            'filepath': child_filepath,
            'modified_time_ns': modified_time_ns,
        }

        child_file_log_list.append(log_info)

    # sort by modified time with the most recently modified first
    child_file_log_list.sort(key=lambda x: x['modified_time_ns'], reverse=True)

    for log_info in child_file_log_list:
        try:
            content_bs = open(log_info['filepath'], 'rb').read()
            content_str = content_bs.decode('utf-8')
            lines = content_str.split('\n')
            # filter empty lines
            lines = [line for line in lines if line]

            for line in lines:
                cell_list = line.split('\t')
                # url, method, status_code, request_time_ns, header_content_md5-size, body_content_md5-size
                if len(cell_list) < 6:
                    continue
                ########################################################
                quoted_url = cell_list[0]
                unquoted_url = urllib.parse.unquote(quoted_url)
                if unquoted_url != url:
                    continue
                ########################################################
                quoted_method = cell_list[1]
                unquoted_method = urllib.parse.unquote(quoted_method)
                if unquoted_method != method:
                    continue
                ########################################################
                quoted_status_code = cell_list[2]
                unquoted_status_code = urllib.parse.unquote(quoted_status_code)
                status_code = int(unquoted_status_code)
                ########################################################
                quoted_request_time_ns = cell_list[3]
                unquoted_request_time_ns = urllib.parse.unquote(quoted_request_time_ns)
                request_time_ns = int(unquoted_request_time_ns)
                ########################################################
                quoted_header_content_md5_size_key = cell_list[4]
                if len(quoted_header_content_md5_size_key) == 0:
                    header_content_bs = None
                else:
                    unquoted_header_content_md5_size_key = urllib.parse.unquote(quoted_header_content_md5_size)
                    # get headers from cache
                    header_content_bs = get_headers_content(unquoted_header_content_md5_size_key)
                ########################################################
                quoted_body_content_md5_size_key = cell_list[5]
                if len(quoted_body_content_md5_size_key) == 0:
                    body_content_bs = None
                else:
                    unquoted_body_content_md5_size_key = urllib.parse.unquote(quoted_body_content_md5_size)
                    # get body from cache
                    body_content_bs = get_body_content(unquoted_body_content_md5_size_key)
                ########################################################

                return {
                    'url': url,
                    'method': method,
                    'status_code': status_code,
                    'request_time_ns': request_time_ns,
                    'header_content_bs': header_content_bs,
                    'body_content_bs': body_content_bs,
                }
        except Exception as ex:
            if verbose:
                stacktrace = traceback.format_exc()
                print(ex)
                print(stacktrace)

    return None


def store_header_content(
    headers: dict,
):
    key_list = list(headers.keys())
    key_list.sort()

    normalized_header_content = ''
    is_first = True
    for key in key_list:
        header_line = f'{key}: {headers[key]}'
        if is_first:
            is_first = False
            normalized_header_content += header_line
        else:
            normalized_header_content += f'\n{header_line}'

    normalized_header_content_bs = normalized_header_content.encode('utf-8')
    header_content_size = len(normalized_header_content_bs)
    if header_content_size == 0:
        return None

    header_content_md5_hash = hashlib.md5(normalized_header_content_bs).hexdigest()
    header_content_md5_size_key = f'{header_content_md5_hash}-{header_content_size}'
    cache_filename = f'{header_content_md5_size_key}.gzip'
    cache_filepath = os.path.join(HEADER_CONTENT_CACHE_DIR, cache_filename)

    if not os.path.exists(cache_filepath):
        if not os.path.exists(HEADER_CONTENT_CACHE_DIR):
            os.makedirs(HEADER_CONTENT_CACHE_DIR)
        with gzip.open(cache_filepath, 'wb') as outfile:
            outfile.write(normalized_header_content_bs)

    return header_content_md5_size_key


def store_body_content(
    body_content_bs: bytes,
):
    body_content_size = len(body_content_bs)
    if body_content_size == 0:
        return None

    body_content_md5_hash = hashlib.md5(body_content_bs).hexdigest()
    body_content_md5_size_key = f'{body_content_md5_hash}-{body_content_size}'
    cache_filename = f'{body_content_md5_size_key}.gzip'
    cache_filepath = os.path.join(BODY_CONTENT_CACHE_DIR, cache_filename)

    if not os.path.exists(cache_filepath):
        if not os.path.exists(BODY_CONTENT_CACHE_DIR):
            os.makedirs(BODY_CONTENT_CACHE_DIR)

        with gzip.open(cache_filepath, 'wb') as outfile:
            outfile.write(body_content_bs)

    return body_content_md5_size_key


def store_response(
    url: str,
    method: str,
    request_time_ns: int,
    status_code: int,
    headers: dict,
    body_content_bs: bytes,
):
    header_content_md5_size_key = store_header_content(headers)
    body_content_md5_size_key = store_body_content(body_content_bs)

    quoted_url = urllib.parse.quote(url)
    quoted_method = urllib.parse.quote(method)
    quoted_request_time_ns = urllib.parse.quote(str(request_time_ns))
    quoted_status_code = urllib.parse.quote(str(status_code))
    if header_content_md5_size_key is None:
        quoted_header_content_md5_size_key = ''
    else:
        quoted_header_content_md5_size_key = urllib.parse.quote(header_content_md5_size_key)

    if body_content_md5_size_key is None:
        quoted_body_content_md5_size_key = ''
    else:
        quoted_body_content_md5_size_key = urllib.parse.quote(body_content_md5_size_key)

    # TODO

### END CACHE MANAGEMENT ###############################################
########################################################################


def wrap_requests(
    url: str,
    method='GET',
    verbose=True,
    force=False,
):
    try:
        if method == 'GET':
            response = requests.get(url)
            request_time_ns = time.time_ns()

            {
                'method': method,
                'url': url,
                'status_code': response.status_code,
                'headers': response.headers,
                'content_bs': response.content,
            }
    except Exception as ex:
        stacktrace = traceback.format_exc()
        if verbose:
            print(ex)
            print(stacktrace)
