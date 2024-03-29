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
import pickle
import sys

import requests

########################################################################
### CACHE MANAGEMENT ###################################################
ENV_VAR_NAME_CACHE_DIR = 'cacherequests_cache_dir'
# check for environment variable
if ENV_VAR_NAME_CACHE_DIR in os.environ:
    print(f'Using cache directory from environment variable {ENV_VAR_NAME_CACHE_DIR}')
    CACHE_ROOT_DIR = os.environ[ENV_VAR_NAME_CACHE_DIR]
else:
    print(f'warning: Using cache directory from default value')
    ROOT = os.path.dirname(os.path.realpath(__file__))
    CACHE_ROOT_DIR = os.path.join(ROOT, 'cache')

if not os.path.exists(CACHE_ROOT_DIR):
    os.makedirs(CACHE_ROOT_DIR)
if not os.path.isdir(CACHE_ROOT_DIR):
    raise Exception(f'{CACHE_ROOT_DIR} is not a directory!')

HEADER_CONTENT_CACHE_DIR = os.path.join(CACHE_ROOT_DIR, 'headers')
BODY_CONTENT_CACHE_DIR = os.path.join(CACHE_ROOT_DIR, 'bodies')

MAIN_DATABASE_CACHE_DIR = os.path.join(CACHE_ROOT_DIR, 'main_database')
MAX_CACHE_SIZE_BYTES = 16777216  # 16MB


def store_header_content(
    headers: dict,
):
    if headers is None:
        return None

    key_list = list(headers.keys())
    key_list.sort()

    header_list = []
    for key in key_list:
        header_list.append((key, headers[key]))

    if len(header_list) == 0:
        return None

    header_content_bs = pickle.dumps(header_list)
    header_content_size = len(header_content_bs)

    header_content_md5_hash = hashlib.md5(header_content_bs).hexdigest()
    header_cache_key = f'{header_content_md5_hash}-{header_content_size}'
    cache_filename = f'{header_cache_key}.pickle.gzip'
    cache_filepath = os.path.join(HEADER_CONTENT_CACHE_DIR, cache_filename)

    if not os.path.exists(cache_filepath):
        if not os.path.exists(HEADER_CONTENT_CACHE_DIR):
            os.makedirs(HEADER_CONTENT_CACHE_DIR)
        with gzip.open(cache_filepath, 'wb') as outfile:
            outfile.write(header_content_bs)

    return header_cache_key


def get_headers_content(md5_size_key: str):
    cache_filename = f'{md5_size_key}.pickle.gzip'
    cache_filepath = os.path.join(HEADER_CONTENT_CACHE_DIR, cache_filename)
    if not os.path.exists(cache_filepath):
        return None

    if not os.path.isfile(cache_filepath):
        return None

    header_content_bs = gzip.open(cache_filepath, 'rb').read()
    header_content_list = pickle.loads(header_content_bs)
    headers = {}
    for key, value in header_content_list:
        headers[key] = value

    return headers


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


def get_response_from_cache(
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
            lines.reverse()

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
                if len(quoted_status_code) == 0:
                    status_code = None
                else:
                    unquoted_status_code = urllib.parse.unquote(quoted_status_code)
                    status_code = int(unquoted_status_code)
                ########################################################
                quoted_request_time_ns = cell_list[3]
                if len(quoted_request_time_ns) == 0:
                    request_time_ns = None
                else:
                    unquoted_request_time_ns = urllib.parse.unquote(quoted_request_time_ns)
                    request_time_ns = int(unquoted_request_time_ns)
                ########################################################
                quoted_key = cell_list[4]
                if len(quoted_key) == 0:
                    headers = None
                else:
                    unquoted_key = urllib.parse.unquote(quoted_key)
                    # get headers from cache
                    headers = get_headers_content(unquoted_key)
                ########################################################
                quoted_key = cell_list[5]
                if len(quoted_key) == 0:
                    body_content_bs = None
                else:
                    unquoted_key = urllib.parse.unquote(quoted_key)
                    # get body from cache
                    body_content_bs = get_body_content(unquoted_key)
                ########################################################

                return {
                    'url': url,
                    'method': method,
                    'status_code': status_code,
                    'request_time_ns': request_time_ns,
                    'headers': headers,
                    'content_bs': body_content_bs,
                }
        except Exception as ex:
            if verbose:
                stacktrace = traceback.format_exc()
                print(ex)
                print(stacktrace)

    return None


def give_me_a_new_cache_filepath(max_count=65536):
    for i in range(max_count):
        cache_filename = f'{i}.tsv'
        cache_filepath = os.path.join(MAIN_DATABASE_CACHE_DIR, cache_filename)
        if not os.path.exists(cache_filepath):
            return cache_filepath

    raise Exception(f'The number of existing cache log files is {max_count}!')


def store_body_content(
    body_content_bs: bytes,
):
    if body_content_bs is None:
        return None

    body_content_size = len(body_content_bs)
    if body_content_size == 0:
        return None

    body_content_md5_hash = hashlib.md5(body_content_bs).hexdigest()
    body_cache_key = f'{body_content_md5_hash}-{body_content_size}'
    cache_filename = f'{body_cache_key}.gzip'
    cache_filepath = os.path.join(BODY_CONTENT_CACHE_DIR, cache_filename)

    if not os.path.exists(cache_filepath):
        if not os.path.exists(BODY_CONTENT_CACHE_DIR):
            os.makedirs(BODY_CONTENT_CACHE_DIR)

        with gzip.open(cache_filepath, 'wb') as outfile:
            outfile.write(body_content_bs)

    return body_cache_key


def store_response(
    url: str,
    method: str,
    request_time_ns: int,
    status_code: int,
    headers: dict,
    body_content_bs: bytes,
):
    header_cache_key = store_header_content(headers)
    body_cache_key = store_body_content(body_content_bs)

    quoted_url = urllib.parse.quote(url)
    quoted_method = urllib.parse.quote(method)
    quoted_request_time_ns = urllib.parse.quote(str(request_time_ns))
    quoted_status_code = urllib.parse.quote(str(status_code))
    if header_cache_key is None:
        header_cache_key_quoted = ''
    else:
        header_cache_key_quoted = urllib.parse.quote(header_cache_key)

    if body_cache_key is None:
        body_cache_key_quoted = ''
    else:
        body_cache_key_quoted = urllib.parse.quote(body_cache_key)

    cache_log_line_content = '\t'.join([
        quoted_url,
        quoted_method,
        quoted_status_code,
        quoted_request_time_ns,
        header_cache_key_quoted,
        body_cache_key_quoted,
    ])

    cache_log_line_content = f'{cache_log_line_content}'
    cache_log_line_content_bs = cache_log_line_content.encode('utf-8')
    del cache_log_line_content
    base_log_content_size = len(cache_log_line_content_bs)

    if not os.path.exists(MAIN_DATABASE_CACHE_DIR):
        os.makedirs(MAIN_DATABASE_CACHE_DIR)
    if not os.path.isdir(MAIN_DATABASE_CACHE_DIR):
        raise Exception(f'{MAIN_DATABASE_CACHE_DIR} is not a directory')

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

    if len(child_file_log_list) == 0:
        # no cache file exists
        cache_filepath = give_me_a_new_cache_filepath()
        with open(cache_filepath, 'wb') as outfile:
            outfile.write(cache_log_line_content_bs)

        return

    latest_child_file_log = child_file_log_list[0]
    latest_log_filepath = latest_child_file_log['filepath']
    latest_log_filesize = os.path.getsize(latest_log_filepath)

    if (latest_log_filesize + base_log_content_size) > MAX_CACHE_SIZE_BYTES:
        # the latest cache file is too large
        # make a new cache file
        cache_filepath = give_me_a_new_cache_filepath()
        with open(cache_filepath, 'wb') as outfile:
            outfile.write(cache_log_line_content_bs)

        return

    # get the last character from the file
    with open(latest_log_filepath, 'rb') as infile:
        infile.seek(-1, os.SEEK_END)
        last_character = infile.read(1)

    if last_character == b'\n':
        # append to the latest cache file
        with open(latest_log_filepath, 'ab') as outfile:
            outfile.write(cache_log_line_content_bs)
    else:
        # re check the size sum with 1 more byte
        if (latest_log_filesize + base_log_content_size + 1) > MAX_CACHE_SIZE_BYTES:
            # the latest cache file is too large
            # make a new cache file
            cache_filepath = give_me_a_new_cache_filepath()
            with open(cache_filepath, 'wb') as outfile:
                outfile.write(cache_log_line_content_bs)

            return

        # append to the latest cache file
        with open(latest_log_filepath, 'ab') as outfile:
            outfile.write(b'\n')
            outfile.write(cache_log_line_content_bs)

### END CACHE MANAGEMENT ###############################################
########################################################################


def get_content_size(
    response_obj,
):
    if response_obj is None:
        return None
    if response_obj.headers is None:
        return None

    header_key_list = list(response_obj.headers.keys())
    for header_key in header_key_list:
        if header_key.lower() == 'content-length':
            return int(response_obj.headers[header_key])

    return None


def wrap_requests(
    url: str,
    method='GET',
    timeout=30,
    verbose=True,
    force=False,
    check_body_size=True,
    do_no_cache=False,
):
    try:
        if not force:
            cache_obj = get_response_from_cache(url, method, verbose)
            if cache_obj is not None:
                return cache_obj

        response = requests.request(method, url, timeout=timeout)
        request_time_ns = time.time_ns()

        if check_body_size:
            body_content_size = get_content_size(response)
            if body_content_size is None:
                raise Exception('body_content_size is None')

            real_body_content_size = len(response.content)
            if real_body_content_size != body_content_size:
                raise Exception(f'content-length: {body_content_size} != {real_body_content_size}')

        if not do_no_cache:
            store_response(
                url=url,
                method=method,
                request_time_ns=request_time_ns,
                status_code=response.status_code,
                headers=response.headers,
                body_content_bs=response.content,
            )

        return {
            'url': url,
            'method': method,
            'status_code': response.status_code,
            'headers': response.headers,
            'content_bs': response.content,
            'request_time_ns': request_time_ns,
        }
    except Exception as ex:
        stacktrace = traceback.format_exc()
        if verbose:
            print(ex)
            print(stacktrace)

        raise

########################################################################


def store_header_content_return_cache_data_filepath(
    headers: dict,
):
    retval = {
        'key': None,
        'filepath': None,
    }

    if headers is None:
        return retval

    key_list = list(headers.keys())
    key_list.sort()

    header_list = []
    for key in key_list:
        header_list.append((key, headers[key]))

    if len(header_list) == 0:
        return None

    header_content_bs = pickle.dumps(header_list)
    header_content_size = len(header_content_bs)

    header_content_md5_hash = hashlib.md5(header_content_bs).hexdigest()
    header_cache_key = f'{header_content_md5_hash}-{header_content_size}'
    cache_filename = f'{header_cache_key}.pickle.gzip'
    cache_filepath = os.path.join(HEADER_CONTENT_CACHE_DIR, cache_filename)

    retval['key'] = header_cache_key
    retval['filepath'] = cache_filepath

    if not os.path.exists(cache_filepath):
        if not os.path.exists(HEADER_CONTENT_CACHE_DIR):
            os.makedirs(HEADER_CONTENT_CACHE_DIR)
        with gzip.open(cache_filepath, 'wb') as outfile:
            outfile.write(header_content_bs)

    return retval


def store_body_content_return_cache_data_filepath(
    body_content_bs: bytes,
):
    retval = {
        'key': None,
        'filepath': None,
    }

    if body_content_bs is None:
        return retval

    body_content_size = len(body_content_bs)
    if body_content_size == 0:
        return retval

    body_content_md5_hash = hashlib.md5(body_content_bs).hexdigest()
    body_cache_key = f'{body_content_md5_hash}-{body_content_size}'
    cache_filename = f'{body_cache_key}.gzip'
    cache_filepath = os.path.join(BODY_CONTENT_CACHE_DIR, cache_filename)

    retval['key'] = body_cache_key
    retval['filepath'] = cache_filepath

    if not os.path.exists(cache_filepath):
        if not os.path.exists(BODY_CONTENT_CACHE_DIR):
            os.makedirs(BODY_CONTENT_CACHE_DIR)

        with gzip.open(cache_filepath, 'wb') as outfile:
            outfile.write(body_content_bs)

    return retval


def store_response_return_cache_data_filepath(
    url: str,
    method: str,
    request_time_ns: int,
    status_code: int,
    headers: dict,
    body_content_bs: bytes,
    cache_metadata_write_filepath: str,
    proxy_url=None,
):
    retval = {
        'headers_cache_filepath': None,
        'body_cache_filepath': None,
    }

    _retval = store_header_content_return_cache_data_filepath(headers)
    header_cache_key = _retval['key']
    retval['headers_cache_filepath'] = _retval['filepath']

    _retval = store_body_content_return_cache_data_filepath(body_content_bs)
    body_cache_key = _retval['key']
    retval['body_cache_filepath'] = _retval['filepath']

    quoted_url = urllib.parse.quote(url)
    quoted_method = urllib.parse.quote(method)
    quoted_request_time_ns = urllib.parse.quote(str(request_time_ns))
    quoted_status_code = urllib.parse.quote(str(status_code))
    if header_cache_key is None:
        quoted_header_cache_key = ''
    else:
        quoted_header_cache_key = urllib.parse.quote(header_cache_key)

    if body_cache_key is None:
        quoted_body_cache_key = ''
    else:
        quoted_body_cache_key = urllib.parse.quote(body_cache_key)

    if proxy_url is None:
        quoted_proxy_url = ''
    else:
        quoted_proxy_url = urllib.parse.quote(proxy_url)

    cache_log_line_content = '\t'.join([
        quoted_url,
        quoted_method,
        quoted_status_code,
        quoted_request_time_ns,
        quoted_header_cache_key,
        quoted_body_cache_key,
        quoted_proxy_url,
    ])

    cache_log_line_content = f'{cache_log_line_content}\n'
    cache_log_line_content_bs = cache_log_line_content.encode('utf-8')
    del cache_log_line_content

    with open(cache_metadata_write_filepath, 'ab+') as outfile:
        outfile.write(cache_log_line_content_bs)

    return retval


def get_response_from_cache_return_cache_data_filepath(
    url: str,
    cache_metadata_filepath_list: list,
    method='GET',
    verbose=True,
):
    retval = {
        'url': url,
        'method': method,
        'status_code': None,
        'request_time_ns': None,
        'headers_cache_filepath': None,
        'body_cache_filepath': None,
        'proxy_url': None,
    }

    cache_metadata_file_info_list = []
    for metadata_filepath in cache_metadata_filepath_list:
        file_stat = os.stat(metadata_filepath)
        if not stat.S_ISREG(file_stat.st_mode):
            continue

        modified_time_ns = file_stat.st_mtime_ns
        log_info = {
            'filename': os.path.basename(metadata_filepath),
            'filepath': metadata_filepath,
            'modified_time_ns': modified_time_ns,
        }

        cache_metadata_file_info_list.append(log_info)

    # sort by modified time with the most recently modified first
    cache_metadata_file_info_list.sort(key=lambda x: x['modified_time_ns'], reverse=True)

    for log_info in cache_metadata_file_info_list:
        try:
            content_bs = open(log_info['filepath'], 'rb').read()
            content_str = content_bs.decode('utf-8')
            lines = content_str.split('\n')
            # filter empty lines
            lines = [line for line in lines if line]
            lines.reverse()

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
                if len(quoted_status_code) > 0:
                    unquoted_status_code = urllib.parse.unquote(quoted_status_code)
                    status_code = int(unquoted_status_code)
                    retval['status_code'] = status_code
                ########################################################
                quoted_request_time_ns = cell_list[3]
                if len(quoted_request_time_ns) > 0:
                    unquoted_request_time_ns = urllib.parse.unquote(quoted_request_time_ns)
                    request_time_ns = int(unquoted_request_time_ns)
                    retval['request_time_ns'] = request_time_ns
                ########################################################
                quoted_key = cell_list[4]
                if len(quoted_key) > 0:
                    unquoted_key = urllib.parse.unquote(quoted_key)
                    headers_cache_filepath = os.path.join(
                        HEADER_CONTENT_CACHE_DIR,
                        f'{unquoted_key}.pickle.gzip',
                    )
                    retval['headers_cache_filepath'] = headers_cache_filepath
                ########################################################
                quoted_key = cell_list[5]
                if len(quoted_key) > 0:
                    unquoted_key = urllib.parse.unquote(quoted_key)
                    body_cache_filepath = os.path.join(
                        BODY_CONTENT_CACHE_DIR,
                        f'{unquoted_key}.pickle.gzip',
                    )
                    retval['body_cache_filepath'] = body_cache_filepath
                ########################################################
                if len(cell_list) > 6:
                    quoted_proxy_url = cell_list[6]
                    if len(quoted_proxy_url) > 0:
                        unquoted_proxy_url = urllib.parse.unquote(quoted_proxy_url)
                        retval['proxy_url'] = unquoted_proxy_url

                return retval
        except Exception as ex:
            if verbose:
                stacktrace = traceback.format_exc()
                print(ex)
                print(stacktrace)

    return None


def wrap_requests_return_cache_data_filepath(
    url: str,
    cache_metadata_filepath_list: list,
    cache_metadata_write_filepath: str,
    method='GET',
    timeout=30,
    verbose=True,
    force=False,
    proxy_url=None,
):
    retval = {
        'url': url,
        'method': method,
        'status_code': None,
        'request_time_ns': None,
        'headers_cache_filepath': None,
        'body_cache_filepath': None,
        'proxy_url': proxy_url,
    }

    if not force:
        cache_obj = get_response_from_cache_return_cache_data_filepath(
            url=url,
            cache_metadata_filepath_list=cache_metadata_filepath_list,
            method=method,
            verbose=verbose,
        )

        if cache_obj is not None:
            cache_obj['from_cache'] = True
            return cache_obj

    proxy_dict = None
    if proxy_url is not None:
        proxy_dict = {
            'http': proxy_url,
            'https': proxy_url,
        }

    response = requests.request(method, url, timeout=timeout, proxies=proxy_dict)

    retval['status_code'] = response.status_code

    request_time_ns = time.time_ns()
    retval['request_time_ns'] = request_time_ns

    _retval = store_response_return_cache_data_filepath(
        url=url,
        method=method,
        request_time_ns=request_time_ns,
        status_code=response.status_code,
        headers=response.headers,
        body_content_bs=response.content,
        cache_metadata_write_filepath=cache_metadata_write_filepath,
        proxy_url=proxy_url,
    )

    retval['headers_cache_filepath'] = _retval['headers_cache_filepath']
    retval['body_cache_filepath'] = _retval['body_cache_filepath']

    return retval
