"""
Crypto Utils
"""

import base64
import json
from hashlib import sha256

from helios_lib.exceptions import JsonLoadParserError


def hash_b64(s):
    """
    hash the string using sha1 and produce a base64 output
    removes the trailing "="
    """
    hasher = sha256(s)
    result = base64.b64encode(hasher.digest())[:-1]
    return result


def to_json(d):
    return json.dumps(d, sort_keys=True, separators=(',', ':'))


def from_json(json_str):
    if not json_str: return None
    try:
        return json.loads(json_str)
    except ValueError:
        raise JsonLoadParserError
