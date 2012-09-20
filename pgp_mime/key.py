# Copyright

import xml.etree.ElementTree as _etree

from . import LOG as _LOG
from . import crypt as _crypt

import pyassuan
import logging
from pyassuan import common as _common


class Key (object):
    def __init__(self, fingerprint=None):
        self.fingerprint = fingerprint
        # more data to come once gpgme-tool gets keylist XML support

    def __str__(self):
        return '<{} {}>'.format(self.__class__.__name__, self.fingerprint[-8:])

    def __repr__(self):
        return str(self)


def lookup_keys(patterns=None, load=False):
    """Lookup keys matching any patterns listed in ``patterns``.

    >>> print(list(lookup_keys(['pgp-mime-test'])))
    [<Key 4332B6E3>]
    >>> print(list(lookup_keys(['pgp-mime@invalid.com'])))
    [<Key 4332B6E3>]
    >>> print(list(lookup_keys(['4332B6E3'])))
    [<Key 4332B6E3>]
    >>> print(list(lookup_keys(['0x2F73DE2E'])))
    [<Key 4332B6E3>]
    >>> print(list(lookup_keys()))  # doctest: +ELLIPSIS
    [..., <Key 4332B6E3>, ...]

    >>> key = lookup_keys(['2F73DE2E'], load=True)
    >>> print(list(key)[0])
    Traceback (most recent call last):
      ...
    NotImplementedError: gpgme-tool doesn't return keylist data
    """
    _LOG.debug('lookup key: {}'.format(patterns))
    pyassuan.LOG.setLevel(logging.DEBUG)
    client,socket = _crypt.get_client()
    parameters = []
    if patterns:
        args = [' '.join(patterns)]
    else:
        args = []
    try:
        _crypt.hello(client)
        if load:
            client.make_request(_common.Request('KEYLIST', *args))
            rs,result = client.make_request(_common.Request('RESULT'))
        else:
            rs,result = client.make_request(_common.Request('KEYLIST', *args))
    finally:
        _crypt.disconnect(client, socket)
    if load:
        tag_mapping = {
            'fpr': 'fingerprint',
            }
        tree = _etree.fromstring(result.replace(b'\x00', b''))
        if list(tree.findall('.//truncated')):
            raise NotImplementedError("gpgme-tool doesn't return keylist data")
        for signature in tree.findall('.//key'):
            key = Key()
            for child in signature.iter():
                if child == signature:  # iter() includes the root element
                    continue
                attribute = tag_mapping.get(
                    child.tag, child.tag.replace('-', '_'))
                if child.tag in ['fpr']:
                    value = child.text
                else:
                    raise NotImplementedError(child.tag)
                setattr(s, attribute, value)
            yield key
    else:
        for line in result.splitlines():
            line = str(line, 'ascii')
            assert line.startswith('key:'), result
            fingerprint = line.split(':', 1)[1]
            yield Key(fingerprint=fingerprint)
