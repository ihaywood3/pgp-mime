# Copyright

import functools as _functools
import xml.etree.ElementTree as _etree

from . import LOG as _LOG
from . import crypt as _crypt

import pyassuan
import logging
from pyassuan import common as _common


@_functools.total_ordering
class SubKey (object):
    """The crypographic key portion of an OpenPGP key.
    """
    def __init__(self, fingerprint=None):
        self.fingerprint = fingerprint

    def __str__(self):
        return '<{} {}>'.format(type(self).__name__, self.fingerprint[-8:])

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        if self.fingerprint and hasattr(other, 'fingerprint'):
            return self.fingerprint == other.fingerprint
        return id(self) == id(other)

    def __lt__(self, other):
        if self.fingerprint and hasattr(other, 'fingerprint'):
            return self.fingerprint < other.fingerprint
        return id(self) < id(other)

    def __hash__(self):
        return int(self.fingerprint, 16)


@_functools.total_ordering
class UserID (object):
    def __init__(self, uid=None, name=None, email=None, comment=None):
        self.uid = uid
        self.name = name
        self.email = email
        self.comment = comment

    def __str__(self):
        return '<{} {}>'.format(type(self).__name__, self.name)

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        if self.uid and hasattr(other, 'uid'):
            return self.uid == other.uid
        return id(self) == id(other)

    def __lt__(self, other):
        if self.uid and hasattr(other, 'uid'):
            return self.uid < other.uid
        return id(self) < id(other)

    def __hash__(self):
        return hash(self.uid)


@_functools.total_ordering
class Key (object):
    def __init__(self, subkeys=None, uids=None):
        revoked = False
        expired = False
        disabled = False
        invalid = False
        can_encrypt = False
        can_sign = False
        can_certify = False
        can_authenticate = False
        is_qualified = False
        secret = False
        protocol = None
        issuer = None
        chain_id = None
        owner_trust = None
        if subkeys is None:
            subkeys = []
        self.subkeys = subkeys
        if uids is None:
            uids = []
        self.uids = uids

    def __str__(self):
        return '<{} {}>'.format(
            type(self).__name__, self.subkeys[0].fingerprint[-8:])

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        other_subkeys = getattr(other, 'subkeys', None)
        if self.subkeys and other_subkeys:
            return self.subkeys[0] == other.subkeys[0]
        return id(self) == id(other)

    def __lt__(self, other):
        other_subkeys = getattr(other, 'subkeys', None)
        if self.subkeys and other_subkeys:
            return self.subkeys[0] < other.subkeys[0]
        return id(self) < id(other)

    def __hash__(self):
        return int(self.fingerprint, 16)


def lookup_keys(patterns=None, **kwargs):
    """Lookup keys matching any patterns listed in ``patterns``.

    >>> import pprint

    >>> key = list(lookup_keys(['pgp-mime-test']))[0]
    >>> key
    <Key 4332B6E3>
    >>> key.subkeys
    [<SubKey 4332B6E3>, <SubKey 2F73DE2E>]
    >>> key.uids
    [<UserID pgp-mime-test>]
    >>> key.uids[0].uid
    'pgp-mime-test (http://blog.tremily.us/posts/pgp-mime/) <pgp-mime@invalid.com>'
    >>> key.can_encrypt
    True
    >>> key.protocol
    'OpenPGP'

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
    """
    _LOG.debug('lookup key: {}'.format(patterns))
    client = _crypt.get_client(**kwargs)
    parameters = []
    if patterns:
        args = [' '.join(patterns)]
    else:
        args = []
    try:
        _crypt.hello(client)
        rs,result = client.make_request(_common.Request('KEYLIST', *args))
    finally:
        _crypt.disconnect(client)
    tag_mapping = {
        }
    tree = _etree.fromstring(result.replace(b'\x00', b''))
    for key in tree.findall('.//key'):
        k = Key()
        for child in key:
            attribute = tag_mapping.get(
                child.tag, child.tag.replace('-', '_'))
            if child.tag in [
                'revoked', 'expired', 'disabled', 'invalid', 'can-encrypt',
                'can-sign', 'can-certify', 'can-authenticate', 'is-qualified',
                'secret', 'revoked']:
                # boolean values
                value = child.get('value')
                if not value.startswith('0x'):
                    raise NotImplementedError('{} value {}'.format(
                            child.tag, value))
                value = int(value, 16)
                value = bool(value)
            elif child.tag in [
                'protocol', 'owner-trust']:
                value = child.text
            elif child.tag in ['issuer', 'chain-id']:
                # ignore for now
                pass
            elif child.tag in ['subkeys', 'uids']:
                parser = globals()['_parse_{}'.format(attribute)]
                value = parser(child)
            else:
                raise NotImplementedError(child.tag)
            setattr(k, attribute, value)
        yield k

def _parse_subkeys(element):
    tag_mapping = {
        'fpr': 'fingerprint',
        }
    subkeys = []
    for subkey in element:
        s = SubKey()
        for child in subkey.iter():
            if child == subkey:  # iter() includes the root element
                continue
            attribute = tag_mapping.get(
                child.tag, child.tag.replace('-', '_'))
            if child.tag in [
                'fpr']:
                value = child.text
            else:
                raise NotImplementedError(child.tag)
            setattr(s, attribute, value)
        subkeys.append(s)
    return subkeys

def _parse_uids(element):
    tag_mapping = {
        }
    uids = []
    for uid in element:
        u = UserID()
        for child in uid.iter():
            if child == uid:  # iter() includes the root element
                continue
            attribute = tag_mapping.get(
                child.tag, child.tag.replace('-', '_'))
            if child.tag in [
                'uid', 'name', 'email', 'comment']:
                value = child.text
            else:
                raise NotImplementedError(child.tag)
            setattr(u, attribute, value)
        uids.append(u)
    return uids
