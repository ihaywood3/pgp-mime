# Copyright (C) 2012 W. Trevor King <wking@tremily.us>
#
# This file is part of pgp-mime.
#
# pgp-mime is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# pgp-mime is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# pgp-mime.  If not, see <http://www.gnu.org/licenses/>.

"""A Python version of GPGME verification signatures.

See the `GPGME manual`_ for details.

.. GPGME manual: http://www.gnupg.org/documentation/manuals/gpgme/Verify.html
"""

import time as _time
import xml.etree.ElementTree as _etree


class Signature (object):
    """Python version of ``gpgme_signature_t``

    >>> from pprint import pprint
    >>> s = Signature()

    You can set flag fields using their integer value (from C).

    >>> s.set_summary(0x3)

    This sets up a convenient dictionary.

    >>> pprint(s.summary)
    {'CRL missing': False,
     'CRL too old': False,
     'bad policy': False,
     'green': True,
     'key expired': False,
     'key missing': False,
     'key revoked': False,
     'red': False,
     'signature expired': False,
     'system error': False,
     'valid': True}

    If you alter the dictionary, it's easy to convert back to the
    equivalent integer value.

    >>> s.summary['green'] = s.summary['valid'] = False
    >>> s.summary['red'] = s.summary['key expired'] = True
    >>> type(s.get_summary())
    <class 'int'>
    >>> '0x{:x}'.format(s.get_summary())
    '0x24'

    If you try and parse a flag field, but have some wonky input, you
    get a helpful error.

    >>> s.set_summary(-1)
    Traceback (most recent call last):
      ...
    ValueError: invalid flags for summary (-1)
    >>> s.set_summary(0x1024)
    Traceback (most recent call last):
      ...
    ValueError: unknown flags for summary (0x1000)

    You can set enumerated fields using their integer value.

    >>> s.set_status(94)
    >>> s.status
    'certificate revoked'
    >>> s.status = 'bad signature'
    >>> s.get_status()
    8

    >>> s.fingerprint = 'ABCDEFG'
    >>> print(s.dumps())  # doctest: +REPORT_UDIFF
    ABCDEFG signature:
      summary:
        CRL missing: False
        CRL too old: False
        bad policy: False
        green: False
        key expired: True
        key missing: False
        key revoked: False
        red: True
        signature expired: False
        system error: False
        valid: False
      status: bad signature
    >>> print(s.dumps(prefix='xx'))  # doctest: +REPORT_UDIFF
    xxABCDEFG signature:
    xx  summary:
    xx    CRL missing: False
    xx    CRL too old: False
    xx    bad policy: False
    xx    green: False
    xx    key expired: True
    xx    key missing: False
    xx    key revoked: False
    xx    red: True
    xx    signature expired: False
    xx    system error: False
    xx    valid: False
    xx  status: bad signature
    """
    _error_enum = {  # GPG_ERR_* in gpg-error.h
        0: 'success',
        1: 'general error',
        8: 'bad signature',
        9: 'no public key',
        94: 'certificate revoked',
        153: 'key expired',
        154: 'signature expired',
        # lots more, to be included as they occur in the wild
        }
    _error_enum_inv = dict((v,k) for k,v in _error_enum.items())

    _summary_flags = {  # GPGME_SIGSUM_* in gpgme.h
        0x001: 'valid',
        0x002: 'green',
        0x004: 'red',
        0x008: 'key revoked',
        0x020: 'key expired',
        0x040: 'signature expired',
        0x080: 'key missing',
        0x100: 'CRL missing',
        0x200: 'CRL too old',
        0x400: 'bad policy',
        0x800: 'system error',
        }

    _pka_trust_enum = {  # struct _gpgme_signature in gpgme.h
        0: 'not available',
        1: 'bad',
        2: 'good',
        3: 'reserved',
        }
    _pka_trust_enum_inv = dict((v,k) for k,v in _pka_trust_enum.items())

    _validity_enum = {  # GPGME_VALIDITY_* in gpgme.h
        0: 'unknown',
        1: 'undefined',
        2: 'never',
        3: 'marginal',
        4: 'full',
        5: 'ultimate',
        }
    _validity_enum_inv = dict((v,k) for k,v in _validity_enum.items())

    _public_key_algorithm_enum = {  # GPGME_PK_* in gpgme.h
        0: 'none',
        1: 'RSA',      # Rivest, Shamir, Adleman
        2: 'RSA for encryption and decryption only',
        3: 'RSA for signing and verification only',
        16: 'ELGamal in GnuPG',
        17: 'DSA',     # Digital Signature Algorithm
        20: 'ELGamal',
        301: 'ECDSA',  # Elliptic Curve Digital Signature Algorithm
        302: 'ECDH',   # Elliptic curve Diffie-Hellman
        }
    _public_key_algorithm_enum_inv = dict(
        (v,k) for k,v in _public_key_algorithm_enum.items())

    _hash_algorithm_enum = {  # GPGME_MD_* in gpgme.h
        0: 'none',
        1: 'MD5',
        2: 'SHA1',
        3: 'RMD160',
        5: 'MD2',
        6: 'TIGER/192',
        7: 'HAVAL, 5 pass, 160 bit',
        8: 'SHA256',
        9: 'SHA384',
        10: 'SHA512',
        301: 'MD4',
        302: 'CRC32',
        303: 'CRC32 RFC1510',
        304: 'CRC24 RFC2440',
        }
    _hash_algorithm_enum_inv = dict(
        (v,k) for k,v in _hash_algorithm_enum.items())

    def __init__(self, summary=None, fingerprint=None, status=None,
                 notations=None, timestamp=None, expiration_timestamp=None,
                 wrong_key_usage=None, pka_trust=None, chain_model=None,
                 validity=None, validity_reason=None,
                 public_key_algorithm=None, hash_algorithm=None):
        self.summary = summary
        self.fingerprint = fingerprint
        self.status = status
        self.notations = notations
        self.timestamp = timestamp
        self.expiration_timestamp = expiration_timestamp
        self.wrong_key_usage = wrong_key_usage
        self.pka_trust = pka_trust
        self.chain_model = chain_model
        self.validity = validity
        self.validity_reason = validity_reason
        self.public_key_algorithm = public_key_algorithm
        self.hash_algorithm = hash_algorithm

    def _set_flags(self, attribute, value, flags):
        if value < 0:
            raise ValueError(
                'invalid flags for {} ({})'.format(attribute, value))
        d = {}
        for flag,name in flags.items():
            x = flag & value
            d[name] = bool(x)
            value -= x
        if value:
            raise ValueError(
                'unknown flags for {} (0x{:x})'.format(attribute, value))
        setattr(self, attribute, d)

    def _get_flags(self, attribute, flags):
        value = 0
        d = getattr(self, attribute)
        for flag,name in flags.items():
            if d[name]:
                value |= flag
        return value

    def set_summary(self, value):
        self._set_flags('summary', value, self._summary_flags)

    def get_summary(self):
        return self._get_flags('summary', self._summary_flags)

    def set_status(self, value):
        self.status = self._error_enum[value]

    def get_status(self):
        return self._error_enum_inv[self.status]

    def set_pka_trust(self, value):
        self.pka_trust = self._pka_trust_enum[value]

    def get_pka_trust(self):
        return self._pka_trust_enum_inv[self.pka_trust]

    def set_validity(self, value):
        self.validity = self._validity_enum[value]

    def get_validity(self):
        return self._error_validity_inv[self.validity]

    def set_validity_reason(self, value):
        self.validity_reason = self._error_enum[value]

    def get_validity_reason(self):
        return self._error_enum_inv[self.validity_reason]

    def set_public_key_algorithm(self, value):
        self.public_key_algorithm = self._public_key_algorithm_enum[value]

    def get_public_key_algorithm(self):
        return self._public_key_algorithm_inv[self.public_key_algorithm]

    def set_hash_algorithm(self, value):
        self.hash_algorithm = self._hash_algorithm_enum[value]

    def get_hash_algorithm(self):
        return self._error_hash_algorithm_inv[self.hash_algorithm]

    def dumps(self, prefix=''):
        lines = ['{}{} signature:'.format(prefix, self.fingerprint)]
        for attribute in ['summary', 'status', 'notations', 'timestamp',
                          'expiration_timestamp', 'wrong_key_usage',
                          'pka_trust', 'chain_model', 'validity',
                          'validity_reason', 'public_key_algorithm',
                          'hash_algorithm']:
            label = attribute.replace('_', ' ')
            value = getattr(self, attribute)
            if value is None:
                continue  # no information
            elif attribute.endswith('timestamp'):
                if value == 0 and attribute == 'expiration_timestamp':
                    value = None
                else:
                    value = _time.asctime(_time.gmtime(value))
            if isinstance(value, dict):  # flag field
                lines.append('  {}:'.format(label))
                lines.extend(
                    ['    {}: {}'.format(k,v)
                     for k,v in sorted(value.items())])
            else:
                lines.append('  {}: {}'.format(label, value))
        sep = '\n{}'.format(prefix)
        return sep.join(lines)


def verify_result_signatures(result):
    """
    >>> from pprint import pprint
    >>> result = b'\\n'.join([
    ...     b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
    ...     b'<gpgme>',
    ...     b'  <verify-result>',
    ...     b'    <signatures>',
    ...     b'      <signature>',
    ...     b'        <summary value="0x0" />',
    ...     b'        <fpr>B2EDBE0E771A4B8708DD16A7511AEDA64332B6E3</fpr>',
    ...     b'        <status value="0x0">Success &lt;Unspecified source&gt;</status>',
    ...     b'        <timestamp unix="1332358207i" />',
    ...     b'        <exp-timestamp unix="0i" />',
    ...     b'        <wrong-key-usage value="0x0" />',
    ...     b'        <pka-trust value="0x0" />',
    ...     b'        <chain-model value="0x0" />',
    ...     b'        <validity value="0x0" />',
    ...     b'        <validity-reason value="0x0">Success &lt;Unspecified source&gt;</validity-reason>',
    ...     b'        <pubkey-algo value="0x1">RSA</pubkey-algo>',
    ...     b'        <hash-algo value="0x2">SHA1</hash-algo>',
    ...     b'      </signature>',
    ...     b'    </signatures>',
    ...     b'  </verify-result>',
    ...     b'</gpgme>',
    ...     b'',
    ...     ])
    >>> signatures = list(verify_result_signatures(result))
    >>> signatures  # doctest: +ELLIPSIS
    [<pgp_mime.signature.Signature object at 0x...>]
    >>> for s in signatures:
    ...     print(s.dumps())  # doctest: +REPORT_UDIFF
    B2EDBE0E771A4B8708DD16A7511AEDA64332B6E3 signature:
      summary:
        CRL missing: False
        CRL too old: False
        bad policy: False
        green: False
        key expired: False
        key missing: False
        key revoked: False
        red: False
        signature expired: False
        system error: False
        valid: False
      status: success
      timestamp: Wed Mar 21 19:30:07 2012
      expiration timestamp: None
      wrong key usage: False
      pka trust: not available
      chain model: False
      validity: unknown
      validity reason: success
      public key algorithm: RSA
      hash algorithm: SHA1
    """
    tag_mapping = {
        'exp-timestamp': 'expiration_timestamp',
        'fpr': 'fingerprint',
        'pubkey-algo': 'public_key_algorithm',
        'hash-algo': 'hash_algorithm',
        }
    tree = _etree.fromstring(result.replace(b'\x00', b''))
    for signature in tree.findall('.//signature'):
        s = Signature()
        for child in signature.iter():
            if child == signature:  # iter() includes the root element
                continue
            attribute = tag_mapping.get(child.tag, child.tag.replace('-', '_'))
            if child.tag in ['summary', 'wrong-key-usage', 'pka-trust',
                             'chain-model', 'validity', 'pubkey-algo',
                             'hash-algo']:
                value = child.get('value')
                if not value.startswith('0x'):
                    raise NotImplementedError('summary value {}'.format(value))
                value = int(value, 16)
                if attribute in ['wrong_key_usage', 'chain_model']:
                    value = bool(value)  # boolean
                else:  # flags or enum
                    setter = getattr(s, 'set_{}'.format(attribute))
                    setter(value)
                    continue
            elif child.tag in ['timestamp', 'exp-timestamp']:
                value = child.get('unix')
                if value.endswith('i'):
                    value = int(value[:-1])
                else:
                    raise NotImplementedError('timestamp value {}'.format(value))
            elif child.tag in ['fpr', 'status', 'validity-reason']:
                value = child.text
                if value.endswith(' <Unspecified source>'):
                    value = value[:-len(' <Unspecified source>')].lower()
            else:
                raise NotImplementedError(child.tag)
            setattr(s, attribute, value)
        yield s
