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

import codecs as _codecs
import configparser as _configparser
import logging as _logging
import os as _os
import os.path as _os_path

from pyassuan import client as _client
from pyassuan import common as _common

from . import LOG as _LOG
from . import signature as _signature


SOCKET_PATH = _os_path.expanduser(_os_path.join('~', '.gnupg', 'S.gpgme-tool'))


def get_client_params(config):
    r"""Retrieve Assuan client paramters from a config file.

    >>> from configparser import ConfigParser
    >>> config = ConfigParser()
    >>> config.read_string('\n'.join([
    ...             '[gpgme-tool]',
    ...             'socket-path: /tmp/S.gpgme-tool',
    ...             ]))
    >>> get_client_params(config)
    {'socket_path': '/tmp/S.gpgme-tool'}
    >>> config = ConfigParser()
    >>> get_smtp_params(ConfigParser())
    {'socket_path': None}
    """
    params = {'socket_path': None}
    try:
        params['socket_path'] = config.get('gpgme-tool', 'socket-path')
    except _configparser.NoSectionError:
        return params
    except _configparser.NoOptionError:
        pass
    return params

def get_client(socket_path=None):
    if socket_path is None:
        socket_path = SOCKET_PATH
    logger = _logging.getLogger('{}.{}'.format(_LOG.name, 'pyassuan'))
    client = _client.AssuanClient(
        name='pgp-mime', logger=logger, use_sublogger=False,
        close_on_disconnect=True)
    client.connect(socket_path=socket_path)
    return client

def disconnect(client):
    client.make_request(_common.Request('BYE'))
    client.disconnect()

def hello(client):
    responses,data = client.get_responses()  # get initial 'OK' from server
    client.make_request(_common.Request('ARMOR', 'true'))

def _read(fd, buffersize=512):
    d = []
    while True:
        try:
            new = _os.read(fd, buffersize)
        except Exception as e:
            _LOG.warn('error while reading: {}'.format(e))
            break
        if not new:
            break
        d.append(new)
    return b''.join(d)

def _write(fd, data):
    i = 0
    while i < len(data):
        i += _os.write(fd, data[i:])


def sign_and_encrypt_bytes(data, signers=None, recipients=None,
                           always_trust=False, mode='detach',
                           allow_default_signer=False, **kwargs):
    r"""Sign ``data`` with ``signers`` and encrypt to ``recipients``.

    Just sign (with a detached signature):

    >>> print(sign_and_encrypt_bytes(
    ...     bytes(b'Hello'), signers=['pgp-mime@invalid.com']))
    ... # doctest: +ELLIPSIS
    b'-----BEGIN PGP SIGNATURE-----\n...-----END PGP SIGNATURE-----\n'

    Just encrypt:

    >>> sign_and_encrypt_bytes(
    ...     bytes(b'Hello'), recipients=['pgp-mime@invalid.com'],
    ...     always_trust=True)
    ... # doctest: +ELLIPSIS
    b'-----BEGIN PGP MESSAGE-----\n...-----END PGP MESSAGE-----\n'

    Sign and encrypt:

    >>> sign_and_encrypt_bytes(
    ...     bytes(b'Hello'), signers=['pgp-mime@invalid.com'],
    ...     recipients=['pgp-mime@invalid.com'], always_trust=True)
    ... # doctest: +ELLIPSIS
    b'-----BEGIN PGP MESSAGE-----\n...-----END PGP MESSAGE-----\n'

    Sign and encrypt with a specific subkey:

    >>> sign_and_encrypt_bytes(
    ...     bytes(b'Hello'), signers=['0x2F73DE2E'],
    ...     recipients=['pgp-mime@invalid.com'], always_trust=True)
    ... # doctest: +ELLIPSIS
    b'-----BEGIN PGP MESSAGE-----\n...-----END PGP MESSAGE-----\n'
    """
    input_read,input_write = _os.pipe()
    output_read,output_write = _os.pipe()
    client = get_client(**kwargs)
    try:
        hello(client)
        if signers:
            for signer in signers:
                client.make_request(_common.Request('SIGNER', signer))
        if recipients:
            for recipient in recipients:
                client.make_request(_common.Request('RECIPIENT', recipient))
        client.send_fds([input_read])
        client.make_request(_common.Request('INPUT', 'FD'))
        _os.close(input_read)
        input_read = -1
        client.send_fds([output_write])
        client.make_request(_common.Request('OUTPUT', 'FD'))
        _os.close(output_write)
        output_write = -1
        parameters = []
        if signers or allow_default_signer:
            if recipients:
                command = 'SIGN_ENCRYPT'
            else:
                command = 'SIGN'
                parameters.append('--{}'.format(mode))
        elif recipients:
            command = 'ENCRYPT'
        else:
            raise ValueError('must specify at least one signer or recipient')
        if always_trust:
            parameters.append('--always-trust')
        _write(input_write, data)
        _os.close(input_write)
        input_write = -1
        client.make_request(
            _common.Request(command, ' '.join(parameters)))
        d = _read(output_read)
    finally:
        disconnect(client)
        for fd in [input_read, input_write, output_read, output_write]:
            if fd >= 0:
                _os.close(fd)
    return d

def decrypt_bytes(data, **kwargs):
    r"""Decrypt ``data``.

    >>> b = '\n'.join([
    ...     '-----BEGIN PGP MESSAGE-----',
    ...     'Version: GnuPG v2.0.17 (GNU/Linux)',
    ...     '',
    ...     'hQEMA1Ea7aZDMrbjAQf/TAqLjksZSJxSqkBxYT5gtLQoXY6isvRZg2apjs7CW0y2',
    ...     'tFK/ptnVYAq2OtWQFhbiJXj8hmwJyyFfb3lghpeu4ihO52JgkkwOpmJb6dxjOi83',
    ...     'qDwaGOogEPH38BNLuwdrMCW0jmNROwvS796PtqSGUaJTuIiKUB8lETwPwIHrDc11',
    ...     'N3RWStE5uShNkXXQXplUoeCKf3N4XguXym+GQCqJQzlEMrkkDdr4l7mzvt3Nf8EA',
    ...     'SgSak086tUoo9x8IN5PJCuOJkcXcjQzFcpqOsA7dyZKO8NeQUZv2JvlZuorckNvN',
    ...     'xx3PwW0a8VeJgTQrh64ZK/d3F3gNHUTzXkq/UIn25tJFAcmSUwxtsBal7p8zAeCV',
    ...     '8zefsHRQ5Y03IBeYBcVJBhDS9XfvwLQTJiGGstPCxzKTwSUT1MzV5t5twG/STDCc',
    ...     'uxW3wSdo',
    ...     '=bZI+',
    ...     '-----END PGP MESSAGE-----',
    ...     ''
    ...     ]).encode('us-ascii')
    >>> decrypt_bytes(b)
    b'Success!\n'
    """
    input_read,input_write = _os.pipe()
    output_read,output_write = _os.pipe()
    client = get_client(**kwargs)
    try:
        hello(client)
        client.send_fds([input_read])
        client.make_request(_common.Request('INPUT', 'FD'))
        _os.close(input_read)
        input_read = -1
        client.send_fds([output_write])
        client.make_request(_common.Request('OUTPUT', 'FD'))
        _os.close(output_write)
        output_write = -1
        _write(input_write, data)
        _os.close(input_write)
        input_write = -1
        client.make_request(_common.Request('DECRYPT'))
        d = _read(output_read)
    finally:
        disconnect(client)
        for fd in [input_read, input_write, output_read, output_write]:
            if fd >= 0:
                _os.close(fd)
    return d

def verify_bytes(data, signature=None, always_trust=False, **kwargs):
    r"""Verify a signature on ``data``, possibly decrypting first.

    These tests assume you didn't trust the distributed test key.

    >>> b = '\n'.join([
    ...     '-----BEGIN PGP MESSAGE-----',
    ...     'Version: GnuPG v2.0.17 (GNU/Linux)',
    ...     '',
    ...     'hQEMA1Ea7aZDMrbjAQf/YM1SeFzNGz0DnUynaEyhfGCvcqmjtbN1PtZMpT7VaQLN',
    ...     'a+c0faskr79Atz0+2IBR7CDOlcETrRtH2EnrWukbRIDtmffNFGuhMRTNfnQ15OIN',
    ...     'qrmt2P5gXznsgnm2XjzTK7S/Cc3Aq+zjaDrDt7bIedEdz+EyNgaKuL/lB9cAB8xL',
    ...     'YYp/yn55Myjair2idgzsa7w/QXdE3RhpyRLqR2Jgz4P1I1xOgUYnylbpIZL9FOKN',
    ...     'NR3RQhkGdANBku8otfthb5ZUGsNMV45ct4V8PE+xChjFb9gcwpaf1hhoIF/sYHD5',
    ...     'Bkf+v/J8F40KGYY16b0DjQIUlnra9y7q9jj0h2bvc9LAtgHtVUso133LLcVYl7RP',
    ...     'Vjyz9Ps366BtIdPlAL4CoF5hEcMKS5J3h1vRlyAKN4uHENl5vKvoxn7ID3JhhWQc',
    ...     '6QrPGis64zi3OnYor34HPh/KNJvkgOQkekmtYuTxnkiONA4lhMDJgeaVZ9WZq+GV',
    ...     'MaCvCFGNYU2TV4V8wMlnUbF8d5bDQ83g8MxIVKdDcnBzzYLZha+qmz4Spry9iB53',
    ...     'Sg/sM5H8gWWSl7Oj1lxVg7o7IscpQfVt6zL6jD2VjL3L3Hu7WEXIrcGZtvrP4d+C',
    ...     'TGYWiGlh5B2UCFk2bVctfw8W/QfaVvJYD4Rfqta2V2p14KIJLFRSGa1g26W4ixrH',
    ...     'XKxgaA3AIfJ+6c5RoisRLuYCxvQi91wkE9hAXR+inXK4Hq4SmiHoeITZFhHP3hh3',
    ...     'rbpp8mopiMNxWqCbuqgILP6pShn4oPclu9aR8uJ1ziDxISTGYC71mvLUERUjFn2L',
    ...     'fu6C0+TCC9RmeyL+eNdM6cjs1G7YR6yX',
    ...     '=phHd',
    ...     '-----END PGP MESSAGE-----',
    ...     '',
    ...     ]).encode('us-ascii')
    >>> output,verified,signatures = verify_bytes(b)
    >>> output
    b'Success!\n'
    >>> verified
    False
    >>> for s in signatures:
    ...     print(s.dumps())
    ... # doctest: +REPORT_UDIFF
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
      timestamp: Wed Mar 21 19:13:57 2012
      expiration timestamp: None
      wrong key usage: False
      pka trust: not available
      chain model: False
      validity: unknown
      validity reason: success
      public key algorithm: RSA
      hash algorithm: SHA256
    >>> b = b'Success!\n'
    >>> signature = '\n'.join([
    ...     '-----BEGIN PGP SIGNATURE-----',
    ...     'Version: GnuPG v2.0.17 (GNU/Linux)',
    ...     '',
    ...     'iQEcBAEBAgAGBQJPaiw/AAoJEFEa7aZDMrbj93gH/1fQPXLjUTpONJUTmvGoMLNA',
    ...     'W9ZhjpUL5i6rRqYGUvQ4kTEDuPMxkMrCyFCDHEhSDHufMek6Nso5/HeJn3aqxlgs',
    ...     'hmNlvAq4FI6JQyFL7eCp/XG9cPx1p42dTI7JAih8FuK21sS4m/H5XP3R/6KXC99D',
    ...     '39rrXCvvR+yNgKe2dxuJwmKuLteVlcWxiIQwVrYK70GtJHC5BO79G8yGccWoEy9C',
    ...     '9JkJiyNptqZyFjGBNmMmrCSFZ7ZFA02RB+laRmwuIiozw4TJYEksxPrgZMbbcFzx',
    ...     'zs3JHyV23+Fz1ftalvwskHE7tJkX9Ub8iBMNZ/KxJXXdPdpuMdEYVjoUehkQBQE=',
    ...     '=rRBP',
    ...     '-----END PGP SIGNATURE-----',
    ...     '',
    ...     ]).encode('us-ascii')
    >>> output,verified,signatures = verify_bytes(b, signature=signature)
    >>> output
    b'Success!\n'
    >>> verified
    False
    >>> for s in signatures:
    ...     print(s.dumps())
    ... # doctest: +REPORT_UDIFF
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

    Data signed by a subkey returns the subkey fingerprint.  To find
    the primary key for a given subkey, use
    ``pgp_mime.key.lookup_keys()``.

    >>> b = '\n'.join([
    ...     '-----BEGIN PGP MESSAGE-----',
    ...     'Version: GnuPG v2.0.19 (GNU/Linux)',
    ...     '',
    ...     'hQEMAxcQCLovc94uAQf9ErTZnr0lYRlLLZIk1VcpNNTHrMro+BmqpFC0jprA4/2m',
    ...     '92klBF4TIS1A9bU5oxzQquaAIDV42P3sXrbxu/YhHLmPGH+dc2JVSfPLL0XOL5GC',
    ...     'qpQYe5lglRBReFSRktrfhukjHBoXvh3c8T4xYK2r+nIV4gsp+FrSQMIOdhhBoC36',
    ...     'U1MOk+R+I0JDbWdzZzJONs7ZcAcNDVKqxmAXZUqVgkhPpnGBSBuF9ExKRT3S6e5N',
    ...     'Rsorb/DjGIUHSZuH2EaWAUz1jJ3nSta7TnveT/avfJiAV7cRS4oVgyyFyuHO5gkI',
    ...     'o0obeJaut3enVgpq2TUUk0M4L8TX4jjKvDGAYNyuPNLAsQFHLj5eLmJSudGStWuA',
    ...     'WjKLqBHD0M8/OcwnrTMleJl+h50ZsHO1tvvkXelH+w/jD5SMS+ktxq2Te8Vj7BmM',
    ...     '0WQn3Ys7ViA5PgcSpbqNNLdgc1EMcpPI/sfJAORPKVWRPBKDXX/irY2onAMSe5gH',
    ...     'teNX6bZd/gaoLWqD/1ZhsOCnlV7LY1R929TJ9vxnJcfKKAKwBDfAaSbecUUMECVw',
    ...     's4u3ZT1pmNslBmH6XSy3ifLYWu/2xsJuhPradT88BJOBARMGg81gOE6zxGRrMLJa',
    ...     'KojFgqaF2y4nlZAyaJ1Ld4qCaoQogaL9qE1BbmgtBehZ2FNQiIBSLC0fUUl8A4Py',
    ...     '4d9ZxUoSp7nZmgTN5pUH1N9DIC4ntp/Rak2WnpS7+dRPlp9A2SF0RkeLY+JD9gNm',
    ...     'j44zBkI79KlgaE/cMt6xUXAF/1ZR/Hv/6GUazGx0l23CnSGuqzLpex2uKOxfKiJt',
    ...     'jfgyZRhIdFJnRuEXt8dTTDiiYA==',
    ...     '=0o+x',
    ...     '-----END PGP MESSAGE-----',
    ...     '',
    ...     ]).encode('us-ascii')
    >>> output,verified,signatures = verify_bytes(b)
    >>> output
    b'Hello'
    >>> verified
    False
    >>> for s in signatures:
    ...     print(s.dumps())
    ... # doctest: +REPORT_UDIFF
    DECC812C8795ADD60538B0CD171008BA2F73DE2E signature:
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
      timestamp: Thu Sep 20 15:29:28 2012
      expiration timestamp: None
      wrong key usage: False
      pka trust: not available
      chain model: False
      validity: unknown
      validity reason: success
      public key algorithm: RSA
      hash algorithm: SHA256
    """
    input_read,input_write = _os.pipe()
    if signature:
        message_read,message_write = _os.pipe()
        output_read = output_write = -1
    else:
        message_read = message_write = -1
        output_read,output_write = _os.pipe()
    client = get_client(**kwargs)
    verified = None
    signatures = []
    try:
        hello(client)
        client.send_fds([input_read])
        client.make_request(_common.Request('INPUT', 'FD'))
        _os.close(input_read)
        input_read = -1
        if signature:
            client.send_fds([message_read])
            client.make_request(_common.Request('MESSAGE', 'FD'))
            _os.close(message_read)
            message_read = -1
        else:
            client.send_fds([output_write])
            client.make_request(_common.Request('OUTPUT', 'FD'))
            _os.close(output_write)
            output_write = -1
        if signature:
            _write(input_write, signature)
            _os.close(input_write)
            input_write = -1
            _write(message_write, data)
            _os.close(message_write)
            message_write = -1
        else:
            _write(input_write, data)
            _os.close(input_write)
            input_write = -1
        client.make_request(_common.Request('VERIFY'))
        if signature:
            plain = data
        else:
            plain = _read(output_read)
        rs,result = client.make_request(_common.Request('RESULT'))
        signatures = list(_signature.verify_result_signatures(result))
        verified = True
        for signature in signatures:
            if signature.status != 'success':
                verified = False
            elif signature.pka_trust != 'good':
                verified = False
    finally:
        disconnect(client)
        for fd in [input_read, input_write, message_read, message_write,
                   output_read, output_write]:
            if fd >= 0:
                _os.close(fd)
    return (plain, verified, signatures)
