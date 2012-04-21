# Copyright

import codecs as _codecs
import logging as _logging
import os as _os
import os.path as _os_path
from _socket import socket as _Socket
import socket as _socket
import subprocess as _subprocess

from pyassuan import client as _client
from pyassuan import common as _common

from . import LOG as _LOG


def connect(client, filename, **kwargs):
    filename = _os_path.expanduser(filename)
    if False:
        socket = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        socket.connect(filename)
        client.input = socket.makefile('rb')
        client.output = socket.makefile('wb')
    else:
        p = _subprocess.Popen(
            filename, stdin=_subprocess.PIPE, stdout=_subprocess.PIPE,
            close_fds=True, **kwargs)
        client.input = p.stdout
        client.output = p.stdin
        socket = p
    client.connect()
    return socket

def get_client(**kwargs):
    client = _client.AssuanClient(name='pgp-mime', close_on_disconnect=True)
    client.logger.setLevel(_logging.DEBUG)
    socket = connect(client, '~/src/gpgme/build/src/gpgme-tool', **kwargs)
    #socket = connect(client, '~/.assuan/S.gpgme-tool', **kwargs)
    return (client, socket)

def disconnect(client, socket):
    client.make_request(_common.Request('BYE'))
    client.disconnect()
    if isinstance(socket, _Socket):
        socket.shutdown(_socket.SHUT_RDWR)
        socket.close()
    else:
        status = socket.wait()
        assert status == 0, status

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
                           allow_default_signer=False):
    r"""Sign ``data`` with ``signers`` and encrypt to ``recipients``.

    Just sign:

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
    """
    input_read,input_write = _os.pipe()
    output_read,output_write = _os.pipe()
    client,socket = get_client(pass_fds=(input_read, output_write))
    _os.close(input_read)
    _os.close(output_write)
    try:
        hello(client)
        if signers:
            for signer in signers:
                client.make_request(_common.Request('SIGNER', signer))
        if recipients:
            for recipient in recipients:
                client.make_request(_common.Request('RECIPIENT', recipient))
        client.make_request(
            _common.Request('INPUT', 'FD={}'.format(input_read)))
        client.make_request(
            _common.Request('OUTPUT', 'FD={}'.format(output_write)))
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
        disconnect(client, socket)
        for fd in [input_write, output_read]:
            if fd >= 0:
                _os.close(fd)
    return d

def decrypt_bytes(data):
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
    client,socket = get_client(pass_fds=(input_read, output_write))
    _os.close(input_read)
    _os.close(output_write)
    try:
        hello(client)
        client.make_request(
            _common.Request('INPUT', 'FD={}'.format(input_read)))
        client.make_request(
            _common.Request('OUTPUT', 'FD={}'.format(output_write)))
        _write(input_write, data)
        _os.close(input_write)
        input_write = -1
        client.make_request(_common.Request('DECRYPT'))
        d = _read(output_read)
    finally:
        disconnect(client, socket)
        for fd in [input_write, output_read]:
            if fd >= 0:
                _os.close(fd)
    return d

def verify_bytes(data, signature=None, always_trust=False):
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
    >>> output,verified,result = verify_bytes(b)
    >>> output
    b'Success!\n'
    >>> verified
    False
    >>> print(str(result, 'utf-8').replace('\x00', ''))
    ... # doctest: +REPORT_UDIFF
    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <gpgme>
      <verify-result>
        <signatures>
          <signature>
            <summary value="0x0" />
            <fpr>B2EDBE0E771A4B8708DD16A7511AEDA64332B6E3</fpr>
            <status value="0x0">Success &lt;Unspecified source&gt;</status>
            <timestamp unix="1332357237i" />
            <exp-timestamp unix="0i" />
            <wrong-key-usage value="0x0" />
            <pka-trust value="0x0" />
            <chain-model value="0x0" />
            <validity value="0x0" />
            <validity-reason value="0x0">Success &lt;Unspecified source&gt;</validity-reason>
            <pubkey-algo value="0x1">RSA</pubkey-algo>
            <hash-algo value="0x8">SHA256</hash-algo>
          </signature>
        </signatures>
      </verify-result>
    </gpgme>
    <BLANKLINE>
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
    >>> output,verified,result = verify_bytes(b, signature=signature)
    >>> output
    b'Success!\n'
    >>> verified
    False
    >>> print(str(result, 'utf-8').replace('\x00', ''))
    ... # doctest: +REPORT_UDIFF
    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <gpgme>
      <verify-result>
        <signatures>
          <signature>
            <summary value="0x0" />
            <fpr>B2EDBE0E771A4B8708DD16A7511AEDA64332B6E3</fpr>
            <status value="0x0">Success &lt;Unspecified source&gt;</status>
            <timestamp unix="1332358207i" />
            <exp-timestamp unix="0i" />
            <wrong-key-usage value="0x0" />
            <pka-trust value="0x0" />
            <chain-model value="0x0" />
            <validity value="0x0" />
            <validity-reason value="0x0">Success &lt;Unspecified source&gt;</validity-reason>
            <pubkey-algo value="0x1">RSA</pubkey-algo>
            <hash-algo value="0x2">SHA1</hash-algo>
          </signature>
        </signatures>
      </verify-result>
    </gpgme>
    <BLANKLINE>
    """
    input_read,input_write = _os.pipe()
    pass_fds = [input_read]
    if signature:
        message_read,message_write = _os.pipe()
        output_read = -1
        pass_fds.append(message_read)
    else:
        message_write = -1
        output_read,output_write = _os.pipe()
        pass_fds.append(output_write)
    client,socket = get_client(pass_fds=pass_fds)
    _os.close(input_read)
    if signature:
        _os.close(message_read)
    else:
        _os.close(output_write)
    verified = result = None
    try:
        hello(client)
        client.make_request(
            _common.Request('INPUT', 'FD={}'.format(input_read)))
        if signature:
            client.make_request(
                _common.Request('MESSAGE', 'FD={}'.format(message_read)))
        else:
            client.make_request(
                _common.Request('OUTPUT', 'FD={}'.format(output_write)))
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
        verified = True
        for line in result.splitlines():
            if b'<status ' in line and b'Success' not in line:
                verified = False
            elif b'<pka-trust' in line and b'0x2' not in line:
                verified = False
    finally:
        disconnect(client, socket)
        for fd in [input_write, message_write, output_read]:
            if fd >= 0:
                _os.close(fd)
    return (plain, verified, result)
