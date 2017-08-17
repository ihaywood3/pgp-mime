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

import copy as _copy
from email import message_from_bytes as _message_from_bytes
from email.encoders import encode_7or8bit as _encode_7or8bit
from email.generator import BytesGenerator as _BytesGenerator
from email.mime.application import MIMEApplication as _MIMEApplication
from email.mime.multipart import MIMEMultipart as _MIMEMultipart
from email import policy as _email_policy
import io as _io
import logging as _logging
from crypt import sign_and_encrypt_bytes as _sign_and_encrypt_bytes
from crypt import verify_bytes as _verify_bytes
from myemail import email_targets as _email_targets
from myemail import strip_bcc as _strip_bcc


def _flatten(message):
    r"""Flatten a message to bytes.

    >>> from pgp_mime.email import encodedMIMEText
    >>> message = encodedMIMEText('Hi\nBye')
    >>> _flatten(message)  # doctest: +ELLIPSIS
    b'Content-Type: text/plain; charset="us-ascii"\r\nMIME-Version: ...'
    """
    bytesio = _io.BytesIO()
    generator = _BytesGenerator(bytesio, policy=_email_policy.SMTP)
    generator.flatten(message)
    return bytesio.getvalue()

def sign(message, **kwargs):
    r"""Sign a ``Message``, returning the signed version.

    multipart/signed
    +-> text/plain                 (body)
    +-> application/pgp-signature  (signature)

    >>> from pgp_mime.email import encodedMIMEText
    >>> message = encodedMIMEText('Hi\nBye')
    >>> signed = sign(message, signers=True)
    >>> signed.set_boundary('boundsep')
    >>> print(signed.as_string().replace(
    ...     'micalg="pgp-sha1"; protocol="application/pgp-signature"',
    ...     'protocol="application/pgp-signature"; micalg="pgp-sha1"'))
    ... # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: multipart/signed; protocol="application/pgp-signature"; micalg="pgp-sha1"; boundary="boundsep"
    MIME-Version: 1.0
    Content-Disposition: inline
    <BLANKLINE>
    --boundsep
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    <BLANKLINE>
    Hi
    Bye
    --boundsep
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Description: OpenPGP digital signature
    Content-Type: application/pgp-signature; name="signature.asc"; charset="us-ascii"
    <BLANKLINE>
    -----BEGIN PGP SIGNATURE-----
    ...
    -----END PGP SIGNATURE-----
    <BLANKLINE>
    --boundsep--

    >>> from email.mime.multipart import MIMEMultipart
    >>> message = MIMEMultipart()
    >>> message.attach(encodedMIMEText('Part A'))
    >>> message.attach(encodedMIMEText('Part B'))
    >>> signed = sign(message, signers=[TESTADDRESS])
    >>> signed.set_boundary('boundsep')
    >>> print(signed.as_string().replace(
    ...     'micalg="pgp-sha1"; protocol="application/pgp-signature"',
    ...     'protocol="application/pgp-signature"; micalg="pgp-sha1"'))
    ... # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: multipart/signed; protocol="application/pgp-signature"; micalg="pgp-sha1"; boundary="boundsep"
    MIME-Version: 1.0
    Content-Disposition: inline
    <BLANKLINE>
    --boundsep
    Content-Type: multipart/mixed; boundary="===============...=="
    MIME-Version: 1.0
    <BLANKLINE>
    --===============...==
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    <BLANKLINE>
    Part A
    --===============...==
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    <BLANKLINE>
    Part B
    --===============...==--
    --boundsep
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Description: OpenPGP digital signature
    Content-Type: application/pgp-signature; name="signature.asc"; charset="us-ascii"
    <BLANKLINE>
    -----BEGIN PGP SIGNATURE-----
    ...
    -----END PGP SIGNATURE-----
    <BLANKLINE>
    --boundsep--
    """
    body = _flatten(message)
    signature = str(_sign_and_encrypt_bytes(data=body, **kwargs), 'us-ascii')
    sig = _MIMEApplication(
        _data=signature,
        _subtype='pgp-signature; name="signature.asc"',
        _encoder=_encode_7or8bit)
    sig['Content-Description'] = 'OpenPGP digital signature'
    sig.set_charset('us-ascii')

    msg = _MIMEMultipart(
        'signed', micalg='pgp-sha1', protocol='application/pgp-signature')
    msg.attach(message)
    msg.attach(sig)
    msg['Content-Disposition'] = 'inline'
    return msg

def encrypt(message, recipients=None, **kwargs):
    r"""Encrypt a ``Message``, returning the encrypted version.

    multipart/encrypted
    +-> application/pgp-encrypted  (control information)
    +-> application/octet-stream   (body)

    >>> from pgp_mime.email import encodedMIMEText
    >>> message = encodedMIMEText('Hi\nBye')
    >>> message['To'] = TESTEMAIL
    >>> encrypted = encrypt(message, always_trust=True)
    >>> encrypted.set_boundary('boundsep')
    >>> print(encrypted.as_string().replace(
    ...     'micalg="pgp-sha1"; protocol="application/pgp-encrypted"',
    ...     'protocol="application/pgp-encrypted"; micalg="pgp-sha1"'))
    ... # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; micalg="pgp-sha1"; boundary="boundsep"
    MIME-Version: 1.0
    Content-Disposition: inline
    <BLANKLINE>
    --boundsep
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Type: application/pgp-encrypted; charset="us-ascii"
    <BLANKLINE>
    Version: 1
    <BLANKLINE>
    --boundsep
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Description: OpenPGP encrypted message
    Content-Type: application/octet-stream; name="encrypted.asc"; charset="us-ascii"
    <BLANKLINE>
    -----BEGIN PGP MESSAGE-----
    ...
    -----END PGP MESSAGE-----
    <BLANKLINE>
    --boundsep--

    >>> from email.mime.multipart import MIMEMultipart
    >>> message = MIMEMultipart()
    >>> message.attach(encodedMIMEText('Part A'))
    >>> message.attach(encodedMIMEText('Part B'))
    >>> encrypted = encrypt(
    ...     message, recipients=[TESTADDRESS], always_trust=True)
    >>> encrypted.set_boundary('boundsep')
    >>> print(encrypted.as_string().replace(
    ...     'micalg="pgp-sha1"; protocol="application/pgp-encrypted"',
    ...     'protocol="application/pgp-encrypted"; micalg="pgp-sha1"'))
    ... # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; micalg="pgp-sha1"; boundary="boundsep"
    MIME-Version: 1.0
    Content-Disposition: inline
    <BLANKLINE>
    --boundsep
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Type: application/pgp-encrypted; charset="us-ascii"
    <BLANKLINE>
    Version: 1
    <BLANKLINE>
    --boundsep
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Description: OpenPGP encrypted message
    Content-Type: application/octet-stream; name="encrypted.asc"; charset="us-ascii"
    <BLANKLINE>
    -----BEGIN PGP MESSAGE-----
    ...
    -----END PGP MESSAGE-----
    <BLANKLINE>
    --boundsep--
    """
    body = _flatten(message)
    if recipients is None:
        recipients = [email for name,email in _email_targets(message)]
        _logging.debug('extracted encryption recipients: {}'.format(recipients))
    encrypted = str(_sign_and_encrypt_bytes(
            data=body, recipients=recipients, **kwargs), 'us-ascii')
    enc = _MIMEApplication(
        _data=encrypted,
        _subtype='octet-stream; name="encrypted.asc"',
        _encoder=_encode_7or8bit)
    enc['Content-Description'] = 'OpenPGP encrypted message'
    enc.set_charset('us-ascii')
    control = _MIMEApplication(
        _data='Version: 1\n',
        _subtype='pgp-encrypted',
        _encoder=_encode_7or8bit)
    control.set_charset('us-ascii')
    msg = _MIMEMultipart(
        'encrypted',
        micalg='pgp-sha1',
        protocol='application/pgp-encrypted')
    msg.attach(control)
    msg.attach(enc)
    msg['Content-Disposition'] = 'inline'
    return msg

def sign_and_encrypt(message, signers=True, recipients=None, **kwargs):
    r"""Sign and encrypt a ``Message``, returning the encrypted version.
     signers=True use the default private key
     signers=None means just encrypt, don't sign at all
     can also be a list of IDs of local keys to sign with
     
     receipients=None -- infer from the To header
    multipart/encrypted
     +-> application/pgp-encrypted  (control information)
     +-> application/octet-stream   (body)

    >>> from pgp_mime.email import encodedMIMEText
    >>> message = encodedMIMEText('Hi\nBye')
    >>> message['To'] = TESTEMAIL
    >>> encrypted = sign_and_encrypt(
    ...     message, signers=[TESTADDRESS], always_trust=True)
    >>> encrypted.set_boundary('boundsep')
    >>> print(encrypted.as_string().replace(
    ...     'micalg="pgp-sha1"; protocol="application/pgp-encrypted"',
    ...     'protocol="application/pgp-encrypted"; micalg="pgp-sha1"').replace(TESTEMAIL,'TESTEMAIL'))
    ... # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; micalg="pgp-sha1"; boundary="boundsep"
    MIME-Version: 1.0
    To: TESTEMAIL
    Content-Disposition: inline
    <BLANKLINE>
    --boundsep
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Type: application/pgp-encrypted; charset="us-ascii"
    <BLANKLINE>
    Version: 1
    <BLANKLINE>
    --boundsep
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Description: OpenPGP encrypted message
    Content-Type: application/octet-stream; name="encrypted.asc"; charset="us-ascii"
    <BLANKLINE>
    -----BEGIN PGP MESSAGE-----
    ...
    -----END PGP MESSAGE-----
    <BLANKLINE>
    --boundsep--

    >>> from email.mime.multipart import MIMEMultipart
    >>> message = MIMEMultipart()
    >>> message.attach(encodedMIMEText('Part A'))
    >>> message.attach(encodedMIMEText('Part B'))
    >>> encrypted = sign_and_encrypt(
    ...     message, signers=[TESTEMAIL],
    ...     recipients=[TESTEMAIL], always_trust=True)
    >>> encrypted.set_boundary('boundsep')
    >>> print(encrypted.as_string().replace(
    ...     'micalg="pgp-sha1"; protocol="application/pgp-encrypted"',
    ...     'protocol="application/pgp-encrypted"; micalg="pgp-sha1"'))
    ... # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; micalg="pgp-sha1"; boundary="boundsep"
    MIME-Version: 1.0
    Content-Disposition: inline
    <BLANKLINE>
    --boundsep
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Type: application/pgp-encrypted; charset="us-ascii"
    <BLANKLINE>
    Version: 1
    <BLANKLINE>
    --boundsep
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Description: OpenPGP encrypted message
    Content-Type: application/octet-stream; name="encrypted.asc"; charset="us-ascii"
    <BLANKLINE>
    -----BEGIN PGP MESSAGE-----
    ...
    -----END PGP MESSAGE-----
    <BLANKLINE>
    --boundsep--
    """
    old_bcc = None
    if 'Bcc' in message:
        old_bcc = message['Bcc']
        _strip_bcc(message=message)
    body = _flatten(message)
    if recipients is None:
        recipients = [email for name,email in _email_targets(message)]
        _logging.debug('extracted encryption recipients: {}'.format(recipients))
    encrypted = str(
        _sign_and_encrypt_bytes(
            data=body, signers=signers, recipients=recipients, **kwargs),
        'us-ascii')
    enc = _MIMEApplication(
        _data=encrypted,
        _subtype='octet-stream; name="encrypted.asc"',
        _encoder=_encode_7or8bit)
    enc['Content-Description'] = 'OpenPGP encrypted message'
    enc.set_charset('us-ascii')
    control = _MIMEApplication(
        _data='Version: 1\n',
        _subtype='pgp-encrypted',
        _encoder=_encode_7or8bit)
    control.set_charset('us-ascii')
    msg = _MIMEMultipart(
        'encrypted',
        micalg='pgp-sha1',
        protocol='application/pgp-encrypted')
    msg.attach(control)
    msg.attach(enc)
    if 'From' in message: msg['From'] = message["From"]
    if 'To' in message: msg['To'] = message['To']
    if 'Subject' in message: msg['Subject'] = message['Subject']
    if 'Cc' in message: msg['Cc'] = message['Cc']
    if old_bcc: msg['Bcc'] = old_bcc
    msg['Content-Disposition'] = 'inline'
    return msg

def _get_encrypted_parts(message):
    ct = message.get_content_type()
    assert ct == 'multipart/encrypted', ct
    params = dict(message.get_params())
    assert params.get('protocol', None) == 'application/pgp-encrypted', params
    assert message.is_multipart(), message
    control = body = None
    for part in message.get_payload():
        if part == message:
            continue
        assert part.is_multipart() == False, part
        ct = part.get_content_type()
        if ct == 'application/pgp-encrypted':
            if control:
                raise ValueError('multiple application/pgp-encrypted parts')
            control = part
        elif ct == 'application/octet-stream':
            if body:
                raise ValueError('multiple application/octet-stream parts')
            body = part
        else:
            raise ValueError('unnecessary {} part'.format(ct))
    if not control:
        raise ValueError('missing application/pgp-encrypted part')
    if not body:
        raise ValueError('missing application/octet-stream part')
    return (control, body)

def _get_signed_parts(message):
    ct = message.get_content_type()
    assert ct == 'multipart/signed', ct
    params = dict(message.get_params())
    assert params.get('protocol', None) == 'application/pgp-signature', params
    assert message.is_multipart(), message
    body = signature = None
    for part in message.get_payload():
        if part == message:
            continue
        ct = part.get_content_type()
        if ct == 'application/pgp-signature':
            if signature:
                raise ValueError('multiple application/pgp-signature parts')
            signature = part
        else:
            if body:
                raise ValueError('multiple non-signature parts')
            body = part
    if not body:
        raise ValueError('missing body part')
    if not signature:
        raise ValueError('missing application/pgp-signature part')
    return (body, signature)

def decrypt(message, **kwargs):
    r"""Decrypt a multipart/encrypted message.

    >>> from pgp_mime.email import encodedMIMEText
    >>> message = encodedMIMEText('Hi\nBye')
    >>> encrypted = encrypt(
    ...     message, recipients=[TESTEMAIL], always_trust=True)
    >>> decrypted = decrypt(encrypted)
    >>> print(decrypted.as_string().replace('\r\n', '\n'))
    ... # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    <BLANKLINE>
    Hi
    Bye

    >>> from email.mime.multipart import MIMEMultipart
    >>> message = MIMEMultipart()
    >>> message.attach(encodedMIMEText('Part A'))
    >>> message.attach(encodedMIMEText('Part B'))
    >>> encrypted = encrypt(
    ...     message, recipients=[TESTEMAIL], always_trust=True)
    >>> decrypted = decrypt(encrypted)
    >>> decrypted.set_boundary('boundsep')
    >>> print(decrypted.as_string()) # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: multipart/mixed; boundary="boundsep"
    MIME-Version: 1.0
    <BLANKLINE>
    --boundsep
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    <BLANKLINE>
    Part A
    --boundsep
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    <BLANKLINE>
    Part B
    --boundsep--
    <BLANKLINE>
    """
    control,body = _get_encrypted_parts(message)
    encrypted = body.get_payload(decode=True)
    if not isinstance(encrypted, bytes):
        encrypted = encrypted.encode('us-ascii')
    decrypted,verified,result = _verify_bytes(encrypted, **kwargs)
    return _message_from_bytes(decrypted)

def verify(message, **kwargs):
    r"""Verify a signature on ``message``, possibly decrypting first.

    >>> from myemail import encodedMIMEText
    >>> message = encodedMIMEText('Hi\nBye')
    >>> message['To'] = TESTADDRESS
    >>> encrypted = sign_and_encrypt(message, signers=[TESTEMAIL],
    ...     always_trust=True)
    >>> decrypted,verified,signatures = verify(encrypted)
    >>> print(decrypted.as_string().replace('\r\n', '\n').replace(TESTADDRESS,'TESTADDRESS'))
    ... # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    To: TESTADDRESS
    <BLANKLINE>
    Hi
    Bye
    >>> verified
    True
    >>> for s in signatures:
    ...     print(s)
    ... # doctest: +ELLIPSIS
    Signature(chain_model=False, exp_timestamp=0, fpr='...', hash_algo=2, key=None, notations=[], pka_address=None, pka_trust=0, pubkey_algo=17, status=0, summary=3, timestamp=..., validity=4, validity_reason=0, wrong_key_usage=False)

    >>> from email.mime.multipart import MIMEMultipart
    >>> message = MIMEMultipart()
    >>> message.attach(encodedMIMEText('Part A'))
    >>> message.attach(encodedMIMEText('Part B'))
    >>> signed = sign(message, signers=[TESTADDRESS])
    >>> decrypted,verified,signatures = verify(signed)
    >>> decrypted.set_boundary('boundsep')
    >>> print(decrypted.as_string())  # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: multipart/mixed; boundary="boundsep"
    MIME-Version: 1.0
    <BLANKLINE>
    --boundsep
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    <BLANKLINE>
    Part A
    --boundsep
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    <BLANKLINE>
    Part B
    --boundsep--
    >>> verified
    True
    >>> for s in signatures:
    ...     print(s) 
    ... # doctest: +ELLIPSIS
    Signature(chain_model=False, exp_timestamp=0, fpr='...', hash_algo=2, key=None, notations=[], pka_address=None, pka_trust=0, pubkey_algo=17, status=0, summary=3, timestamp=..., validity=4, validity_reason=0, wrong_key_usage=False)

    Test a message generated by Thundderbird=Engimail (for sanity):
    >>> verified = None
    >>> signatures = None
    >>> from email import message_from_bytes
    >>> message_bytes = '\n'.join(
    ... ['To: ihaywood3@gmail.com',
    ... 'From: Ian Haywood <ian@haywood.id.au>',
    ... 'Subject: test message',
    ... 'Message-ID: <d9c718a2-46f5-f702-4ec9-39ec6a4f0582@haywood.id.au>',
    ... 'Date: Thu, 17 Aug 2017 12:03:57 +1000',
    ... 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101',
    ... ' Thunderbird/52.2.1',
    ... 'MIME-Version: 1.0',
    ... 'Content-Type: multipart/encrypted;',
    ... ' protocol="application/pgp-encrypted";',
    ... ' boundary="kF4M06pNtcSQkWDo3x7nJHQsGwrfvpuR2"',
    ... '',
    ... 'This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)',
    ... '--kF4M06pNtcSQkWDo3x7nJHQsGwrfvpuR2',
    ... 'Content-Type: application/pgp-encrypted',
    ... 'Content-Description: PGP/MIME version identification',
    ... '',
    ... 'Version: 1',
    ... '',
    ... '--kF4M06pNtcSQkWDo3x7nJHQsGwrfvpuR2',
    ... 'Content-Type: application/octet-stream; name="encrypted.asc"',
    ... 'Content-Description: OpenPGP encrypted message',
    ... 'Content-Disposition: inline; filename="encrypted.asc"',
    ... '',
    ... '-----BEGIN PGP MESSAGE-----',
    ... '',
    ... 'hQEOA6KWUi8uBFm6EAP/ZloFzI9+VuU1lV6B3Q5SfcPsDpcj4zJcdylfXNoqfvmq',
    ... 'kYl8wZo0n1/kCiUgyfsOOXU8AN6C3QFLX5WcDZeOaLguXVw4bRXOVXW/Fs7m9DZI',
    ... 'JxQeX6XlVIgZDLlSwEd8YDwi3zA9aUQhQqyMrSbsh2ZcJghW+JkebGhtp+1ne18D',
    ... '/ik1NG6zXo3ZzUGw+yasCZWYpSbqbCVHFUna888HXj0dc4xdt+SRIXz10rgnweUR',
    ... '+/WvLd8+UPYMGX7ABhVwZDqv3vGVuQ+Ddw1u/epCwQ9Vtj4338mRI0qcDV3u2AP6',
    ... 'vY9JrKrAgZHpZsyhFxsnAhkYQKzU4PVEUf8tdZaIfpZr0ukBuNz7boJNQutffmyc',
    ... '1Mcdt090hUbyra2ESWeb6D3/Qg0rxbZ0MlJgohi+CTdp1sMiqnJnMD8nzJ87iEwV',
    ... '3YYpCwW0r/ITrxSD/hKbh6wUh9hmw+ulDc6QggYrVT1HczDm2EIA4ix6oqDMWCYv',
    ... 'JDWnStIWmfyZ6NobO2pBkAOgsG61OvIMjVBPTguTp0SygBfuPdgq8MYaVfZ4+kCd',
    ... 'OAQPqulWBYjCwb1rEYVNydtN+DA7GVk0M+YbwQYoBPTYgRVjRSTNNQzotgxP3iW5',
    ... '1TFaBZ1Ngi67fY62ResGb/ds8vG43On4eBaUNerBwppQzqh4xOgn1L5nLNFHnEQ8',
    ... 'QLuiG17zC5cydbiZD78MXoZk/vPjsHnhFVC/w/q/2WEUeMiMg2CH9GCrwk33KTKR',
    ... 'bItUQBjJa0welhq1F3C/BJha4k7qoN0PtIWZWLlvWFdj236I/d7k964Is+Gh+isg',
    ... 'ZUr4iAe/1MrLErpF+hwYn17JbdEt6bL76PuIa0SlrdVuT+MCjX//N+YyrXpmfPd2',
    ... 'H1v7/Sa4jSBx1xuEjuYih8xcfq2M9EeXrBT0kYfZZHJcTuG/9L8SHq3Izpy1Pjva',
    ... 'KvA2dKA7n5SIgTdYK89+rplM4McAY7vIs2cCdNe2TvYULHigRELcfTTU0IWD9clg',
    ... 'QWSdp54ANi9HdkaUW7vk1Mo7aRfofQo0xd1/2Yl8b9lrrw5wDQq8hMwKMQ==',
    ... '=0unP',
    ... '-----END PGP MESSAGE-----',
    ... '',
    ... '--kF4M06pNtcSQkWDo3x7nJHQsGwrfvpuR2--',
    ...   '']).encode("us-ascii")
    >>> message = message_from_bytes(message_bytes)
    >>> decrypted,verified,signatures = verify(message)
    >>> print(decrypted.as_string())  # doctest: +ELLIPSIS
    Content-Type: multipart/mixed; boundary="...";
     protected-headers="v1"
    From: Ian Haywood <ian@haywood.id.au>
    To: ihaywood3@gmail.com
    Message-ID: <...>
    Subject: test message
    <BLANKLINE>
    --...
    Content-Type: multipart/mixed; boundary="..."
    <BLANKLINE>
    --...
    Content-Type: text/plain; charset=utf-8
    Content-Transfer-Encoding: quoted-printable
    Content-Language: en-US
    <BLANKLINE>
    bazinga!
    <BLANKLINE>
    <BLANKLINE>
    --...--
    <BLANKLINE>
    --...--
    <BLANKLINE>
    >>> verified
    True
    >>> for s in signatures:
    ...     print(s) 
    ... # doctest: +ELLIPSIS
    Signature(chain_model=False, exp_timestamp=0, fpr='9BF067B7F84FF7EE0C42C06328FCBC52E750652E', hash_algo=2, key=None, notations=[], pka_address=None, pka_trust=0, pubkey_algo=17, status=0, summary=3, timestamp=..., validity=4, validity_reason=0, wrong_key_usage=False)
    """
    ct = message.get_content_type()
    if ct == 'multipart/encrypted':
        control,body = _get_encrypted_parts(message)
        encrypted = body.get_payload(decode=True)
        if not isinstance(encrypted, bytes):
            encrypted = encrypted.encode('us-ascii')
        decrypted,verified,message = _verify_bytes(encrypted)
        return (_message_from_bytes(decrypted), verified, message)
    body,signature = _get_signed_parts(message)
    sig_data = signature.get_payload(decode=True)
    if not isinstance(sig_data, bytes):
        sig_data = sig_data.encode('us-ascii')
    decrypted,verified,result = _verify_bytes(
        _flatten(body), signature=sig_data, **kwargs)
    return (_copy.deepcopy(body), verified, result)



def test_sending():
    from myemail import encodedMIMEText
    message = encodedMIMEText('Hi\nBye')
    message['To'] = TESTEMAIL
    message['From'] = TESTEMAIL
    message['Subject'] = "hello from pgp-mime"
    encrypted = sign_and_encrypt(message)
    import smtplib
    conn = smtplib.SMTP("haywood.id.au")
    conn.send_message(encrypted)
    conn.close()

if __name__ == "__main__":
    import doctest
    global TESTEMAIL
    TESTEMAIL='Ian Haywood <ian@haywood.id.au>'
    global TESTADDRESS
    TESTADDRESS='ian@haywood.id.au'
    doctest.testmod(optionflags=doctest.NORMALIZE_WHITESPACE|doctest.ELLIPSIS)
    #test_sending()
