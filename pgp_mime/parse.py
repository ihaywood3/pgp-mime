# Copyright (C) 2017 Ian Haywood <ian@haywood.id.au>
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
import email.charset
email.charset.add_charset('utf-8', email.charset.QP, email.charset.QP)
from email.encoders import encode_7or8bit as _encode_7or8bit
from email.encoders import encode_quopri as _encode_quopri
from email.generator import BytesGenerator as _BytesGenerator
from email.mime.application import MIMEApplication as _MIMEApplication
from email.mime.text import MIMEText as _MIMEText
from email.mime.multipart import MIMEMultipart as _MIMEMultipart
from email import policy as _email_policy

import io as _io
import logging as _logging
try:
    from .pgp import verify as _verify
    from .crypt import verify_bytes as _verify_bytes
    from .crypt import process_signature as _process_signature
    from .crypt import uid_from signature as _uid_from_sig
except SystemError:
    from pgp import verify as _verify
    from crypt import verify_bytes as _verify_bytes
    from crypt import process_signature as _process_signature
    from crypt import uid_from signature as _uid_from_sig

def mime_taster(data):
    r"""
    Accepts the document as bytes
    returns a MIME object with the appropriate MIME type
    based on analysis of the data

    >>> print(mime_taster(b'001 some pathology').as_string())
    Content-Type: text/x-pit; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    <BLANKLINE>
    001 some pathology

    >>> print(mime_taster(b'001 some pathology involving 50\xb5g/ml').as_string())
    Content-Type: text/x-pit; charset="utf-8"
    MIME-Version: 1.0
    Content-Transfer-Encoding: quoted-printable
    <BLANKLINE>
    001 some pathology involving 50=C2=B5g/ml
    """
    if data[:4] == b'001 ':
        # most likely the obscure PIT format
        data = data.decode('windows-1252',errors='replace')
        return _MIMEText(data,"x-pit")
    if data[:4] == b'FHS|' or data[:4] == b'BHS|' or data[:4] == b'MSH|':
        # most likely HL7 2.x
        return _MIMEApplication(data,"hl7-v2",_encoder=_encode_quopri)
    if data[:5] == b'%PDF-':
        return _MIMEApplication(data,"pdf")
    try:
        data = data.decode('utf-8')
    except UnicodeDecodeError:
        data = data.decode("windows-1252",errors='replace')
    return _MIMEText(data, "plain")


def parse(orig_msg,ctx=None):
    r"""
    Try hard to parse an arbitrary message, including deformed PGP/MIME, and
    even inline PGP. With inline will synthesise a MIME packet for
    the payload with a guessed content-type.

    Returns a decrypted MIME message with a X-OpenPGP-Status header 
    in the form colour/short message

    If fails the orginal MIME is returned with X-OpenPGP-Status: grey/no OpenPGP encryption

>>> message_bytes = '\n'.join([
... 'To: ihaywood3@gmail.com',
... 'From: Ian Haywood <ian@haywood.id.au>',
...  'Subject: test message',
...  'Date: Thu, 17 Aug 2017 12:03:57 +1000',
...  'MIME-Version: 1.0',
...  'Content-Type: multipart/encrypted;',
...  ' protocol="application/pgp-encrypted";',
...  ' boundary="kF4M06pNtcSQkWDo3x7nJHQsGwrfvpuR2"',
...  '',
...  'This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)',
...  '--kF4M06pNtcSQkWDo3x7nJHQsGwrfvpuR2',
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
... '']).encode("us-ascii")
>>> import email
>>> print(parse(email.message_from_bytes(message_bytes)).as_string()) # doctest: +ELLIPSIS, +REPORT_UDIFF  
Content-Type: multipart/mixed; boundary="BKmMxMjhRbtCRmB1UjVK28mDEw5wfNuTn";
 protected-headers="v1"
From: Ian Haywood <ian@haywood.id.au>
To: ihaywood3@gmail.com
Message-ID: <d9c718a2-46f5-f702-4ec9-39ec6a4f0582@haywood.id.au>
Subject: test message
Date: Thu, 17 Aug 2017 12:03:57 +1000
X-OpenPGP-Status: green/Signed by Ian Haywood <ian@haywood.id.au> on Thu Aug 17 12:03:57 2017
<BLANKLINE>
--BKmMxMjhRbtCRmB1UjVK28mDEw5wfNuTn
Content-Type: multipart/mixed; boundary="J4sKOiHVSqLLioo5XuVHt0dsKpHeOoOMd"
<BLANKLINE>
--J4sKOiHVSqLLioo5XuVHt0dsKpHeOoOMd
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
<BLANKLINE>
bazinga!
<BLANKLINE>
<BLANKLINE>
--J4sKOiHVSqLLioo5XuVHt0dsKpHeOoOMd--
<BLANKLINE>
--BKmMxMjhRbtCRmB1UjVK28mDEw5wfNuTn--
<BLANKLINE>

>>> message_bytes = b'\n'.join(
... [b'To: ihaywood3@gmail.com',
... b'From: Ian Haywood <ian@haywood.id.au>',
... b'Subject: test of inline PGP',
... b'Message-ID: <2c64b751-4eb3-a496-ff8b-8acf30a808ff@haywood.id.au>',
... b'Date: Thu, 17 Aug 2017 21:37:33 +1000',
... b'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101',
... b' Thunderbird/52.2.1',
... b'MIME-Version: 1.0',
... b'Content-Type: text/plain; charset=utf-8',
... b'Content-Transfer-Encoding: quoted-printable',
... b'Content-Language: en-US',
... b'',
... b'',
... b'-----BEGIN PGP MESSAGE-----',
... b'Charset: utf-8',
... b'',
... b'hQEOA6KWUi8uBFm6EAP/RyghDBkDccNAlXzWsPajluVFi8RdEfsjQkwzeqfmfO8W',
... b'dAYp+1M15iZ2btoFdPzl1ag1b2f2ys97yW0P8bJWmCxtm3o68q+52nP2P32Z44Mi',
... b'SYpNZsLuQsxbIkRrgABaI9wCVBnz22dTf43KK9b0S6TO0tpqwwbdWxNV7t171OED',
... b'+QHLsbt8xC8xvnHlb5JhFCshK32O5hTANxW+AnL3V1dKNPmgYkSijlEuCWwobV3V',
... b'VwckypxHM5JB/ffXm/UXuvQiLdKXn89xLXszwsiPSZFK0hE1ogdhu2cvKAwbOuKp',
... b'sAJ3yZMyX9rCg/9qePC7D7Y1PNoVa1xN+Q6oFdNdtH940rsBdjLHtinHyrli5igl',
... b'iMsDZVLhQwwR+C+AmNmFFdMB+PGDawovtFvIeSDc7CYrqxDoEoXZmdB3oR/p3tvV',
... b'6Vt/vnbbbrWTTARlBY2qhOw39BS/eNmXsvHK0Jhbyn+j61lyZ81DJxYXXu5OSW7/',
... b'jECfqYX02xa1Soig/oNQFWMP4kkXVlFK20lti6hFq2XBERXvgRxkbUf4IEVu0EIU',
... b'Rs/fbMPlG0sjDb4roT5/AFKXy8p4aTraSC8v4act',
... b'=3Ddrs6',
... b'-----END PGP MESSAGE-----',
... b''])
>>> print(parse(email.message_from_bytes(message_bytes)).as_string())
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
From: Ian Haywood <ian@haywood.id.au>
To: ihaywood3@gmail.com
Subject: test of inline PGP
Date: Thu, 17 Aug 2017 21:37:33 +1000
Message-ID: <2c64b751-4eb3-a496-ff8b-8acf30a808ff@haywood.id.au>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101
 Thunderbird/52.2.1
X-OpenPGP-Status: green/Signed by Ian Haywood <ian@haywood.id.au> on Thu Aug 17 21:37:33 2017
<BLANKLINE>
inline PGP from Enigmail
<BLANKLINE>
<BLANKLINE>
<BLANKLINE>

    """
    msg = orig_msg
    ct = msg.get_content_type()
    verified = None
    if ct == 'multipart/encrypted':
        msg,verified,signatures = _verify(msg,ctx=ctx)
        ct = msg.get_content_type()
    if ct == 'multipart/signed':
        # some senders may enclose a signed MIME packet inside an encrypted 
        # packet. yes this is stupid as OpenPGP can sign and encrypt in one 
        # layer. it may arise historically from a need to be like X.509
        msg,verified,signatures = _verify(msg,ctx=ctx)
    if verified is None:
        # ok let's have a crack at inline PGP
        if msg.is_multipart():
            body = msg.get_body(preferencelist=('plain',))
        elif ct == 'text/plain':
            body = msg
        else:
            # give up
            orig_msg["X-OpenPGP-Status"] = "grey/no OpenPGP encryption"
            return orig_msg
        payload = body.get_payload(decode=True)
        if not isinstance(payload, bytes):
            payload = payload.encode('us-ascii',errors='replace')
        start = payload.find(b'-----BEGIN PGP MESSAGE-----')
        end = payload.find(b'-----END PGP MESSAGE-----')
        if start != -1 and end != -1:
            payload = payload[start:end+25]+b'\n'
            data,verified,signatures = _verify_bytes(payload,ctx=ctx)
            msg = mime_taster(data)
    if verified is None:
        # ok I give up
        orig_msg["X-OpenPGP-Status"] = "grey/no OpenPGP encryption"
        return orig_msg
    for i in ['From','To','Subject','Date','Cc','Message-ID','User-Agent']:
        if i in orig_msg and not i in msg:
            msg[i] = orig_msg[i]
    if not signatures:
        status = "grey/encrypted but not signed"
    else:
        status = ", ".join(_process_signature(sig) for sig in signatures)
        if verified:
            status = "green/"+status
            msg['X-OpenPGP-Signer'] = ", ".join(i for i in list(_uid_from_sig(sig) for sig in signatures) if i is not None)
        else:
            status = "red/"+status
    msg['X-OpenPGP-Status'] = status
    return msg


if __name__ == "__main__":
    import doctest
    doctest.testmod(optionflags=doctest.NORMALIZE_WHITESPACE|doctest.ELLIPSIS)
