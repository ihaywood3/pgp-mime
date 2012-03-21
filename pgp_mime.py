# -*- coding: utf-8 -*-
# Copyright (C) 2012 W. Trevor King <wking@drexel.edu>
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
"""Python module and for constructing and sending pgp/mime email.

Mostly uses subprocess to call ``gpg`` and sends mail using either
SMTP or a sendmail-compatible mailer.  If you lack ``gpg``, either
don't use the encryption functions, adjust the ``GPG_*`` constants, or
adjust the ``*_bytes`` commands.
"""

import configparser as _configparser
import io as _io
import logging as _logging
import os as _os
import re as _re
import smtplib as _smtplib
import smtplib as _smtplib
import subprocess as _subprocess

from email.encoders import encode_7or8bit as _encode_7or8bit
from email.generator import Generator as _Generator
from email.header import decode_header as _decode_header
from email.message import Message as _Message
from email.mime.application import MIMEApplication as _MIMEApplication
from email.mime.multipart import MIMEMultipart as _MIMEMultipart
from email.mime.text import MIMEText as _MIMEText
from email.parser import Parser as _Parser
from email.utils import formataddr as _formataddr
from email.utils import getaddresses as _getaddresses


__version__ = '0.2'


LOG = _logging.getLogger('pgp-mime')
LOG.setLevel(_logging.ERROR)
LOG.addHandler(_logging.StreamHandler())

ENCODING = 'utf-8'
#ENCODING = 'iso-8859-1'

GPG_ARGS = [
    '/usr/bin/gpg', '--no-verbose', '--quiet', '--batch', '--output', '-',
    '--armor', '--textmode']
GPG_SIGN_ARGS = ['--detach-sign']
GPG_ENCRYPT_ARGS = ['--encrypt', '--always-trust']
GPG_SIGN_AND_ENCRYPT_ARGS = ['--sign', '--encrypt', '--always-trust']
SENDMAIL = ['/usr/sbin/sendmail', '-t']


def get_smtp_params(config):
    r"""Retrieve SMTP paramters from a config file.

    >>> from configparser import ConfigParser
    >>> config = ConfigParser()
    >>> config.read_string('\n'.join([
    ...             '[smtp]',
    ...             'host: smtp.mail.uu.edu',
    ...             'port: 587',
    ...             'starttls: yes',
    ...             'username: rincewind',
    ...             'password: 7ugg@g3',
    ...             ]))
    >>> get_smtp_params(config)
    ('smtp.mail.uu.edu', 587, True, 'rincewind', '7ugg@g3')
    >>> config = ConfigParser()
    >>> get_smtp_params(ConfigParser())
    (None, None, None, None, None)
    """
    try:
        host = config.get('smtp', 'host')
    except _configparser.NoSectionError:
        return (None, None, None, None, None)
    except _configparser.NoOptionError:
        host = None
    try:
        port = config.getint('smtp', 'port')
    except _configparser.NoOptionError:
        port = None
    try:
        starttls = config.getboolean('smtp', 'starttls')
    except _configparser.NoOptionError:
        starttls = None
    try:
        username = config.get('smtp', 'username')
    except _configparser.NoOptionError:
        username = None
    try:
        password = config.get('smtp', 'password')
    except _configparser.NoOptionError:
        password = None
    return (host, port, starttls, username, password)

def get_smtp(host=None, port=None, starttls=None, username=None,
             password=None):
    """Connect to an SMTP host using the given parameters.

    >>> import smtplib
    >>> try:  # doctest: +SKIP
    ...     smtp = get_smtp(host='smtp.gmail.com', port=587, starttls=True,
    ...         username='rincewind@uu.edu', password='7ugg@g3')
    ... except smtplib.SMTPAuthenticationError as error:
    ...     print('that was not a real account')
    that was not a real account
    >>> smtp = get_smtp()  # doctest: +SKIP
    >>> smtp.quit()  # doctest: +SKIP
    """
    if host is None:
        host = 'localhost'
    if port is None:
        port = _smtplib.SMTP_PORT
    if username and not starttls:
        raise ValueError(
            'sending passwords in the clear is unsafe!  Use STARTTLS.')
    LOG.info('connect to SMTP server at {}:{}'.format(host, port))
    smtp = _smtplib.SMTP(host=host, port=port)
    smtp.ehlo()
    if starttls:
        smtp.starttls()
    if username:
        smtp.login(username, password)
    #smtp.set_debuglevel(1)
    return smtp

def mail(message, smtp=None, sendmail=None):
    """Send an email ``Message`` instance on its merry way.

    We can shell out to the user specified sendmail in case
    the local host doesn't have an SMTP server set up
    for easy ``smtplib`` usage.

    >>> message = encodedMIMEText('howdy!')
    >>> message['From'] = 'John Doe <jdoe@a.gov.ru>'
    >>> message['To'] = 'Jack <jack@hill.org>, Jill <jill@hill.org>'
    >>> mail(message=message, sendmail=SENDMAIL)
    """
    LOG.info('send message {} -> {}'.format(message['from'], message['to']))
    if smtp:
        smtp.send_message(msg=message)
    elif sendmail:
        execute(sendmail, stdin=message.as_string().encode('us-ascii'))
    else:
        smtp = _smtplib.SMTP()
        smtp.connect()
        smtp.send_message(msg=message)
        smtp.close()

def header_from_text(text):
    r"""Simple wrapper for instantiating a ``Message`` from text.

    >>> text = '\n'.join(
    ...     ['From: me@big.edu','To: you@big.edu','Subject: testing'])
    >>> header = header_from_text(text=text)
    >>> print(header.as_string())  # doctest: +REPORT_UDIFF
    From: me@big.edu
    To: you@big.edu
    Subject: testing
    <BLANKLINE>
    <BLANKLINE>
    """
    text = text.strip()
    p = _Parser()
    return p.parsestr(text, headersonly=True)

def guess_encoding(text):
    r"""
    >>> guess_encoding('hi there')
    'us-ascii'
    >>> guess_encoding('✉')
    'utf-8'
    """
    for encoding in ['us-ascii', ENCODING, 'utf-8']:
        try:
            text.encode(encoding)
        except UnicodeEncodeError:
            pass
        else:
            return encoding
    raise ValueError(text)

def encodedMIMEText(body, encoding=None):
    """Wrap ``MIMEText`` with ``guess_encoding`` detection.

    >>> message = encodedMIMEText('Hello')
    >>> print(message.as_string())  # doctest: +REPORT_UDIFF
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    <BLANKLINE>
    Hello
    >>> message = encodedMIMEText('Джон Доу')
    >>> print(message.as_string())  # doctest: +REPORT_UDIFF
    Content-Type: text/plain; charset="utf-8"
    MIME-Version: 1.0
    Content-Transfer-Encoding: base64
    Content-Disposition: inline
    <BLANKLINE>
    0JTQttC+0L0g0JTQvtGD
    <BLANKLINE>
    """
    if encoding == None:
        encoding = guess_encoding(body)
    if encoding == 'us-ascii':
        message = _MIMEText(body)
    else:
        # Create the message ('plain' stands for Content-Type: text/plain)
        message = _MIMEText(body, 'plain', encoding)
    message.add_header('Content-Disposition', 'inline')
    return message

def strip_bcc(message):
    """Remove the Bcc field from a ``Message`` in preparation for mailing

    >>> message = encodedMIMEText('howdy!')
    >>> message['To'] = 'John Doe <jdoe@a.gov.ru>'
    >>> message['Bcc'] = 'Jack <jack@hill.org>, Jill <jill@hill.org>'
    >>> message = strip_bcc(message)
    >>> print(message.as_string())  # doctest: +REPORT_UDIFF
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    To: John Doe <jdoe@a.gov.ru>
    <BLANKLINE>
    howdy!
    """
    del message['bcc']
    del message['resent-bcc']
    return message

def append_text(text_part, new_text):
    r"""Append text to the body of a ``plain/text`` part.

    Updates encoding as necessary.

    >>> message = encodedMIMEText('Hello')
    >>> append_text(message, ' John Doe')
    >>> print(message.as_string())  # doctest: +REPORT_UDIFF
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Disposition: inline
    Content-Transfer-Encoding: 7bit
    <BLANKLINE>
    Hello John Doe
    >>> append_text(message, ', Джон Доу')
    >>> print(message.as_string())  # doctest: +REPORT_UDIFF
    MIME-Version: 1.0
    Content-Disposition: inline
    Content-Type: text/plain; charset="utf-8"
    Content-Transfer-Encoding: base64
    <BLANKLINE>
    SGVsbG8gSm9obiBEb2UsINCU0LbQvtC9INCU0L7Rgw==
    <BLANKLINE>
    >>> append_text(message, ', and Jane Sixpack.')
    >>> print(message.as_string())  # doctest: +REPORT_UDIFF
    MIME-Version: 1.0
    Content-Disposition: inline
    Content-Type: text/plain; charset="utf-8"
    Content-Transfer-Encoding: base64
    <BLANKLINE>
    SGVsbG8gSm9obiBEb2UsINCU0LbQvtC9INCU0L7RgywgYW5kIEphbmUgU2l4cGFjay4=
    <BLANKLINE>
    """
    original_encoding = text_part.get_charset().input_charset
    original_payload = str(
        text_part.get_payload(decode=True), original_encoding)
    new_payload = '{}{}'.format(original_payload, new_text)
    new_encoding = guess_encoding(new_payload)
    if text_part.get('content-transfer-encoding', None):
        # clear CTE so set_payload will set it properly for the new encoding
        del text_part['content-transfer-encoding']
    text_part.set_payload(new_payload, new_encoding)

def attach_root(header, root_part):
    r"""Copy headers from ``header`` onto ``root_part``.

    >>> header = header_from_text('From: me@big.edu\n')
    >>> body = encodedMIMEText('Hello')
    >>> message = attach_root(header, body)
    >>> print(message.as_string())  # doctest: +REPORT_UDIFF
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    From: me@big.edu
    <BLANKLINE>
    Hello
    """
    for k,v in header.items():
        root_part[k] = v
    return root_part    

def execute(args, stdin=None, expect=(0,), env=_os.environ):
    """Execute a command (allows us to drive gpg).
    """
    LOG.debug('$ {}'.format(args))
    try:
        p = _subprocess.Popen(
            args, stdin=_subprocess.PIPE, stdout=_subprocess.PIPE,
            stderr=_subprocess.PIPE, shell=False, close_fds=True, env=env)
    except OSError as e:
        raise Exception('{}\nwhile executing {}'.format(e.args[1], args))
    output,error = p.communicate(input=stdin)
    status = p.wait()
    LOG.debug('(status: {})\n{}{}'.format(status, output, error))
    if status not in expect:
        raise Exception('unexpected status while executing {}\n{}\n{}'.format(
                args, error, status))
    return (status, output, error)

def getaddresses(addresses):
    """A decoding version of ``email.utils.getaddresses``.

    >>> text = ('To: =?utf-8?b?0JTQttC+0L0g0JTQvtGD?= <jdoe@a.gov.ru>, '
    ...     'Jack <jack@hill.org>')
    >>> header = header_from_text(text=text)
    >>> list(getaddresses(header.get_all('to', [])))
    [('Джон Доу', 'jdoe@a.gov.ru'), ('Jack', 'jack@hill.org')]
    """
    for (name,address) in _getaddresses(addresses):
        n = []
        for b,encoding in _decode_header(name):
            if encoding is None:
                n.append(b)
            else:
                n.append(str(b, encoding))
        yield (' '.join(n), address)

def email_sources(message):
    """Extract author address from an email ``Message``

    Search the header of an email Message instance to find the
    senders' email addresses (or sender's address).

    >>> text = ('From: =?utf-8?b?0JTQttC+0L0g0JTQvtGD?= <jdoe@a.gov.ru>, '
    ...     'Jack <jack@hill.org>')
    >>> header = header_from_text(text=text)
    >>> list(email_sources(header))
    [('Джон Доу', 'jdoe@a.gov.ru'), ('Jack', 'jack@hill.org')]
    """
    froms = message.get_all('from', [])
    return getaddresses(froms) # [(name, address), ...]

def email_targets(message):
    """Extract recipient addresses from an email ``Message``

    Search the header of an email Message instance to find a
    list of recipient's email addresses.

    >>> text = ('To: =?utf-8?b?0JTQttC+0L0g0JTQvtGD?= <jdoe@a.gov.ru>, '
    ...     'Jack <jack@hill.org>')
    >>> header = header_from_text(text=text)
    >>> list(email_targets(header))
    [('Джон Доу', 'jdoe@a.gov.ru'), ('Jack', 'jack@hill.org')]
    """
    tos = message.get_all('to', [])
    ccs = message.get_all('cc', [])
    bccs = message.get_all('bcc', [])
    resent_tos = message.get_all('resent-to', [])
    resent_ccs = message.get_all('resent-cc', [])
    resent_bccs = message.get_all('resent-bcc', [])
    return getaddresses(
        tos + ccs + bccs + resent_tos + resent_ccs + resent_bccs)

def sign_bytes(bytes, sign_as=None):
    r"""Sign ``bytes`` as ``sign_as``.

    >>> print(sign_bytes(bytes(b'Hello'), 'wking@drexel.edu'))
    ... # doctest: +ELLIPSIS
    b'-----BEGIN PGP SIGNATURE-----\n...-----END PGP SIGNATURE-----\n'
    """
    args = GPG_ARGS + GPG_SIGN_ARGS
    if sign_as:
        args.extend(['--local-user', sign_as])
    status,output,error = execute(args, stdin=bytes)
    return output

def encrypt_bytes(bytes, recipients):
    r"""Encrypt ``bytes`` to ``recipients``.

    >>> encrypt_bytes(bytes(b'Hello'), ['wking@drexel.edu'])
    ... # doctest: +ELLIPSIS
    b'-----BEGIN PGP MESSAGE-----\n...-----END PGP MESSAGE-----\n'
    """
    args = GPG_ARGS + GPG_ENCRYPT_ARGS
    if not recipients:
        raise ValueError('no recipients specified for encryption')
    for recipient in recipients:
        args.extend(['--recipient', recipient])
    status,output,error = execute(args, stdin=bytes)
    return output

def sign_and_encrypt_bytes(bytes, sign_as=None, recipients=None):
    r"""Sign ``bytes`` as ``sign_as`` and encrypt to ``recipients``.

    >>> sign_and_encrypt_bytes(
    ...     bytes(b'Hello'), 'wking@drexel.edu', ['wking@drexel.edu'])
    ... # doctest: +ELLIPSIS
    b'-----BEGIN PGP MESSAGE-----\n...-----END PGP MESSAGE-----\n'
    """
    args = GPG_ARGS + GPG_SIGN_AND_ENCRYPT_ARGS
    if sign_as:
        args.extend(['--local-user', sign_as])
    if not recipients:
        raise ValueError('no recipients specified for encryption')
    for recipient in recipients:
        args.extend(['--recipient', recipient])
    status,output,error = execute(args, stdin=bytes)
    return output

def sign(message, sign_as=None):
    r"""Sign a ``Message``, returning the signed version.

    multipart/signed
    +-> text/plain                 (body)
    +-> application/pgp-signature  (signature)

    >>> message = encodedMIMEText('Hi\nBye')
    >>> signed = sign(message, sign_as='0xFC29BDCDF15F5BE8')
    >>> signed.set_boundary('boundsep')
    >>> print(signed.as_string())  # doctest: +ELLIPSIS, +REPORT_UDIFF
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
    Version: GnuPG...
    -----END PGP SIGNATURE-----
    <BLANKLINE>
    --boundsep--

    >>> from email.mime.multipart import MIMEMultipart
    >>> message = MIMEMultipart()
    >>> message.attach(encodedMIMEText('Part A'))
    >>> message.attach(encodedMIMEText('Part B'))
    >>> signed = sign(message, sign_as='0xFC29BDCDF15F5BE8')
    >>> signed.set_boundary('boundsep')
    >>> print(signed.as_string())  # doctest: +ELLIPSIS, +REPORT_UDIFF
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
    Version: GnuPG...
    -----END PGP SIGNATURE-----
    <BLANKLINE>
    --boundsep--
    """
    body = message.as_string().encode('us-ascii')
    signature = str(sign_bytes(body, sign_as), 'us-ascii')
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

def encrypt(message, recipients=None):
    r"""Encrypt a ``Message``, returning the encrypted version.

    multipart/encrypted
    +-> application/pgp-encrypted  (control information)
    +-> application/octet-stream   (body)

    >>> message = encodedMIMEText('Hi\nBye')
    >>> message['To'] = '"W. Trevor King" <wking@drexel.edu>'
    >>> encrypted = encrypt(message)
    >>> encrypted.set_boundary('boundsep')
    >>> print(encrypted.as_string())  # doctest: +ELLIPSIS, +REPORT_UDIFF
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
    Version: GnuPG...
    -----END PGP MESSAGE-----
    <BLANKLINE>
    --boundsep--

    >>> from email.mime.multipart import MIMEMultipart
    >>> message = MIMEMultipart()
    >>> message.attach(encodedMIMEText('Part A'))
    >>> message.attach(encodedMIMEText('Part B'))
    >>> encrypted = encrypt(message, recipients=['F15F5BE8'])
    >>> encrypted.set_boundary('boundsep')
    >>> print(encrypted.as_string()) # doctest: +ELLIPSIS, +REPORT_UDIFF
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
    Version: GnuPG...
    -----END PGP MESSAGE-----
    <BLANKLINE>
    --boundsep--
    """
    body = message.as_string().encode('us-ascii')
    if recipients is None:
        recipients = [email for name,email in email_targets(message)]
        LOG.debug('extracted encryption recipients: {}'.format(recipients))
    encrypted = str(encrypt_bytes(body, recipients), 'us-ascii')
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

def sign_and_encrypt(message, sign_as=None, recipients=None):
    r"""Sign and encrypt a ``Message``, returning the encrypted version.

    multipart/encrypted
     +-> application/pgp-encrypted  (control information)
     +-> application/octet-stream   (body)

    >>> message = encodedMIMEText('Hi\nBye')
    >>> message['To'] = '"W. Trevor King" <wking@drexel.edu>'
    >>> encrypted = sign_and_encrypt(message)
    >>> encrypted.set_boundary('boundsep')
    >>> print(encrypted.as_string())  # doctest: +ELLIPSIS, +REPORT_UDIFF
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
    Version: GnuPG...
    -----END PGP MESSAGE-----
    <BLANKLINE>
    --boundsep--

    >>> from email.mime.multipart import MIMEMultipart
    >>> message = MIMEMultipart()
    >>> message.attach(encodedMIMEText('Part A'))
    >>> message.attach(encodedMIMEText('Part B'))
    >>> encrypted = sign_and_encrypt(message, recipients=['F15F5BE8'])
    >>> encrypted.set_boundary('boundsep')
    >>> print(encrypted.as_string()) # doctest: +ELLIPSIS, +REPORT_UDIFF
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
    Version: GnuPG...
    -----END PGP MESSAGE-----
    <BLANKLINE>
    --boundsep--
    """
    strip_bcc(message=message)
    body = message.as_string().encode('us-ascii')
    if recipients is None:
        recipients = [email for name,email in email_targets(message)]
        LOG.debug('extracted encryption recipients: {}'.format(recipients))
    encrypted = str(sign_and_encrypt_bytes(
            body, sign_as=sign_as, recipients=recipients), 'us-ascii')
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
