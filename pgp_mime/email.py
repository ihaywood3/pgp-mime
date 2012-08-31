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

from __future__ import absolute_import

from email.header import decode_header as _decode_header
from email.message import Message as _Message
from email.mime.text import MIMEText as _MIMEText
from email.parser import Parser as _Parser
from email.utils import formataddr as _formataddr
from email.utils import getaddresses as _getaddresses


ENCODING = 'utf-8'
#ENCODING = 'iso-8859-1'


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
