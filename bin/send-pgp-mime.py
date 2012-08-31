#!/usr/bin/env python3
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

"""Scriptable PGP MIME email using ``gpg``.

You can use ``gpg-agent`` for passphrase caching if your key requires
a passphrase (it better!).  Example usage would be to install
``gpg-agent``, and then run::

  $ export GPG_TTY=`tty`
  $ eval $(gpg-agent --daemon)

in your shell before invoking this script.  See ``gpg-agent(1)`` for
more details.
"""

import codecs as _codecs
import configparser as _configparser
import logging as _logging
import mimetypes as _mimetypes
import os.path as _os_path
import sys as _sys

from email.encoders import encode_base64 as _encode_base64
from email.mime.application import MIMEApplication as _MIMEApplication
from email.mime.audio import MIMEAudio as _MIMEAudio
from email.mime.image import MIMEImage as _MIMEImage
from email.mime.multipart import MIMEMultipart as _MIMEMultipart
from email.mime.nonmultipart import MIMENonMultipart as _MIMENonMultipart

import pgp_mime as _pgp_mime


STDIN_USED = False


def read_file(filename=None, encoding='us-ascii'):
    global STDIN_USED
    if filename == '-':
        assert STDIN_USED == False, STDIN_USED
        STDIN_USED = True
        return _sys.stdin.read()
    if filename:
        return _codecs.open(filename, 'r', encoding).read()
    raise ValueError('neither filename nor descriptor given for reading')

def load_attachment(filename, encoding='us-ascii'):
    mimetype,content_encoding = _mimetypes.guess_type(filename)
    if mimetype is None or content_encoding is not None:
        mimetype = 'application/octet-stream'
    maintype,subtype = mimetype.split('/', 1)
    _pgp_mime.LOG.info('loading attachment {} as {} ({})'.format(
            filename, mimetype, content_encoding))
    if maintype == 'text':
        text = read_file(filename=filename, encoding=encoding)
        attachment = _pgp_mime.encodedMIMEText(text)
        del attachment['content-disposition']
    else:
        data = open(filename, 'rb').read()
        if maintype == 'application':
            attachment = _MIMEApplication(data, subtype)
        elif maintype == 'audio':
            attachment = _MIMEAudio(data)
        elif maintype == 'image':
            attachment = _MIMEImage(data)
        else:
            attachment = _MIMENonMultipary(maintype, subtype)
            attachment.set_payload(data, _encode_base64)
    attachment.add_header(
        'Content-Disposition', 'attachment', filename=filename)
    return attachment


if __name__ == '__main__':
    import argparse

    doc_lines = __doc__.splitlines()
    parser = argparse.ArgumentParser(
        description = doc_lines[0],
        epilog = '\n'.join(doc_lines[1:]).strip(),
        version=_pgp_mime.__version__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        '-e', '--encoding', metavar='ENCODING', default='utf-8',
        help='encoding for input files')
    parser.add_argument(
        '-H', '--header-file', metavar='FILE',
        help='file containing email header')
    parser.add_argument(
        '-B', '--body-file', metavar='FILE',
        help='file containing email body')
    parser.add_argument(
        '-a', '--attachment', metavar='FILE', action='append',
        help='add an attachment to your message')
    parser.add_argument(
        '-m', '--mode', default='sign', metavar='MODE',
        choices=['sign', 'encrypt', 'sign-encrypt', 'plain'],
        help='encryption mode')
    parser.add_argument(
        '-s', '--sign-as', metavar='KEY',
        help="gpg key to sign with (gpg's -u/--local-user)")
    parser.add_argument(
        '-c', '--config', metavar='FILE',
        default=_os_path.expanduser(_os_path.join(
                '~', '.config', 'smtplib.conf')),
        help='SMTP config file for sending mail'),
    parser.add_argument(
        '--output', action='store_const', const=True,
        help="don't mail the generated message, print it to stdout instead")
    parser.add_argument(
        '-V', '--verbose', default=0, action='count',
        help='increment verbosity')

    args = parser.parse_args()

    if args.verbose:
        _pgp_mime.LOG.setLevel(max(
                _logging.DEBUG, _pgp_mime.LOG.level - 10*args.verbose))

    header_text = read_file(filename=args.header_file, encoding=args.encoding)
    header = _pgp_mime.header_from_text(header_text)
    body_text = read_file(filename=args.body_file, encoding=args.encoding)
    body = _pgp_mime.encodedMIMEText(body_text)
    if args.attachment:
        b = _MIMEMultipart()
        b.attach(body)
        body = b
        _mimetypes.init()
        for attachment in args.attachment:
            body.attach(load_attachment(
                    filename=attachment, encoding=args.encoding))
    if args.sign_as:
        signers = [args.sign_as]
    else:
        signers = None
    if 'encrypt' in args.mode:
        recipients = [email for name,email in _pgp_mime.email_targets(header)]
    if args.mode == 'sign':
        body = _pgp_mime.sign(body, signers=signers, allow_default_signer=True)
    elif args.mode == 'encrypt':
        body = _pgp_mime.encrypt(body, recipients=recipients)
    elif args.mode == 'sign-encrypt':
        body = _pgp_mime.sign_and_encrypt(
            body, signers=signers, recipients=recipients,
            allow_default_signer=True)
    elif args.mode == 'plain':
        pass
    else:
        raise Exception('unrecognized mode {}'.format(args.mode))
    message = _pgp_mime.attach_root(header, body)

    if args.output:
        print(message.as_string())
    else:
        config = _configparser.ConfigParser()
        config.read(args.config)
        params = _pgp_mime.get_smtp_params(config)
        smtp = _pgp_mime.get_smtp(*params)
        try:
            _pgp_mime.mail(message, smtp)
        finally:
            _pgp_mime.LOG.info('disconnect from SMTP server')
            smtp.quit()
