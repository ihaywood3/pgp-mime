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

import configparser as _configparser
import smtplib as _smtplib

from . import LOG as _LOG


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
    _LOG.info('connect to SMTP server at {}:{}'.format(host, port))
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

    >>> from pgp_mime.email import encodedMIMEText
    >>> message = encodedMIMEText('howdy!')
    >>> message['From'] = 'John Doe <jdoe@a.gov.ru>'
    >>> message['To'] = 'Jack <jack@hill.org>, Jill <jill@hill.org>'
    >>> mail(message=message, sendmail=SENDMAIL)  # doctest: +SKIP
    """
    _LOG.info('send message {} -> {}'.format(message['from'], message['to']))
    if smtp:
        smtp.send_message(msg=message)
    elif sendmail:
        execute(
            sendmail, stdin=message.as_string().encode('us-ascii'),
            close_fds=True)
    else:
        smtp = _smtplib.SMTP()
        smtp.connect()
        smtp.send_message(msg=message)
        smtp.close()
