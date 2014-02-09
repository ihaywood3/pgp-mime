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

"""Python module and tools for constructing and sending pgp/mime email.

Uses ``pyassuan`` to connect to ``gpgme-tool`` for the cryptography.
"""

import logging as _logging


__version__ = '0.3-nopyassuan'


LOG = _logging.getLogger('pgp-mime')
LOG.setLevel(_logging.ERROR)
LOG.addHandler(_logging.StreamHandler())


from .pgp import sign, encrypt, sign_and_encrypt, decrypt, verify
from .email import (
    header_from_text, guess_encoding, encodedMIMEText, strip_bcc, append_text,
    attach_root, getaddresses, email_sources, email_targets)
from .smtp import get_smtp_params, get_smtp, mail
