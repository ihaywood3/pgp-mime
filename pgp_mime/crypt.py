# Copyright (C) 2014 Johannes Schlatow <johannes.schlatow@googlemail.com>
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

import gpg
import gpg.constants as constants
import time

try:
    from io import BytesIO, StringIO
except ImportError:
    from StringIO import StringIO as BytesIO
    from StringIO import StringIO

def sign_and_encrypt_bytes(data, signers=None, recipients=None,
                           always_trust=False, mode='detach',
                           allow_default_signer=False, ctx=None, **kwargs):
    r"""Sign ``data`` with ``signers`` and encrypt to ``recipients``.

    Just sign (with a detached signature):

    >>> sign_and_encrypt_bytes(b'Hello', signers=True)
    b'-----BEGIN PGP SIGNATURE-----...-----END PGP SIGNATURE-----\n'

    Just encrypt:

    >>> sign_and_encrypt_bytes(b'Hello', recipients=['ian@haywood.id.au'],
    ...     always_trust=True)
    ... # doctest: +ELLIPSIS
    b'-----BEGIN PGP MESSAGE-----...-----END PGP MESSAGE-----\n'

    Sign and encrypt:

    >>> sign_and_encrypt_bytes(
    ...     b'Hello', signers=True,
    ...     recipients=['ian@haywood.id.au'], always_trust=True)
    ... # doctest: +ELLIPSIS
    b'-----BEGIN PGP MESSAGE-----...-----END PGP MESSAGE-----\n'

    Sign and encrypt with a specific subkey:

    >>> sign_and_encrypt_bytes(
    ...     b'Hello', signers=['ian@haywood.id.au'],
    ...     recipients=['ian@haywood.id.au'], always_trust=True)
    ... # doctest: +ELLIPSIS
    b'-----BEGIN PGP MESSAGE-----...-----END PGP MESSAGE-----\n'
    """
    if not ctx:
        ctx = gpg.Context()
    ctx.armor = True
    if recipients:
        keys = [ctx.get_key(i) for i in recipients]
    if signers and type(signers) is list:
        ctx.signers = [ctx.get_key(i) for i in signers]

    if recipients:
        if signers:
            cipher, _, _ = ctx.encrypt(data, recipients=keys, sign=True, always_trust=always_trust)
        else:
            cipher, _, _ = ctx.encrypt(data, recipients=keys, sign=False, always_trust=always_trust)
    elif mode == "detach":
        cipher, _ = ctx.sign(data, mode=constants.SIG_MODE_DETACH)
    else:
        cipher, _ = ctx.sign(data, mode=constants.SIG_MODE_NORMAL)

    return cipher

def verify_bytes(data, signature=None, always_trust=False, ctx=None, **kwargs):
    r"""Verify a signature on ``data``, possibly decrypting first.

    These tests assume you do trust the key.

    >>> b = '\n'.join([
    ...     '-----BEGIN PGP MESSAGE-----',
    ...     '',
    ...     'jA0EBwMCWRBmko3MkBjk0p4BrqRwPUeG0PKgWS+vPELpixMs2CMIuIypiDGe42rb',
    ...     'Ip0MTHN9VqEGw29UdGQ7wPDFe4KX5++ugPijR1lHoyd35Yk9C47uZxh7okzvyj/x',
    ...     '+HLgY115BP/Y7eAX8hrs1f3dXueROfzMbbyOMunXhPfRbKqRCS2RHWIp+tphZTU7',
    ...     'g17VL1vN1+KgiTFBBrbSllEazso3ffeQabO2dp92HQ==\n=1koP',
    ...     '-----END PGP MESSAGE-----',
    ...     '',
    ...     ]).encode('us-ascii')
    ...     # doctest: +NORMALIZE_WHITESPACE
    >>> output,verified,signatures = verify_bytes(b)
    >>> output
    b'Hello'
    >>> verified
    True
    >>> signatures
    [Signature(chain_model=False, exp_timestamp=0, fpr='9BF067B7F84FF7EE0C42C06328FCBC52E750652E', hash_algo=2, key=None, notations=[], pka_address=None, pka_trust=0, pubkey_algo=17, status=0, summary=3, timestamp=1502926440, validity=4, validity_reason=0, wrong_key_usage=False)]
    """
    if not ctx:
        ctx = gpg.Context()
    ctx.armor = True
    if signature:
        plain, sigdata = ctx.verify(data, signature=signature)
    else:
        plain, sigdata = ctx.verify(data)
    verified = True
    if not always_trust:
        for sig in sigdata.signatures:
            if not (sig.summary & constants.SIGSUM_VALID):
                verified = False
    return (plain, verified, sigdata.signatures)

def process_signature(sig,ctx=None):
    r"""Process a single signature and return a short string describing it
    Will be of the form 'Good signature from X on Y' or 'Bad signature: XXX'

    >>> b = '\n'.join([
    ...     '-----BEGIN PGP MESSAGE-----',
    ...     '',
    ...     'jA0EBwMCWRBmko3MkBjk0p4BrqRwPUeG0PKgWS+vPELpixMs2CMIuIypiDGe42rb',
    ...     'Ip0MTHN9VqEGw29UdGQ7wPDFe4KX5++ugPijR1lHoyd35Yk9C47uZxh7okzvyj/x',
    ...     '+HLgY115BP/Y7eAX8hrs1f3dXueROfzMbbyOMunXhPfRbKqRCS2RHWIp+tphZTU7',
    ...     'g17VL1vN1+KgiTFBBrbSllEazso3ffeQabO2dp92HQ==\n=1koP',
    ...     '-----END PGP MESSAGE-----',
    ...     '',
    ...     ]).encode('us-ascii')
    ...     # doctest: +NORMALIZE_WHITESPACE
    >>> output,verified,signatures = verify_bytes(b)
    >>> process_signature(signatures[0])
    'Signed by Ian Haywood <ian@haywood.id.au> on Thu Aug 17 09:34:00 2017'

    """
    if not ctx:
        ctx = gpg.Context()
    if sig.summary & constants.SIGSUM_VALID:
        key = ctx.get_key(sig.fpr)
        uid = key.uids[0].uid
        t = time.strftime("%c",time.localtime(sig.timestamp))
        return "Signed by {} on {}".format(uid,t)
    else:
        masks = [(constants.SIGSUM_BAD_POLICY,'bad policy'),
                 (constants.SIGSUM_CRL_TOO_OLD,'CRL too old'),
                 (constants.SIGSUM_KEY_EXPIRED,"Key expired"),
                 (constants.SIGSUM_KEY_REVOKED,"Key revoked by owner"),
                 (constants.SIGSUM_SIG_EXPIRED,"Signature expired"),
                 (constants.SIGSUM_TOFU_CONFLICT,"Multiple conflicting keys"),
                 (constants.SIGSUM_CRL_MISSING,"CRL missing"),
                 (constants.SIGSUM_KEY_MISSING,"Kewy missing"),
                 (constants.SIGSUM_SYS_ERROR,"System error")]
        return "Bad signature: "+", ".join(c for m, c in masks if m & sig.summary)


def uid_from_signature(sig,ctx=None):
    if not ctx:
        ctx = gpg.Context()
    if sig.fpr:
        key = ctx.get_key(sig.fpr)
        return key.uids[0].uid
    else:
        return None

if __name__ == "__main__":
    import doctest
    doctest.testmod(optionflags=doctest.NORMALIZE_WHITESPACE|doctest.ELLIPSIS)
