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

try:
    from io import BytesIO
except ImportError:
    from StringIO import StringIO as BytesIO

def sign_and_encrypt_bytes(data, signers=None, recipients=None,
                           always_trust=False, mode='detach',
                           allow_default_signer=False, ctx=None, **kwargs):
    r"""Sign ``data`` with ``signers`` and encrypt to ``recipients``.

    Just sign (with a detached signature):

    >>> print(sign_and_encrypt_bytes(
    ...     bytes(b'Hello'), signers=True))
    ... # doctest: +ELLIPSIS
    -----BEGIN PGP SIGNATURE-----
    ...
    -----END PGP SIGNATURE-----

    Just encrypt:

    >>> print(sign_and_encrypt_bytes(
    ...     bytes(b'Hello'), recipients=['ian@haywood.id.au'],
    ...     always_trust=True))
    ... # doctest: +ELLIPSIS
    -----BEGIN PGP MESSAGE-----
    ...
    -----END PGP MESSAGE-----

    Sign and encrypt:

    >>> print(sign_and_encrypt_bytes(
    ...     bytes(b'Hello'), signers=True,
    ...     recipients=['ian@haywood.id.au'], always_trust=True))
    ... # doctest: +ELLIPSIS
    -----BEGIN PGP MESSAGE-----
    ...
    -----END PGP MESSAGE-----

    Sign and encrypt with a specific subkey:

    >>> print(sign_and_encrypt_bytes(
    ...     bytes(b'Hello'), signers=['ian@haywood.id.au'],
    ...     recipients=['ian@haywood.id.au'], always_trust=True))
    ... # doctest: +ELLIPSIS
    -----BEGIN PGP MESSAGE-----
    ...
    -----END PGP MESSAGE-----
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
    'Hello'
    >>> verified
    True
    >>> print(signatures)
    [Signature(chain_model=False, 
    exp_timestamp=0L,
    fpr='9BF067B7F84FF7EE0C42C06328FCBC52E750652E', 
    hash_algo=2, 
    key=None, 
    notations=[], 
    pka_address=None, 
    pka_trust=0, 
    pubkey_algo=17, 
    status=0L, 
    summary=3, 
    timestamp=1502926440L, 
    validity=4, 
    validity_reason=0L, 
    wrong_key_usage=False)]
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

if __name__ == "__main__":
    import doctest
    doctest.testmod(optionflags=doctest.NORMALIZE_WHITESPACE|doctest.ELLIPSIS)
