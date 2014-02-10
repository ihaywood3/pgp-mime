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

import gpgme
try:
    from io import BytesIO
except ImportError:
    from StringIO import StringIO as BytesIO

def sign_and_encrypt_bytes(data, signers=None, recipients=None,
                           always_trust=False, mode='detach',
                           allow_default_signer=False, **kwargs):
    r"""Sign ``data`` with ``signers`` and encrypt to ``recipients``.

    Just sign (with a detached signature):

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

    Sign and encrypt with a specific subkey:

    >>> sign_and_encrypt_bytes(
    ...     bytes(b'Hello'), signers=['0x7B2E921E'],
    ...     recipients=['pgp-mime@invalid.com'], always_trust=True)
    ... # doctest: +ELLIPSIS
    b'-----BEGIN PGP MESSAGE-----\n...-----END PGP MESSAGE-----\n'
    """
    ctx = gpgme.Context()
    ctx.armor = True
    keys=list()
    if recipients:
        for recipient in recipients:
            keys.append(ctx.get_key(recipient))
    if signers:
        ctx.signers = [ctx.get_key(signers[0])]

    plain = BytesIO(data)
    cipher = BytesIO()

    if recipients:
        if signers:
            ctx.encrypt_sign(keys, always_trust, plain, cipher)
        else:
            ctx.encrypt(keys, always_trust, plain, cipher)
    elif mode == "detach":
        ctx.sign(plain, cipher, gpgme.SIG_MODE_DETACH)        
    else:
        ctx.sign(plain, cipher, gpgme.SIG_MODE_NORMAL)        

    return cipher.getvalue()

def verify_bytes(data, signature=None, always_trust=False, **kwargs):
    r"""Verify a signature on ``data``, possibly decrypting first.

    These tests assume you didn't trust the distributed test key.

#    >>> b = '\n'.join([
#    ...     '-----BEGIN PGP MESSAGE-----',
#    ...     'Version: GnuPG v2.0.17 (GNU/Linux)',
#    ...     '',
#    ...     'hQEMA1Ea7aZDMrbjAQf/YM1SeFzNGz0DnUynaEyhfGCvcqmjtbN1PtZMpT7VaQLN',
#    ...     'a+c0faskr79Atz0+2IBR7CDOlcETrRtH2EnrWukbRIDtmffNFGuhMRTNfnQ15OIN',
#    ...     'qrmt2P5gXznsgnm2XjzTK7S/Cc3Aq+zjaDrDt7bIedEdz+EyNgaKuL/lB9cAB8xL',
#    ...     'YYp/yn55Myjair2idgzsa7w/QXdE3RhpyRLqR2Jgz4P1I1xOgUYnylbpIZL9FOKN',
#    ...     'NR3RQhkGdANBku8otfthb5ZUGsNMV45ct4V8PE+xChjFb9gcwpaf1hhoIF/sYHD5',
#    ...     'Bkf+v/J8F40KGYY16b0DjQIUlnra9y7q9jj0h2bvc9LAtgHtVUso133LLcVYl7RP',
#    ...     'Vjyz9Ps366BtIdPlAL4CoF5hEcMKS5J3h1vRlyAKN4uHENl5vKvoxn7ID3JhhWQc',
#    ...     '6QrPGis64zi3OnYor34HPh/KNJvkgOQkekmtYuTxnkiONA4lhMDJgeaVZ9WZq+GV',
#    ...     'MaCvCFGNYU2TV4V8wMlnUbF8d5bDQ83g8MxIVKdDcnBzzYLZha+qmz4Spry9iB53',
#    ...     'Sg/sM5H8gWWSl7Oj1lxVg7o7IscpQfVt6zL6jD2VjL3L3Hu7WEXIrcGZtvrP4d+C',
#    ...     'TGYWiGlh5B2UCFk2bVctfw8W/QfaVvJYD4Rfqta2V2p14KIJLFRSGa1g26W4ixrH',
#    ...     'XKxgaA3AIfJ+6c5RoisRLuYCxvQi91wkE9hAXR+inXK4Hq4SmiHoeITZFhHP3hh3',
#    ...     'rbpp8mopiMNxWqCbuqgILP6pShn4oPclu9aR8uJ1ziDxISTGYC71mvLUERUjFn2L',
#    ...     'fu6C0+TCC9RmeyL+eNdM6cjs1G7YR6yX',
#    ...     '=phHd',
#    ...     '-----END PGP MESSAGE-----',
#    ...     '',
#    ...     ]).encode('us-ascii')
#    >>> output,verified,signatures = verify_bytes(b)
#    >>> output
#    b'Success!\n'
#    >>> verified
#    False
#    >>> for s in signatures:
#    ...     print(s.dumps())
#    ... # doctest: +REPORT_UDIFF
#    B2EDBE0E771A4B8708DD16A7511AEDA64332B6E3 signature:
#      summary:
#        CRL missing: False
#        CRL too old: False
#        bad policy: False
#        green: False
#        key expired: False
#        key missing: False
#        key revoked: False
#        red: False
#        signature expired: False
#        system error: False
#        valid: False
#      status: success
#      timestamp: Wed Mar 21 19:13:57 2012
#      expiration timestamp: None
#      wrong key usage: False
#      pka trust: not available
#      chain model: False
#      validity: unknown
#      validity reason: success
#      public key algorithm: RSA
#      hash algorithm: SHA256
#    >>> b = b'Success!\n'
#    >>> signature = '\n'.join([
#    ...     '-----BEGIN PGP SIGNATURE-----',
#    ...     'Version: GnuPG v2.0.17 (GNU/Linux)',
#    ...     '',
#    ...     'iQEcBAEBAgAGBQJPaiw/AAoJEFEa7aZDMrbj93gH/1fQPXLjUTpONJUTmvGoMLNA',
#    ...     'W9ZhjpUL5i6rRqYGUvQ4kTEDuPMxkMrCyFCDHEhSDHufMek6Nso5/HeJn3aqxlgs',
#    ...     'hmNlvAq4FI6JQyFL7eCp/XG9cPx1p42dTI7JAih8FuK21sS4m/H5XP3R/6KXC99D',
#    ...     '39rrXCvvR+yNgKe2dxuJwmKuLteVlcWxiIQwVrYK70GtJHC5BO79G8yGccWoEy9C',
#    ...     '9JkJiyNptqZyFjGBNmMmrCSFZ7ZFA02RB+laRmwuIiozw4TJYEksxPrgZMbbcFzx',
#    ...     'zs3JHyV23+Fz1ftalvwskHE7tJkX9Ub8iBMNZ/KxJXXdPdpuMdEYVjoUehkQBQE=',
#    ...     '=rRBP',
#    ...     '-----END PGP SIGNATURE-----',
#    ...     '',
#    ...     ]).encode('us-ascii')
#    >>> output,verified,signatures = verify_bytes(b, signature=signature)
#    >>> output
#    b'Success!\n'
#    >>> verified
#    False
#    >>> for s in signatures:
#    ...     print(s.dumps())
#    ... # doctest: +REPORT_UDIFF
#    B2EDBE0E771A4B8708DD16A7511AEDA64332B6E3 signature:
#      summary:
#        CRL missing: False
#        CRL too old: False
#        bad policy: False
#        green: False
#        key expired: False
#        key missing: False
#        key revoked: False
#        red: False
#        signature expired: False
#        system error: False
#        valid: False
#      status: success
#      timestamp: Wed Mar 21 19:30:07 2012
#      expiration timestamp: None
#      wrong key usage: False
#      pka trust: not available
#      chain model: False
#      validity: unknown
#      validity reason: success
#      public key algorithm: RSA
#      hash algorithm: SHA1
#
#    Data signed by a subkey returns the subkey fingerprint.  To find
#    the primary key for a given subkey, use
#    ``pgp_mime.key.lookup_keys()``.
#
#    >>> b = '\n'.join([
#    ...     '-----BEGIN PGP MESSAGE-----',
#    ...     'Version: GnuPG v2.0.19 (GNU/Linux)',
#    ...     '',
#    ...     'hQEMAxcQCLovc94uAQf9ErTZnr0lYRlLLZIk1VcpNNTHrMro+BmqpFC0jprA4/2m',
#    ...     '92klBF4TIS1A9bU5oxzQquaAIDV42P3sXrbxu/YhHLmPGH+dc2JVSfPLL0XOL5GC',
#    ...     'qpQYe5lglRBReFSRktrfhukjHBoXvh3c8T4xYK2r+nIV4gsp+FrSQMIOdhhBoC36',
#    ...     'U1MOk+R+I0JDbWdzZzJONs7ZcAcNDVKqxmAXZUqVgkhPpnGBSBuF9ExKRT3S6e5N',
#    ...     'Rsorb/DjGIUHSZuH2EaWAUz1jJ3nSta7TnveT/avfJiAV7cRS4oVgyyFyuHO5gkI',
#    ...     'o0obeJaut3enVgpq2TUUk0M4L8TX4jjKvDGAYNyuPNLAsQFHLj5eLmJSudGStWuA',
#    ...     'WjKLqBHD0M8/OcwnrTMleJl+h50ZsHO1tvvkXelH+w/jD5SMS+ktxq2Te8Vj7BmM',
#    ...     '0WQn3Ys7ViA5PgcSpbqNNLdgc1EMcpPI/sfJAORPKVWRPBKDXX/irY2onAMSe5gH',
#    ...     'teNX6bZd/gaoLWqD/1ZhsOCnlV7LY1R929TJ9vxnJcfKKAKwBDfAaSbecUUMECVw',
#    ...     's4u3ZT1pmNslBmH6XSy3ifLYWu/2xsJuhPradT88BJOBARMGg81gOE6zxGRrMLJa',
#    ...     'KojFgqaF2y4nlZAyaJ1Ld4qCaoQogaL9qE1BbmgtBehZ2FNQiIBSLC0fUUl8A4Py',
#    ...     '4d9ZxUoSp7nZmgTN5pUH1N9DIC4ntp/Rak2WnpS7+dRPlp9A2SF0RkeLY+JD9gNm',
#    ...     'j44zBkI79KlgaE/cMt6xUXAF/1ZR/Hv/6GUazGx0l23CnSGuqzLpex2uKOxfKiJt',
#    ...     'jfgyZRhIdFJnRuEXt8dTTDiiYA==',
#    ...     '=0o+x',
#    ...     '-----END PGP MESSAGE-----',
#    ...     '',
#    ...     ]).encode('us-ascii')
#    >>> output,verified,signatures = verify_bytes(b)
#    >>> output
#    b'Hello'
#    >>> verified
#    False
#    >>> for s in signatures:
#    ...     print(s.dumps())
#    ... # doctest: +REPORT_UDIFF
#    DECC812C8795ADD60538B0CD171008BA2F73DE2E signature:
#      summary:
#        CRL missing: False
#        CRL too old: False
#        bad policy: False
#        green: False
#        key expired: False
#        key missing: False
#        key revoked: False
#        red: False
#        signature expired: False
#        system error: False
#        valid: False
#      status: success
#      timestamp: Thu Sep 20 15:29:28 2012
#      expiration timestamp: None
#      wrong key usage: False
#      pka trust: not available
#      chain model: False
#      validity: unknown
#      validity reason: success
#      public key algorithm: RSA
#      hash algorithm: SHA256
    """
    raise NotImplementedError()
    verified = False
    plain = data
    signatures = list(signature)
    return (plain, verified, signatures)

if __name__ == "__main__":
    import doctest
    doctest.testmod()
