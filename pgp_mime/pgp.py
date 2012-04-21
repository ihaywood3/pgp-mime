# Copyright

from email import message_from_bytes as _message_from_bytes
from email.encoders import encode_7or8bit as _encode_7or8bit
from email.mime.application import MIMEApplication as _MIMEApplication
from email.mime.multipart import MIMEMultipart as _MIMEMultipart

from . import LOG as _LOG
from .crypt import sign_and_encrypt_bytes as _sign_and_encrypt_bytes
from .crypt import verify_bytes as _verify_bytes
from .email import email_targets as _email_targets
from .email import strip_bcc as _strip_bcc


def sign(message, signers=None, allow_default_signer=False):
    r"""Sign a ``Message``, returning the signed version.

    multipart/signed
    +-> text/plain                 (body)
    +-> application/pgp-signature  (signature)

    >>> from pgp_mime.email import encodedMIMEText
    >>> message = encodedMIMEText('Hi\nBye')
    >>> signed = sign(message, signers=['pgp-mime@invalid.com'])
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
    >>> signed = sign(message, signers=['pgp-mime@invalid.com'])
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
    signature = str(_sign_and_encrypt_bytes(
            data=body, signers=signers,
            allow_default_signer=allow_default_signer), 'us-ascii')
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

def encrypt(message, recipients=None, always_trust=True):
    r"""Encrypt a ``Message``, returning the encrypted version.

    multipart/encrypted
    +-> application/pgp-encrypted  (control information)
    +-> application/octet-stream   (body)

    >>> from pgp_mime.email import encodedMIMEText
    >>> message = encodedMIMEText('Hi\nBye')
    >>> message['To'] = 'pgp-mime-test <pgp-mime@invalid.com>'
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
    >>> encrypted = encrypt(
    ...     message, recipients=['pgp-mime@invalid.com'], always_trust=True)
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
        recipients = [email for name,email in _email_targets(message)]
        _LOG.debug('extracted encryption recipients: {}'.format(recipients))
    encrypted = str(_sign_and_encrypt_bytes(
            data=body, recipients=recipients,
            always_trust=always_trust), 'us-ascii')
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

def sign_and_encrypt(message, signers=None, recipients=None,
                     always_trust=False, allow_default_signer=False):
    r"""Sign and encrypt a ``Message``, returning the encrypted version.

    multipart/encrypted
     +-> application/pgp-encrypted  (control information)
     +-> application/octet-stream   (body)

    >>> from pgp_mime.email import encodedMIMEText
    >>> message = encodedMIMEText('Hi\nBye')
    >>> message['To'] = 'pgp-mime-test <pgp-mime@invalid.com>'
    >>> encrypted = sign_and_encrypt(
    ...     message, signers=['pgp-mime@invalid.com'], always_trust=True)
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
    >>> encrypted = sign_and_encrypt(
    ...     message, signers=['pgp-mime@invalid.com'],
    ...     recipients=['pgp-mime@invalid.com'], always_trust=True)
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
    _strip_bcc(message=message)
    body = message.as_string().encode('us-ascii')
    if recipients is None:
        recipients = [email for name,email in _email_targets(message)]
        _LOG.debug('extracted encryption recipients: {}'.format(recipients))
    encrypted = str(_sign_and_encrypt_bytes(
            data=body, signers=signers, recipients=recipients,
            always_trust=always_trust,
            allow_default_signer=allow_default_signer), 'us-ascii')
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

def decrypt(message):
    r"""Decrypt a multipart/encrypted message.

    >>> from pgp_mime.email import encodedMIMEText
    >>> message = encodedMIMEText('Hi\nBye')
    >>> encrypted = encrypt(message, recipients=['<pgp-mime@invalid.com>'])
    >>> decrypted = decrypt(encrypted)
    >>> print(decrypted.as_string())  # doctest: +ELLIPSIS, +REPORT_UDIFF
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
    ...     message, recipients=['pgp-mime@invalid.com'], always_trust=True)
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
    decrypted,verified,result = _verify_bytes(encrypted)
    return _message_from_bytes(decrypted)

def verify(message):
    r"""Verify a signature on ``message``, possibly decrypting first.

    >>> from pgp_mime.email import encodedMIMEText
    >>> message = encodedMIMEText('Hi\nBye')
    >>> message['To'] = 'pgp-mime-test <pgp-mime@invalid.com>'
    >>> encrypted = sign_and_encrypt(message, signers=['pgp-mime@invalid.com'],
    ...     always_trust=True)
    >>> decrypted,verified,result = verify(encrypted)
    >>> print(decrypted.as_string())  # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    To: pgp-mime-test <pgp-mime@invalid.com>
    <BLANKLINE>
    Hi
    Bye
    >>> verified
    False
    >>> print(str(result, 'utf-8').replace('\x00', ''))
    ... # doctest: +REPORT_UDIFF, +ELLIPSIS
    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <gpgme>
      <verify-result>
        <signatures>
          <signature>
            <summary value="0x0" />
            <fpr>B2EDBE0E771A4B8708DD16A7511AEDA64332B6E3</fpr>
            <status value="0x0">Success &lt;Unspecified source&gt;</status>
            <timestamp unix="..." />
            <exp-timestamp unix="0i" />
            <wrong-key-usage value="0x0" />
            <pka-trust value="0x0" />
            <chain-model value="0x0" />
            <validity value="0x0" />
            <validity-reason value="0x0">Success &lt;Unspecified source&gt;</validity-reason>
            <pubkey-algo value="0x1">RSA</pubkey-algo>
            <hash-algo value="0x8">SHA256</hash-algo>
          </signature>
        </signatures>
      </verify-result>
    </gpgme>
    <BLANKLINE>

    >>> from email.mime.multipart import MIMEMultipart
    >>> message = MIMEMultipart()
    >>> message.attach(encodedMIMEText('Part A'))
    >>> message.attach(encodedMIMEText('Part B'))
    >>> signed = sign(message, signers=['pgp-mime@invalid.com'])
    >>> decrypted,verified,result = verify(signed)
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
    False
    >>> print(str(result, 'utf-8').replace('\x00', ''))
    ... # doctest: +REPORT_UDIFF, +ELLIPSIS
    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <gpgme>
      <verify-result>
        <signatures>
          <signature>
            <summary value="0x0" />
            <fpr>B2EDBE0E771A4B8708DD16A7511AEDA64332B6E3</fpr>
            <status value="0x0">Success &lt;Unspecified source&gt;</status>
            <timestamp unix="..." />
            <exp-timestamp unix="0i" />
            <wrong-key-usage value="0x0" />
            <pka-trust value="0x0" />
            <chain-model value="0x0" />
            <validity value="0x0" />
            <validity-reason value="0x0">Success &lt;Unspecified source&gt;</validity-reason>
            <pubkey-algo value="0x1">RSA</pubkey-algo>
            <hash-algo value="0x2">SHA1</hash-algo>
          </signature>
        </signatures>
      </verify-result>
    </gpgme>
    <BLANKLINE>
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
        body.as_string().encode('us-ascii'), signature=sig_data)
    return (body, verified, result)
