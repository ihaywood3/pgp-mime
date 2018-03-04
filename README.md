Python module and tools for constructing and sending PGP/MIME email.

The ``pgp_mime`` module makes it easy to construct and dispatch signed
and/or encrypted email using PGP and :RFC:`3156`.  It uses GnuPG
(via gpgme) to perform the cryptography.

Dependencies
------------

``pgp-mime`` is a simple package with no external dependencies outside
the Python 3.3 standard library and the `gpg` module provided
by GPGME (see ``lang/python`` in the repository from
https://www.gnupg.org/related_software/gpgme/ )

This is also now available as ``python3-gpg`` in the latest Ubuntu (17.10).
 
Installing
----------

::

   $ pip3 install https://github.com/ihaywood3/pgp-mime/archive/master.zip



Testing
=======

Run the internal unit tests using [nose](http://readthedocs.org/docs/nose/en/latest/)::

   $ nosetests --with-doctest --doctest-tests pgp_mime

If a Python-3-version of ``nosetests`` is not the default on your
system, you may need to try something like::

   $ nosetests-3.3 --with-doctest --doctest-tests pgp_mime

Licence
=======

This project is distributed under the [GNU General Public License
Version 3](http://www.gnu.org/licenses/gpl.html) or greater.

History
=======

This module was orginally W. Trevor King's ``pgp_mime`` which used his 
[pyassuan](http://blog.tremily.us/posts/pyassuan/)
to talk to GnuPG, in conjunction with a ``gpgme-tool`` he patched to work as a UNIX socket server. 
However, his patches never made it to the main ``gpgme``, so his code is now quite hard to use.

ValiValpas replaced the ``crypt.py`` in order to handle cryptography with the GnuPG layer ``pygpgme`` instead.

This version is forked and adapted again to use the standard GPGME bindings for Python.

Authors
=======

W. Trevor King
wking@tremily.us

Johannes Schlatow
johannes.schlatow@googlemail.com

Ian Haywood
ian@haywood.id.au

