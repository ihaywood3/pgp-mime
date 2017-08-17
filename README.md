Python module and tools for constructing and sending PGP/MIME email.

The ``pgp_mime`` module makes it easy to construct and dispatch signed
and/or encrypted email using PGP_ and :RFC:`3156`.  It uses GnuPG_
(via `gpgme`_) to perform the cryptography.

Dependencies
------------

``pgp-mime`` is a simple package with no external dependencies outside
the Python 3.3 standard library and the `gpg` module provided
by GPGME (see lang/python in the repository from
https://www.gnupg.org/related_software/gpgme/ )

 
Installing by hand
------------------

``pgp-mime`` is available as a Git_ repository::

  $ git clone https://github.com/ihaywood3/pgp-mime

See the homepage_ for details.  To install the checkout, run the
standard::

  $ python setup.py install


Testing
=======

Run the internal unit tests using nose_::

  $ nosetests --with-doctest --doctest-tests pgp_mime

If a Python-3-version of ``nosetests`` is not the default on your
system, you may need to try something like::

  $ nosetests-3.3 --with-doctest --doctest-tests pgp_mime

Licence
=======

This project is distributed under the `GNU General Public License
Version 3`_ or greater.

History
=======

This module was orginally W. Trevor King's ``pgp_mime`` which used his ``_pyassuan``
to talk to GnuPG, in conjunction with a ``gpgme-tool`` he patched to work as a UNIX socket server. 
However, his patches never made it ot the stock  ``gpgme``, so his code is hard to use currently.
ValiValpas replaced the ``crypt.py`` in order to handle cryptography with the GnuPG layer ``pygpgme`` instead.

This version is forked and adapted again to use the stock GPGME bindings for Python.

Authors
=======

W. Trevor King
wking@tremily.us

Johannes Schlatow
johannes.schlatow@googlemail.com

Ian Haywood
ian@haywood.id.au

.. _PGP: http://en.wikipedia.org/wiki/Pretty_Good_Privacy
.. _pyassuan: http://blog.tremily.us/posts/pyassuan/
.. _Git: http://git-scm.com/
.. _GnuPG: http://www.gnupg.org/
.. _nose: http://readthedocs.org/docs/nose/en/latest/
.. _GNU General Public License Version 3: http://www.gnu.org/licenses/gpl.html
