# Copyright (C) 2014 Johannes Schlatow <johannes.schlatow@googlemail.com>
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

"Tools for dealing with Pretty Good Privacy (PGP) and email."

from setuptools import setup as _setup
import os.path as _os_path

from pgp_mime import __version__


_this_dir = _os_path.dirname(__file__)

_setup(
    name='pgp-mime',
    version=__version__,
    maintainer='Ian Haywood',
    maintainer_email='ian@haywood.id.au',
    url='https://github.com/ihaywood3/pgp-mime',
    download_url='https://github.com/ihaywood3/pgp-mime/archive/master.tar.gz',
    license = 'GNU General Public License (GPL)',
    platforms = ['all'],
    description = __doc__,
    long_description=open(_os_path.join(_this_dir, 'README.md'), 'r').read(),
    classifiers = [
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Communications :: Email',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development'
        ],
    scripts = ['bin/send-pgp-mime.py'],
    packages = ['pgp_mime'],
    provides = ['pgp_mime'],
    )
