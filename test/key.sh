#!/bin/bash
#
# Copyright

# generate an OpenPGP key for testing pgp-mime
gpg --batch --gen-key key.conf
gpg --no-default-keyring --secret-keyring ./key.sec --keyring ./key.pub --export-secret-keys --armor --output key.txt
rm -f key.sec key.pub
