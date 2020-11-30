# recover-password
Python script to recover password you only remember partially
It builds passwords using suggestions in secret-word.txt

run with python ./recover-luks-crypto.py

NOT USABLE - HARD CODED DEFAULTS
~/.cryptofileLUKS 

## For ssh key passphrase recovery
copy key into dir, e.g. id_rsa.new
 * ensure it has correct permissions chmod 600 id_rsa.new
 * Test command
    ssh-keygen -p -f id_rsa.new
    "Enter old passphrase: "  xyz
    "Failed to load key id_rsa.new: incorrect passphrase supplied to decrypt private key"
    "Enter new passphrase"