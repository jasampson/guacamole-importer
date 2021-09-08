# guacamole-importer

Retrieves server information from multiple data sources, cleans up the data and imports it into Guacamole using the Guacamole REST API.

This script is able to add/remove/update session profiles for domain joined servers.  It should normally run from cron once a day.

This script is designed to work with a single AD domain, or with multiple domains.

# Setting things up to run the script
- You'll need a recent version of Python 3.  This was testing on Python 3.7 for Linux but it probably works on more recent versions too.
- You'll need to take a look at ./conf/guac_import.json and update accordingly.  This file normally lives in /opt/guacamole/scripts/guac_import.json, but this can be changed by editing the path in the guac_import.py.
- You'll need AD credentials to set the ldap bind_account.  Make sure you set the value of guac_parent_identifer to the corresponding value of the folder you would like those sessions to be created in.
- You'll need to install the guacapy python library and make some changes since this python library doesn't support everything.  I've included a .patch file to fix this.
- You'll need the guacadmin credentials and if you are using TOTP, the guacadmin TOTP secret, which can be found in the Guacamole postgresql database.
- Connectivity to all domain controllers in each domain, to RDP gateways, and to SSH gateways.

## Setting up guacapy
Guacapy was lacking a feature I needed so I added it and fixed some other small problems.  To use this script you will need to apply a patch to guacapy before installing it.  The directions below assume you are in this project's directory when starting.
```
git clone https://github.com/pschmitt/guacapy.git
cp guacapy.patch guacapy
cd guacapy
patch -p0 < guacapy.patch
pip install . --user
```

After patching and installing guacapy, you will need a few other modules, which you can use requirements.txt to install.
```
pip install -r requirements.txt
```

# How it works
Here's the guac_import.py script does on a high level:
- The script loads settings from `/opt/guacamole/scripts/guac_import.json`
- Connects to the Guacamole REST API.
- Retrieves server information from Active Directory using LDAPS.
- Compares the server list downloaded from the Guacamole to the list from Active Directory and prepares to update Guacamole's server data.
- Determines which servers need to be imported/deleted.
- Determines server operating system using Active Directory attributes.
- Applies a list of transforms.  Basically we can add, delete or rename any server using this feature before it gets imported.
- Determines if an RDP or SSH gateway is necessary based on hostname patterns.
- Performs imports or deletes of server profiles from Guacamole.
- Moves on to the next domain until all domains have been updated.

# Bonus scripts
`guac_mass_update_parameter.py` - this script can mass update a single connection profile parameter in the postgresql database.
`guac_nuke.py` - this script deletes all connection profiles from the postgresql database.

# TODO:
Ideas left to implement:
- Finish fully documenting what each setting does.
