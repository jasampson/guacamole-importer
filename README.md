# guacamole-importer

Retrieves server information from multiple data sources, cleans up the data and imports sessions into Apache Guacamole using the Guacamole REST API.

This script should live somewhere that can reach the guacamole server REST API and ideally should run once a day from cron.

You are free to use these scripts but please do not ask me for support.  I am not responsible for any damage done to your server as a result of these scripts.  That being said, they have been tested in a production environment and have worked well for me for over a year now.

# Setting things up to run the script
- You'll need a recent version of Python 3.  This has been used in production on Python 3.7, 3.8 and 3.9 for Linux.
- You'll need to take a look at settings and add missing passwords for each service account.  The bind_account really only needs read access to Active Directory.
- You'll need to install the (guacapy)[https://github.com/pschmitt/guacapy] python library and make some changes since this python library doesn't support everything I needed and I was too lazy to submit a pull request.  I've included a .patch file to fix this.
- You'll need the guacadmin credentials and the guacadmin TOTP secret, which can be found in the Guacamole postgresql database.  If you are even thinking of trying to use script this I will assume you know how to get this on your own.
- Connectivity to all domain controllers in each domain, to RDP gateways, and to SSH gateways.

## Setting up guacapy
Guacamole's python module was lacking a feature I needed so I added it and fixed some other small problems.  To use this script you will need to apply a patch to guacapy before installing it.  The directions below assume you are in this project's directory when starting.
```
git clone https://github.com/pschmitt/guacapy.git
cp guacapy.patch guacapy
cd guacapy
patch -p0 < guacapy.patch
python setup.py install
```

# How it works
Here's the guac_import.py script does on a high level:
- Connects to the Guacamole REST API.
- Retrieves server information from Active Directory using LDAPS.
- Compares the server list downloaded from the Guacamole REST API to the list from Active Directory.
- Determines server operating system using Active Directory attributes.
- Applies a list of transforms before creating sessions.  Basically we can add, delete or rename any server using this feature before it gets imported into the Guacamole database.
- Determines if an RDP or SSH gateway is necessary based on hostname patterns.
- Performs imports or deletes of server profiles from Guacamole.
- Moves on to the next Active Directory domain until all sessions in Guacamole have been updated.

# Bonus scripts
`guac_mass_update_parameter.py` - this script can mass update a single connection profile parameter across multiple session profiles in the postgresql database.
`guac_nuke.py` - this script deletes all connection profiles from the postgresql database.  By delete I mean it flags the connection as deleted, which actually leaves the data in the database.

# Known issues
- This script will not change the session IP address if changes are made to DNS after a server gets imported.  The session IP address is used for display purposes only so leaving it broken will not impact use of the session.
