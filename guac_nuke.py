#!/usr/bin/env python3

import guacapy


def main():
    """
    delete all connection profiles from guacamole postgresql database
    """

    settings = {
        "auth": {
            # guacamole server credentials
            "server": "guacamole.server.com",
            "username": "guacadmin",
            "password": "",
            "totp": "",
        },
    }

    print(
        "Deleting guacamole sessions from postgresql db using the REST API.  Please wait."
    )

    # connect to guacamole REST API
    g = guacapy.Guacamole(
        hostname=settings['auth']['server'],
        username=settings['auth']['username'],
        password=settings['auth']['password'],
    )
    g_conns = g.get_all_connections("postgresql")
    # delete all connections from postgresql database
    [g.delete_connection(j, "postgresql") for j in [i for i in g_conns]]
    print("All guacamole sessions were successfully deleted.  Exiting.")


if __name__ == "__main__":
    main()
