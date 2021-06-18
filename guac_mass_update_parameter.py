#!/usr/bin/env python3

import guacapy


def main():
    """
    updates a single parameter value in all guacamole sessions
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

    # connect to guacamole API
    g = guacapy.Guacamole(
        hostname=settings['auth']['server'],
        username=settings['auth']['username'],
        password=settings['auth']['password'],
    )
    g_conns = g.get_all_connections("postgresql")

    # here i'm filtering the connection profiles based on protocol type.  this could be removed if you want to update everything
    conn_ids = [g_conns[i]['identifier'] for i in g_conns if g_conns[i]["protocol"] == "rdp"]

    # loop through every connection profile and update the attribute
    for conn_id in conn_ids:
        print(f"Updating {conn_id}")
        old_params = g.get_connection_full(int(conn_id), "postgresql")
        # this is the parameter and value that you want to edit on every connection
        old_params["attributes"]["max-connections-per-user"] = "2"
        g.edit_connection(int(conn_id), old_params)


if __name__ == "__main__":
    main()
