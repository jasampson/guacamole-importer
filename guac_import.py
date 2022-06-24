#!/usr/bin/env python3

from dns import resolver
from ipaddress import ip_address
from ldap3 import Server, Connection, Tls, SUBTREE
from time import sleep
import json
import ssl
import guacapy
import requests


def main():
    """
    do all of the things
    """

    # load settings from config
    settings = guac_load_config("/opt/guacamole/scripts/guac_import.json")

    # connect to the guacamole REST API
    g = guac_connect(settings)

    # iterate through each domain and import them one at a time into guacamole
    for domain_settings in settings["domains"]:
        print(f"[{domain_settings['short_domain']}] Starting import.")
        print(
            f"[{domain_settings['short_domain']}] Querying Active Directory for server accounts."
        )
        ldap_out = ldap_get_servers(domain_settings)

        # servers contains only the hostname in lowercase, and the value of the operatingSystem LDAP attribute
        ad_servers = [
            {
                "hostname": i["attributes"]["dNSHostName"].lower(),
                "operatingsystem": i["attributes"]["operatingSystem"],
            }
            for i in ldap_out
        ]

        print(
            f"[{domain_settings['short_domain']}] Applying transforms to servers list"
        )
        ad_servers = apply_transforms(domain_settings, ad_servers)

        # import sessions from Active Directory
        guac_sync_sessions(g, domain_settings, ad_servers)

        # add recursive group permissions to folders if needed
        if domain_settings["recursive_read_access"]:
            print(
                f"[{domain_settings['short_domain']}] Setting recursive permissions to connection groups."
            )
            guac_user_group_recursive_add(g, domain_settings)

        print(f"[{domain_settings['short_domain']}] Completed import.")

    print("Exiting normally.")


def guac_load_config(config_file: str) -> dict:
    """
    loads a json config file and returns it in python dict format
    """
    try:
        with open(config_file) as json_file:
            settings = json.load(json_file)
    except FileNotFoundError:
        raise RuntimeError("guac_import.json: file not found in current directory.")
    except PermissionError:
        raise RuntimeError("guac_import.json: cannot read file due to permissions.")
    except json.JSONDecodeError:
        raise RuntimeError("guac_import.json: malformed JSON detected.")
    return settings


def guac_connect(settings: dict) -> guacapy.client.Guacamole:
    while True:
        try:
            g = guacapy.Guacamole(
                hostname=settings["auth"]["server"],
                username=settings["auth"]["username"],
                password=settings["auth"]["password"],
                secret=settings["auth"]["totp"],
            )
            break
        except requests.exceptions.HTTPError:
            print(
                "[Warning] HTTP 400 Client Error received.  Retrying REST API connection in 10 seconds."
            )
            sleep(10)
    return g


def guac_sync_sessions(
    g: guacapy.client.Guacamole, domain_settings: dict, ad_servers: list
) -> None:
    """
    adds/updates/deletes servers in guacamole using Active Directory and DNS
    """
    # for guacamole api stuff this unofficial documentation is very useful
    # https://github.com/ridvanaltun/guacamole-rest-api-documentation

    # connect to guac api and retrieve a list of servers from postgresql
    print(
        f"[{domain_settings['short_domain']}] Querying Guacamole PostgreSQL database for existing guacamole sessions."
    )
    g_conns = g.get_all_connections("postgresql")

    # if for some reason you need to nuke everything from guacamole, this could be used:
    # [g.delete_connection(j, 'postgresql') for j in [i for i in g_conns]]

    # query guacamole db for session names and derive server short names from this
    g_session_names = [
        g_conns[i]["name"]
        for i in g_conns
        if g_conns[i]["parentIdentifier"] == domain_settings["guac_parent_identifier"]
    ]
    g_servers_short = [i.split()[0] for i in g_session_names]
    # shorten server names from AD
    ad_servers_short = [i["hostname"].split(".")[0] for i in ad_servers]
    # query DNS for what session names should look like and store it for later use
    print(f"[{domain_settings['short_domain']}] Querying DNS for server DNS entries.")
    dns_session_names = {}
    for hostname in g_servers_short:
        dns_session_names[hostname] = guac_session_get_name(
            f"{hostname}.{domain_settings['dns_domain']}"
        )

    # create lists of servers to add, delete or update
    print(
        f"[{domain_settings['short_domain']}] Computing guacamole sessions to add/remove/update."
    )
    ad_servers_to_add = [
        server for server in ad_servers_short if server not in g_servers_short
    ]
    ad_servers_to_del = [
        server for server in g_servers_short if server not in ad_servers_short
    ]
    servers_to_update = [
        server
        for server in g_servers_short
        if dns_session_names[server]
        and dns_session_names[server] not in g_session_names
    ]

    # update servers
    servers_to_update_ids = [
        g_conns[i]["identifier"]
        for i in g_conns
        if g_conns[i]["name"].split()[0] in servers_to_update
    ]
    for conn_id in servers_to_update_ids:
        conn_profile = g.get_connection_full(conn_id)
        # some sessions use commands to relay ssh through bastion hosts.  in this case, we have to derive the remote hostanme from the command field and not the hostname field
        if (
            conn_profile["protocol"] == "ssh"
            and "ssh" in conn_profile["parameters"]["command"]
        ):
            new_name = dns_session_names[
                conn_profile["parameters"]["command"].split()[2].split(".")[0]
            ]
        else:
            new_name = dns_session_names[
                conn_profile["parameters"]["hostname"].split(".")[0]
            ]
        if len(new_name) == 128:
            print(
                f"[{domain_settings['short_domain']}] Warning: Server: {conn_profile['parameters']['hostname']} session name has been truncated due to length >= 128.  This can happen when a server has many IPs in DNS."
            )
        print(
            f"[{domain_settings['short_domain']}] Updating Server: {conn_profile['parameters']['hostname']} From: {conn_profile['name']} To: {new_name}"
        )
        conn_profile["name"] = new_name
        g.edit_connection(conn_id, conn_profile, "postgresql")

    # delete servers
    ad_servers_to_del_ids = [
        g_conns[i]["identifier"]
        for i in g_conns
        if g_conns[i]["name"].split()[0] in ad_servers_to_del
    ]
    [
        print(f"[{domain_settings['short_domain']}] Deleting Server: {server}")
        for server in ad_servers_to_del
    ]
    [
        g.delete_connection(connection_id, "postgresql")
        for connection_id in ad_servers_to_del_ids
    ]

    # add servers
    windows_servers = [
        s["hostname"]
        for s in ad_servers
        if s["hostname"].split(".")[0] in ad_servers_to_add
        and "Windows" in s["operatingsystem"]
    ]
    linux_servers = [
        s["hostname"]
        for s in ad_servers
        if s["hostname"].split(".")[0] in ad_servers_to_add
        and "Ubuntu" in s["operatingsystem"]
    ]

    for hostname in windows_servers:
        # Servers > 2012 R2 need to have glyph caching disabled or connections will break
        if (
            "2008"
            in [i["operatingsystem"] for i in ad_servers if hostname in i["hostname"]][
                0
            ]
        ):
            guac_connection_profile = guac_session_rdp(
                hostname, domain_settings, disable_glyph_caching=True
            )
        else:
            guac_connection_profile = guac_session_rdp(hostname, domain_settings)

        # only add session profile if the server has a DNS entry
        if guac_connection_profile:
            print(
                f"[{domain_settings['short_domain']}] Importing Windows Server: {hostname}"
            )
            g.add_connection(guac_connection_profile, "postgresql")
        else:
            print(
                f"[Warning] Skipped adding {hostname} because it does not have a DNS entry."
            )

    for hostname in linux_servers:
        guac_connection_profile = guac_session_ssh(hostname, domain_settings)

        # only add session profile if the server has a DNS entry
        if guac_connection_profile:
            print(
                f"[{domain_settings['short_domain']}] Importing Linux Server: {hostname}"
            )
            g.add_connection(guac_connection_profile, "postgresql")
        else:
            print(
                f"[Warning] Skipped adding {hostname} because it does not have a DNS entry."
            )


def guac_session_rdp(
    hostname: str, domain_settings: dict, disable_glyph_caching=False
) -> dict:
    """
    returns a guacamole session dictionary for an RDP connection
    """
    session_name = guac_session_get_name(hostname)

    if session_name:
        # baseline RDP session config is here
        rdp_session = {
            "name": session_name,
            "parentIdentifier": domain_settings["guac_parent_identifier"],
            "protocol": "rdp",
            "attributes": {"max-connections": "", "max-connections-per-user": "2"},
            "activeConnections": 0,
            "parameters": {
                "port": "3389",
                "hostname": hostname,
                "ignore-cert": "true",
                "enable-drive": "true",
                "security": "nla",
                "username": "${GUAC_USERNAME}",
                "password": "${GUAC_PASSWORD}",
                "domain": domain_settings["short_domain"],
                "drive-path": "/var/tmp/guac_drive/${GUAC_USERNAME}",
                "create-drive-path": "true",
                "enable-font-smoothing": "true",
                "enable-full-window-drag": "true",
                "enable-wallpaper": "true",
                "enable-theming": "true",
                "color-depth": "32",
            },
        }

        # if an RDP gateway was specified and the pattern matches our hostname add additional gateway parameters
        rdp_gateway = [
            i
            for i in domain_settings["rdp_gateway"]
            if i["pattern"] in hostname and i["gateway"]
        ]
        if rdp_gateway:
            rdp_session["parameters"]["gateway-hostname"] = rdp_gateway[0]["gateway"]
            rdp_session["parameters"]["gateway-username"] = "${GUAC_USERNAME}"
            rdp_session["parameters"]["gateway-password"] = "${GUAC_PASSWORD}"
            rdp_session["parameters"]["gateway-domain"] = domain_settings[
                "short_domain"
            ]
            rdp_session["parameters"]["gateway-port"] = "443"

        # For Server 2008 and lower, we need to disable glyph caching because it causes the RDP connection to drop constantly
        if disable_glyph_caching:
            rdp_session["parameters"]["disable-glyph-caching"] = "true"

        return rdp_session
    else:
        return False


def guac_session_ssh(hostname: str, domain_settings: dict) -> dict:
    """
    returns a guacamole session dictionary for an SSH connection
    """
    session_name = guac_session_get_name(hostname)

    if session_name:
        # baseline SSH session config is here
        ssh_session = {
            "name": session_name,
            "identifier": "",
            "parentIdentifier": domain_settings["guac_parent_identifier"],
            "protocol": "ssh",
            "activeConnections": 0,
            "attributes": {"max-connections": "", "max-connections-per-user": ""},
            "parameters": {
                "hostname": hostname,
                "port": "22",
                "username": "${GUAC_USERNAME}",
                "password": "${GUAC_PASSWORD}",
                "color-scheme": "background: rgb:00/00/00;\n"
                "foreground: rgb:FF/FF/FF;\n"
                "color0: rgb:2E/34/36;\n"
                "color1: rgb:CC/00/00;\n"
                "color2: rgb:4E/9A/06;\n"
                "color3: rgb:C4/A0/00;\n"
                "color4: rgb:34/65/A4;\n"
                "color5: rgb:75/50/7B;\n"
                "color6: rgb:06/98/9A;\n"
                "color7: rgb:D3/D7/CF;\n"
                "color8: rgb:55/57/53;\n"
                "color9: rgb:EF/29/29;\n"
                "color10: rgb:8A/E2/34;\n"
                "color11: rgb:FC/E9/4F;\n"
                "color12: rgb:72/9F/CF;\n"
                "color13: rgb:AD/7F/A8;\n"
                "color14: rgb:34/E2/E2;\n"
                "color15: rgb:EE/EE/EC;",
            },
        }

        # if an SSH gateway was specified add additional gateway parameters
        ssh_gateway = [
            i
            for i in domain_settings["ssh_gateway"]
            if i["pattern"] in hostname and i["gateway"]
        ]
        if ssh_gateway:
            ssh_session["parameters"]["hostname"] = ssh_gateway[0]["gateway"]
            ssh_session["parameters"]["command"] = f"ssh -q {hostname}"
        return ssh_session
    else:
        return False


def guac_session_get_name(hostname: str) -> str:
    """
    turns an ip/hostname string into a formatted session name
    """
    # check if hostname is actually an IP address so that we don't .split() it
    if not is_ip(hostname):
        short_hostname = hostname.split(".")[0]
        # look up IP using DNS
        ip = dns_lookup(hostname)
        if ip:
            # behave slightly differently if dns_lookup returns multiple results
            if len(ip) > 1:
                name = f"{short_hostname} ({' '.join(ip)})"
            elif len(ip) == 1:
                name = f"{short_hostname} ({ip[0]})"
            else:
                name = short_hostname
        else:
            # return False so we can skip this server
            return False
    else:
        name = hostname
    return name[0:128]


def apply_transforms(domain_settings: dict, servers: list) -> list:
    """
    applies transforms from settings to LDAP search results
    """
    if domain_settings["transforms"]["delete"]:
        for hostname in domain_settings["transforms"]["delete"]:
            try:
                l_index = [i["hostname"] for i in servers].index(hostname.lower())
                del servers[l_index]
            except ValueError:
                print(f"Warning: could not find transforms:delete:{hostname} in LDAP")
    if domain_settings["transforms"]["add"]:
        for hostname in domain_settings["transforms"]["add"]:
            servers.append(hostname)
    return servers


def ldap_get_servers(domain: dict) -> list:
    """
    performs ldap search operations and lightly cleans results
    """
    # look up domain controller _SRV.ldap record in DNS, and clean up the dns.resolver.Answer so that we get the fdqn
    dns_answer = resolver.resolve("_ldap._tcp." + domain["dns_domain"], "SRV")
    dc = dns_answer[0].to_text().split()[-1][:-1]

    # set up ssl/tls ldap connection to domain controller
    tls = Tls(validate=ssl.CERT_NONE)
    ldap_server = Server(dc, use_ssl=True, tls=tls)
    ldap_conn = Connection(
        ldap_server, domain["bind_dn"], domain["bind_pw"], auto_bind=True
    )

    # bind to the ldap server using creds above
    if not ldap_conn.bind():
        raise RuntimeError("Error binding to LDAP server.", ldap_conn.result)

    # grab all Windows Servers from the base_dn path above
    ldap_results = ldap_conn.extend.standard.paged_search(
        search_base=domain["base_dn"],
        search_filter=domain["server_search_filter"],
        search_scope=SUBTREE,
        attributes=["dNSHostName", "operatingSystem"],
        paged_size=5,
        generator=False,
    )

    # ldap3 sometimes returns referral records from LDAP, so we use this list comprehension to remove those
    out = [i for i in ldap_results if i["type"] == "searchResEntry"]
    return out


def is_ip(host: str) -> bool:
    """
    returns True if host is a valid ipv4 address
    """
    try:
        ip_address(host)
    except ValueError:
        return False
    return True


def dns_lookup(hostname: str) -> list:
    """
    returns a result, or False if no result
    """
    try:
        dns_answer = resolver.resolve(hostname, "A")
        dns_answer = [
            answer.split()[-1]
            for answer in dns_answer.response.answer[0].to_text().split("\n")
        ]
        # sort ips if more than 1 result is received
        if len(dns_answer) > 1:
            dns_answer = [str(ip) for ip in sorted([ip_address(i) for i in dns_answer])]
    except resolver.NXDOMAIN:
        return False
    return dns_answer


def guac_user_group_recursive_add(
    g: guacapy.client.Guacamole, domain_settings: dict
) -> None:
    """
    adds user groups to folders in guacamole recursively
    """

    # query some things from guacamole API and clean up results
    guac_conns = g.get_all_connections()
    guac_user_groups = g.get_user_groups()
    guac_user_groups_list = [*guac_user_groups]

    # do very some basic error checking.  the group we're giving permissions to must be in the guac DB or this won't work
    if [
        group
        for group in domain_settings["recursive_read_access"]
        if group not in guac_user_groups_list
    ]:
        raise RuntimeError(
            f"There are AD groups present in settings['{domain_settings['short_domain']}']['recursive_read_access'] "
            "that do not exist in guacamole db"
        )

    for ad_group in domain_settings["recursive_read_access"]:
        # this first section deals with adding the group to individual connection profiles.  there is another section below that adds
        # the group to connection groups since that requires a slightly different API payload.

        # gather info
        guac_group_permissions = g.get_group_permissions(ad_group)

        # first filter guac_conns to only show things that are under our connection folder parentIdentifier
        guac_conns_ids_in_folder = [
            guac_conns[i]["identifier"]
            for i in guac_conns
            if guac_conns[i]["parentIdentifier"]
            == domain_settings["guac_parent_identifier"]
        ]
        # next, gather permissions entries for ad_group
        guac_conns_permissions = guac_group_permissions["connectionPermissions"]
        # third, take the above 2 items and make a list where they intersect.  this tells us which connection profiles in the connection folder the ad_group has read access to
        guac_conns_ids_read_access = [
            i
            for i in guac_conns_permissions
            if guac_conns_permissions[i] == ["READ"] and i in guac_conns_ids_in_folder
        ]
        # last, create a list containing only ids which do not already have read access
        guac_conns_ids_to_add = [
            i for i in guac_conns_ids_in_folder if i not in guac_conns_ids_read_access
        ]

        # add read access to any missing profiles
        [
            guac_grant_read_permissions_to_connection_profile(
                g, connection_id, ad_group
            )
            for connection_id in guac_conns_ids_to_add
        ]

        # add permissions for the connection group if they haven't been granted
        try:
            guac_group_permissions[domain_settings["guac_parent_identifier"]]
        except KeyError:
            guac_grant_read_permission_to_connection_group(
                g, domain_settings["guac_parent_identifier"], ad_group
            )


def guac_grant_read_permissions_to_connection_profile(
    g: guacapy.client.Guacamole, connection_id: str, ad_group: str
) -> None:
    """
    grants read access to ad_group on connection_id object
    """
    # create payload
    payload = [
        {
            "op": "add",
            "path": f"/connectionPermissions/{connection_id}",
            "value": "READ",
        }
    ]
    g.grant_group_permission(ad_group, payload)


def guac_grant_read_permission_to_connection_group(
    g: guacapy.client.Guacamole, parent_id: str, ad_group: str
) -> None:
    """
    grants read access to ad_group on connection_id object
    """
    # create payload
    payload = [
        {
            "op": "add",
            "path": f"/connectionGroupPermissions/{parent_id}",
            "value": "READ",
        }
    ]
    g.grant_group_permission(ad_group, payload)


if __name__ == "__main__":
    main()
