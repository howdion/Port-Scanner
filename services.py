"""Bảng ánh xạ cổng TCP phổ biến sang tên dịch vụ."""

from __future__ import annotations


# Tên dịch vụ tham khảo theo IANA và cách gọi thông dụng của các công cụ quét cổng.
# Một số cổng không có tên đăng ký chính thức với IANA nhưng rất hay gặp trong
# mạng thực tế (ví dụ phần mềm quản trị thiết bị mạng, ứng dụng máy chủ phổ biến)
# vẫn được thêm vào kèm chú thích, theo đúng tinh thần ban đầu của bảng này.
SERVICES: dict[int, str] = {
    # --- Giao thức cổ điển (thường gặp trong giáo trình mạng) ---
    7: "echo",
    9: "discard",
    13: "daytime",
    19: "chargen",
    37: "time",
    # --- Hệ thống, thư mục, xác thực ---
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    43: "whois",
    49: "tacacs",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    70: "gopher",
    79: "finger",
    80: "http",
    88: "kerberos",
    102: "iso-tsap",
    110: "pop3",
    111: "rpcbind",
    113: "ident",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    177: "xdmcp",
    179: "bgp",
    194: "irc",
    389: "ldap",
    427: "svrloc",
    443: "https",
    445: "microsoft-ds",
    464: "kpasswd",
    465: "smtps",
    500: "isakmp",  # IPsec/IKE
    512: "exec",
    513: "login",
    514: "syslog",
    515: "printer",
    520: "rip",
    523: "ibm-db2",
    524: "ncp",
    540: "uucp",
    543: "klogin",
    544: "kshell",
    548: "afp",
    554: "rtsp",
    563: "nntps",
    587: "submission",
    593: "http-rpc-epmap",
    623: "ipmi",
    631: "ipp",
    636: "ldaps",
    646: "ldp",
    691: "msexch-routing",
    860: "iscsi",
    873: "rsync",
    902: "vmware-auth",  # VMware Authentication Daemon
    903: "vmware-auth",
    989: "ftps-data",
    990: "ftps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1194: "openvpn",
    1352: "lotusnotes",
    1433: "mssql",
    1434: "ms-sql-m",  # SQL Server Browser
    1512: "wins",
    1521: "oracle",
    1701: "l2tp",
    1723: "pptp",
    1755: "mms",
    1812: "radius",
    1813: "radius-acct",
    1883: "mqtt",
    1900: "ssdp",  # UPnP/SSDP discovery
    2000: "cisco-sccp",
    2049: "nfs",
    2082: "cpanel",
    2083: "cpanel-ssl",
    2086: "whm",
    2087: "whm-ssl",
    2095: "webmail",
    2096: "webmail-ssl",
    2121: "ccproxy-ftp",
    2179: "vmrdp",  # Hyper-V VMConnect
    2181: "zookeeper",
    2222: "ssh-alt",
    2375: "docker",
    2376: "docker-tls",
    2379: "etcd-client",
    2380: "etcd-server",
    2382: "ms-olap",  # SQL Server Analysis Services
    2484: "oracle-tcps",
    3000: "http-alt",
    3128: "squid-http",
    3260: "iscsi-target",
    3268: "ldap-gc",
    3269: "ldap-gc-ssl",
    3283: "netassistant",  # Apple Remote Desktop
    3306: "mysql",
    3389: "ms-wbt-server",
    3690: "svn",
    4369: "epmd",  # Erlang Port Mapper
    4500: "ipsec-nat-t",
    4786: "cisco-smart-install",
    4840: "opcua-tcp",
    4848: "appserv-http",
    5000: "http-alt",
    5001: "commplex-link",  # thường thấy trên NAS Synology
    5060: "sip",
    5061: "sips",
    5222: "xmpp-client",
    5223: "xmpp-client-ssl",
    5269: "xmpp-server",
    5351: "nat-pmp",
    5353: "mdns",
    5355: "llmnr",
    5357: "wsdapi",  # WSDAPI - Web Services for Devices (IANA)
    5432: "postgresql",
    5601: "kibana",
    5631: "pcanywheredata",
    5632: "pcanywherestat",
    5672: "amqp",
    5684: "coaps",
    5900: "vnc",
    5938: "teamviewer",  # không phải cổng đăng ký IANA nhưng rất phổ biến
    6000: "x11",
    6379: "redis",
    6443: "kubernetes-api",
    6667: "irc",  # cổng IRC thay thế hay gặp
    6881: "bittorrent",
    7001: "weblogic",
    7474: "neo4j",
    7547: "cwmp",  # TR-069, giao thức quản trị router từ xa
    7680: "dosvc",  # Windows Delivery Optimization
    8000: "http-alt",
    8006: "proxmox",
    8008: "http-alt",
    8080: "http-proxy",
    8081: "http-alt",
    8086: "influxdb",
    8089: "splunkd",
    8091: "couchbase",
    8096: "jellyfin",
    8140: "puppet",
    8291: "winbox",  # MikroTik RouterOS, không phải cổng đăng ký IANA
    8333: "bitcoin",
    8443: "https-alt",
    8500: "consul",
    8529: "arangodb",
    8545: "ethereum-rpc",
    8554: "rtsp-alt",
    8883: "secure-mqtt",
    8888: "http-alt",
    9042: "cassandra",
    9090: "zeus-admin",
    9092: "kafka",
    9100: "hp-pdl-datastream",  # cổng in mạng phổ biến (JetDirect)
    9200: "elasticsearch",
    9300: "elasticsearch",
    9418: "git",
    9993: "zerotier",
    10000: "webmin",
    10050: "zabbix-agent",
    10051: "zabbix-trapper",
    10250: "kubelet",
    11211: "memcached",
    15672: "rabbitmq-management",
    16992: "amt-soap-http",  # Intel AMT
    16993: "amt-soap-https",
    17500: "dropbox-lansync",
    27017: "mongodb",
    27018: "mongodb-shard",
    27019: "mongodb-config",
    32400: "plex",
    47808: "bacnet",  # giao thức tự động hóa tòa nhà
}

# Windows và nhiều hệ điều hành cấp cổng RPC/kết nối tạm thời trong dải này.
# Nhiều cổng loại này xuất hiện trong kết quả quét (ví dụ 49664-49670, các cổng
# ngẫu nhiên phía trên 50000) mà không có tên dịch vụ cố định, vì chúng được hệ
# điều hành cấp phát linh động cho từng tiến trình. Gắn nhãn "dynamic" thay vì
# "unknown" để người đọc hiểu đây là cổng động, không phải một dịch vụ lạ.
_DYNAMIC_PORT_RANGE = range(49152, 65536)


def get_service_name(port: int) -> str:
    """Trả về tên dịch vụ ứng với cổng.

    - Nếu cổng có trong bảng ``SERVICES``, trả về tên tương ứng.
    - Nếu cổng nằm trong dải cổng động (49152-65535) và chưa có tên cụ thể,
      trả về ``dynamic`` để phân biệt với cổng thật sự chưa biết.
    - Ngược lại trả về ``unknown``.
    """
    if port in SERVICES:
        return SERVICES[port]
    if port in _DYNAMIC_PORT_RANGE:
        return "dynamic"
    return "unknown"