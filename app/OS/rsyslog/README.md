### Prerequisits:

1. You have configured your FW or Panorama to send logs to Expedition
2. Expedition is receiving the logs. You can test that by using below command:`tcpdump #protocol port #port`

    * Example:
        * tcpdump tcp port 514
        * tcpdump udp port 514

### Steps:

1. Get a sample syslog file from Expedition library /var/www/html/OS/rsyslog
2. For regular use case where each device sent the logs: Get one of below files based on the used syslog protocol UDP, TCP or both (UDP and TCP)

    * TCP - `rsyslog.default-tcp`
    * UDP - `rsyslog.default-udp`
    * TCP-UDP - `rsyslog.default-tcpudp`
3. For cases where we have a centralized syslog server forwarding logs from different firewalls, could be a Panorama or any other LogConnector system: Get one of below files based on the used syslog protocol UDP, TCP or both (UDP and TCP)

    * TCP - `rsyslog.split_by_serial-tcp`
    * UDP - `rsyslog.split_by_serial-udp`
    * TCP-UDP - `rsyslog.split_by_serial-tcpudp`
4. Rename file `/etc/rsyslog.conf` to `/etc/rsyslog.conf_#timestamp`.
5. Move your selected file to /etc/ and rename it to /etc/rsyslog.conf
6. Review your firewall configuration to make sure the used protocol/port is allowed

    * List firewall rules: `sudo firewall-cmd --list-all`
    * Add the required port/protocol: `sudo firewall-cmd --add-port=#port/#protocol`
    * Make changes permanent: `sudo firewall-cmd --runtime-to-permanent`

7. Restart syslog server `service rsyslog start`