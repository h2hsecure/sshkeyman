#!/bin/bash

cp libnss_sshkeyman.so.2 /usr/lib/x86_64-linux-gnu/libnss_sshkeyman.so.2
cp sshkeyman /usr/bin/sshkeyman
mkdir -p /var/lib/sshkeyman

cp sshkeyman.service /etc/systemd/system/sshkeyman.service
systemctl daemon-reload

systemctl start sshkeyman