#!/bin/bash

systemctl stop sshkeyman || true
cp libnss_sshkeyman.so.2 /usr/lib/x86_64-linux-gnu/libnss_sshkeyman.so.2
cp sshkeyman /usr/bin/sshkeyman
mkdir -p /var/lib/sshkeyman
cp --update=none nss_sshkeyman.conf /etc
cp --update=none sshkeyman.service /etc/systemd/system/sshkeyman.service

systemctl daemon-reload
systemctl start sshkeyman