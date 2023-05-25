#!/bin/sh

rm -rf /opt/bkedr
rm -rf /etc/systemd/system/bkedr.service

mkdir /opt/bkedr

cp -r ./configs /opt/bkedr
cp bkedr /opt/bkedr
chmod +x /opt/bkedr/bkedr

touch /opt/bkedr/configs/agents.conf

mkdir /opt/bkedr/downloadfile

mkdir /opt/bkedr/log
touch /opt/bkedr/log/applog.txt
touch /opt/bkedr/log/responselog.txt

cp -r ./rules /opt/bkedr/
cp bkedr.service /etc/systemd/system/

systemctl enable bkedr.service
systemctl daemon-reload
