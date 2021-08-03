#!/bin/bash
source ../sh.config
for name in 10M 20M 30M 40M 50M
do
	sshpass -p "123qweASD" ssh root@$ip "cp /fixdataset/origindata /server/test.tar"
	python3 testfed.py ../dataset/$name
	sshpass -p "123qweASD" ssh root@$ip "rm -rf /server/*"
done
