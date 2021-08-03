#!/bin/bash
source ../sh.config
for name in cloud linux-3.1 linux-4.2 linux-5.0 linux-5.8 opencv spring tensorflow origindata
do
	python3 featuresync.py ../dataset/old/$name/
	sshpass -p "123qweASD" ssh root@$ip "mv /server/test.tar /dataset/$name"
done
