#!/bin/bash
source ../sh.config
for name in linux-3.1 linux-4.2 linux-5.0 linux-5.8 opencv tensorflow
do
	python3 featuresync.py ../dataset/old/$name
	python3 featuresync.py ../dataset/new/$name
	rm -rf /server/*
done
