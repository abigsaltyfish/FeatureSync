import os

SMALL_FILE_SIZE = 1024 * 1024
MAX_SMALL_FILE_SCALE = 0.3

def isdispersed(path):
	smallsize = 0
	allsize = 0
	flag = 0
	if os.path.isfile(path):
		flag = 0
	else:
		files = os.walk(path)
		for subfile in files:
		    sub_path = subfile[0]
		    for file_name in subfile[2]:
		        file_path = sub_path + '/' + file_name
		        filesize = os.path.getsize(file_path)
		        if filesize < SMALL_FILE_SIZE:
		            smallsize += filesize
		        allsize += filesize
		if smallsize / allsize > MAX_SMALL_FILE_SCALE:
			flag = 1
		else:
			flag = 0
	return flag

print(isdispersed("/home/aaa/图片/dataset/new/tensorflow"))
