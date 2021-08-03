import os
import sys
import time
sys.path.append("..")
from dest import ip
from dispersed import isdispersed

filename = sys.argv[1]
t1 = time.time()

tar_cmd = "./tar -cf test.tar " + filename
os.system(tar_cmd)

t2 = time.time()

if isdispersed(filename):
	sync_cmd = "rsync -rvz -B 700 test.tar rsync_backup@" + ip + "::server --password-file=../rsync.password"
else:
	sync_cmd = "rsync -rvz test.tar rsync_backup@" + ip + "::server --password-file=../rsync.password"
os.system(sync_cmd)

t3 = time.time()
remove_cmd = "rm test.tar"
os.system(remove_cmd)

with open('fedsynctime','a') as f:
	f.write("this file is = " + filename + '\n')
	f.write("tar + enc time = " + str(t2 - t1) + '\n')
	f.write("sync time = " + str(t3 - t2) + '\n')
	f.write('\n')
