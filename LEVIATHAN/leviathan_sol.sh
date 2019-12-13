LEVIATHAN

All the usernames are leviathan followed by the level number.

Level0:
ssh leviathan0@leviathan.labs.overthewire.org -p 2223
password: leviathan0

ls -a
cd .backup
~/.backup$ ls
bookmarks.html

grep -i "password" bookmarks.html

Means we look for the word password, case insensitive

Level1:
ls -a
file check
# check: setuid ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0d17ae20f672ebc7d440bb4562277561cc60f2d0, not stripped
./check
# password: password
# Wrong password, Good Bye ...

# ltrace is a command that runs the specified command until it exits
ltrace ./check

# __libc_start_main(0x804853b, 1, 0xffffd784, 0x8048610 <unfinished ...>
# printf("password: ")                             = 10
# getchar(1, 0, 0x65766f6c, 0x646f6700password: 3
# )            = 51
# getchar(1, 0, 0x65766f6c, 0x646f6700)            = 10
# getchar(1, 0, 0x65766f6c, 0x646f6700
# )            = 10
# strcmp("3\n\n", "sex")                           = -1
# puts("Wrong password, Good Bye ..."Wrong password, Good Bye ...
# )             = 29
# +++ exited (status 0) +++


# The  strcmp()  function compares the two strings s1 and s2.  It returns
# an integer less than, equal to, or greater than zero if  s1  is  found,
# respectively, to be less than, to match, or be greater than s2

# It looks like the function strcmp is comparing our input to the stored password: sex

./check
# password: sex
cat /etc/leviathan_pass/leviathan2

# Found it !


Level2:
