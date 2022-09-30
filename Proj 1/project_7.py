# include <stdio.h>

unsigned int magic(unsigned int i, unsigned int j) {
    i ^= j << 3
    j ^= i << 3
    i |= 58623
    j %= 0x42
    return i & j
}

void orbit() {
    char buf[8]
    gets(buf)
}

int main() {
    orbit()
    return 0
}
# CORRECT ADDRESS
0x80491fd < magic+24 > :        jmp    * %esp

found by taking address of where the breakpoint was and
x/i 0x80491fa+3

# Address of buf
0xffdf27a8
# Address of RIP
0xffdf27bc

difference = 20

8 04 91 fd
#__________________________________________
#New round!!
addres of buf
0xffe6c5f8

0xffe6c60c