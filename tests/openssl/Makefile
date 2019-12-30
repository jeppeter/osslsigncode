

all:main
	
main:main.o
	gcc -Wall -o $@  $< -lcrypto

main.o:main.c
	gcc  -Wall -c $< -o $@

clean:
	rm -f main main.o