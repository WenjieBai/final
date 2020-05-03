all:
	gcc purenc.c -o purenc -lgcrypt
	gcc purdec.c -o purdec -lgcrypt
clean:
	rm 

