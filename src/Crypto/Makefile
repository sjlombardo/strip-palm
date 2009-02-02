CC= gcc
CFLAGS= -DNOPILOT -g

all:
	$(CC) $(CFLAGS) rijndael_driver.c rijndael-256.c encrypt_mc_test.c rijndael_cbc.c	-o encrypt_mc_test
	$(CC) $(CFLAGS) rijndael_driver.c rijndael-256.c decrypt_mc_test.c rijndael_cbc.c	-o decrypt_mc_test
	$(CC) $(CFLAGS) ripemd_driver.c ripemd.c ripemd_kat_test.c -o ripemd_kat_test
	$(CC) $(CFLAGS) -DCONVERT_ENDIANNESS sha256_driver.c sha256.c sha256_kat_test.c -o sha256_kat_test
	$(CC) $(CFLAGS) -DTEST random.c  sha256.c -o random_test

test:
	./ripemd_kat_test > testvectors/ripemd_kat_test.out
	./random_test  >	testvectors/random_test.out
	./sha256_kat_test > testvectors/sha256_kat_test.out
	./encrypt_mc_test > testvectors/encrypt_mc_test.out
	./decrypt_mc_test > testvectors/decrypt_mc_test.out

	#TESTs FINSHED!
	#use the following commands to look for differences:
	# diff -iw testvectors/encrypt_mc_test.out testvectors/ecb_e_m.txt | more
	# diff -iw testvectors/decrypt_mc_test.out testvectors/ecb_d_m.txt | more	
	# cat testvectors/ripemd_kat_test.out

clean:
	rm -f encrypt_mc_test decrypt_mc_test ripemd_kat_test sha256_kat_test random_test *.o a.out testvectors/*.out

