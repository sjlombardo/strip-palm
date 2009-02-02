#include "register.h"

int main(int argc, char **argv) {
	const char *code;
	if(argc < 2 ) {
		printf("Not enough arguments");
		exit(1);
	}

	code = getCode(argv[1]);
	printf("%s\n", code);
}

