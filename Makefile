all: test

shim:
	$(CC) -dynamiclib -Wall -Werror -Iblindrsa_src -I/opt/homebrew/opt/openssl@3/include -I/usr/local/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -L/usr/local/opt/openssl@3/lib -I/Library/Java/JavaVirtualMachines/jdk-20.jdk/Contents/Home/include -I/Library/Java/JavaVirtualMachines/jdk-20.jdk/Contents/Home/include/darwin blindrsa_src/blind_rsa.c -o libblind_rsa.dylib PrivacyPassExample.c -fPIC -lcrypto
