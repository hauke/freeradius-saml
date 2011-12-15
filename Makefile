
CFLAGS = -c -g -I. -Wall -fPIC
CXXFLAGS = -c -g -Wall -fPIC

LIBS = -lssl -lcrypto -lsamlc

all:  libsamlc.so rlm_eap_gtc.so rlm_saml.so testlibsaml

libsamlc.so: libsamlc.o
	cc -g -shared -Wl,-soname,$@ -o $@ $^ -lsaml

rlm_eap_gtc.so: rlm_eap_gtc.o
	cc -g -shared -Wl,-soname,$@ -o $@ $^

rlm_saml.so: rlm_saml.o libmongoose.so
	cc -g -shared -Wl,-soname,$@ -o $@ $^ -L. -lsamlc -lssl -lcrypto -lmongoose

libmongoose.so: mongoose.o
	cc -g -shared -Wl,-soname,$@ -o $@ $^

testlibsaml: testlibsaml.o
	cc -g testlibsaml.o -L. -lsamlc -o testlibsaml
clean:
	rm -f *.o *.so *~
