SAML Support for FreeRADIUS

This uses the mongoose webserver, please also check out 
https://github.com/hauke/mongoose and create a symlink to it:

 ln -s ../mongoose/mongoose.c mongoose.c
 ln -s ../mongoose/mongoose.h mongoose.h

eap_types.h and eap.h are copied from FreeRADIUS version 2.1.10, the 
version used in current ubuntu and debian, This must match the used 
version of FreeRADIUS otherwise you will encounter strange behavior.
