#include <samlc.h>
#include <stdio.h>
#include <stdlib.h>

#define SAML_RESPONSE "<?xml version=\"1.0\" encoding=\"UTF-8\"?><samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Destination=\"https://bachelor.lan:9875/samlResponse\" ID=\"1320364198133.127.0.0.1.7992992958593679671\" InResponseTo=\"0x8c4e6675f042f2229c901c34c71b8050\" IssueInstant=\"2011-11-03T23:49:58.133Z\" Version=\"2.0\"><saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">Governikus Autent</saml:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
<ds:SignedInfo>\
<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\
<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\
<ds:Reference URI=\"#1320364198133.127.0.0.1.7992992958593679671\">\
<ds:Transforms>\
<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\
<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"><ec:InclusiveNamespaces xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\" PrefixList=\"ds saml samlp xenc\"/></ds:Transform>\
</ds:Transforms>\
<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\
<ds:DigestValue>MbQg1TvXBSDTcvmwllmmJbOs0Zc=</ds:DigestValue>\
</ds:Reference>\
</ds:SignedInfo>\
<ds:SignatureValue>\
XPAx++0oP1bkow4DoNonhpKsn3PVk2Ab6l4t4JRQ/+hjIcAlb2sTLxirvF5Oou2E2K2ZSM9lKk4g\
xzwVaoeNGSIBTOYxBu7QXyMNfO2FpA7CVD4DmrGG+kyz24siohk63jeGB2pmhTzl5cpGO1xcRrF8\
GHBmMHqQMxMXbXQg4YRgFvXBWa1iT/BGa0dlpxTkMH69Xy/veh5xG+VxqJKk+bNbT/A85MVNerOK\
EaFoTdXsHuAh7NNDBTxi5KB9Bsvc2COnYN7M6gD9i++S6+vo273U9anLhwpdYtKfjJvt9TfXF8h+\
RK4VDyinZWwR/RzLW6XhyiqpD4WAKGDm2TYyKw==\
</ds:SignatureValue>\
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDZDCCAkygAwIBAgIDAfXPMA0GCSqGSIb3DQEBCwUAMDUxGDAWBgNVBAMMD2JvcyB0ZXN0IGlz\
c3VlcjELMAkGA1UEBhMCREUxDDAKBgNVBAoMA2JvczAeFw0wOTEwMDIxMzQwNDhaFw0xMjEwMDEx\
MzQwNDhaMEgxKzApBgNVBAMMIkdvdmVybmlrdXMgSWRlbnRpdHkgTWFuYWdlciAoVGVzdCkxCzAJ\
BgNVBAYTAkRFMQwwCgYDVQQKDANib3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCD\
nVPhVnZylgTxVo0JezkWeOwFz+uBq4HLEc3pplah3k5fs8AGtR43X35lfoVTzt1yf56se4cx/sqP\
EU3/nIxQVlL9Dm27cD2lEk+X8FlQzmV6EDHaFICSUU88IZq9X4OnWcyxw48LtgnsDvc9UpQoPNxp\
NuLxvU5CtxvnP9U8oyYyONuq39i0DYOaV/PpPj8C7T5pZ8PAb9l6DM1ufE3bqcsiZTzcoq3mYYj0\
VGyJ+YunkD6FAH+pNh1ag5dxt4wp+L4WJsTzzrYESkPytmayfwtN721YFkPXOM/DB4vpE5Ak5TyJ\
mylI0nvdCdk4ul4m3OejFc9KkpABqRrnV+URAgMBAAGjajBoMB0GA1UdDgQWBBT0MepFRAPp0CF5\
HdQIIpT9Wtpp2TAfBgNVHSMEGDAWgBQVrcPt1EzaZuATCiEecQ+SUG6SzzAOBgNVHQ8BAf8EBAMC\
BJAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggEBAHJIwr0lTF9HhFEU\
1X9wGZZv9wM2bnUcYY5AQar8REAs0TD1RjQfccpxSASBGLPjAcxly3uPrtxrjQ1vanpH4rOBm+2e\
3cZWUH/AYBEXfd6uRmWg62mlVi0BCINwjXK7rxc2Drpmg4JooKewqC/zQlKqw7Ada0ysm/IsTkgA\
Sr+4rjVtfV83iW/fcWll7pCqp5suAJpaf9dvjr1oo3O7OFofgE0VYma6yNTvvreN/mzYYoy1HUjI\
aJiM2dqaGg+Dfp8m9BmSL6knHHU8gsXQPtH77BMtkDc+B+avon0DVzjr7cMDz6whV8O/WmeODctl\
ZqbyvNA0mhrK59U8Ms5smzQ=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status><saml:EncryptedAssertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"_2bb5e874fe2c27ef02918ad423706654\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><xenc:EncryptedKey Id=\"_899f65fd331f3e3fc5f515d6900576dd\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDYTCCAkmgAwIBAgIDAfXPMA0GCSqGSIb3DQEBCwUAMDUxGDAWBgNVBAMMD2JvcyB0ZXN0IGlz\
c3VlcjELMAkGA1UEBhMCREUxDDAKBgNVBAoMA2JvczAeFw0wOTEwMDIxMzQxMThaFw0xMjA5MzAy\
MjAwMDBaMEUxKDAmBgNVBAMMH0V4YW1wbGUgU2VydmljZSBQcm92aWRlciAoVGVzdCkxCzAJBgNV\
BAYTAkRFMQwwCgYDVQQKDANib3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5237+\
fXXjjFHda8CZt8ZANpxKExz1RYrtE+1EXh3AgrfkwwCyYNaB8/q/LgzCZYfocHJJdWyJLnQTU+ln\
SxC+12sV1wLv/Pi++smpmBAr8cOdNHfFRNFQJA9Rng8agYXBGDehtrn3uTq/DwNEkPy9UTCSjHie\
HefXAK9Be8kfBI76q492Sj2C58vNCjAt6UkEn79mTl+bDSkZbHEdsnHz7YcRfovnTQMvZXviqnpH\
XkCcp5ZBCv+PybpKqXM9tbLcRVmGgpSz6D9aTkr/ZRYS5cHQ+jV7Ir1g9VXpk3raMMh75QL0oPuf\
Ssoth91zyueGxo6zTKsodG5s2xcs14CfAgMBAAGjajBoMB0GA1UdDgQWBBR7Qwoq4XI+RdmTcppv\
y2C2r5T/LTAfBgNVHSMEGDAWgBT0a1xy4ny8H72MRAeJ/yrgm1QAqTAOBgNVHQ8BAf8EBAMCBJAw\
FgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggEBAAJABaeX7kucVjPUAcdm\
Doz+dOO8/Tr6rNzKBNyOCQGHAbrVYbLPDj2T/j7MqqDbgYe8a8/mZ25VNI/VZ36jc/BZPkCVOuCR\
nYh0poGHlhFkYpK9RVk1O8lEBk/CemOuRwpLrFg4Z32V3XSFtTB26HEo1nqhBVAeY1xFbxrua3nx\
UmFVm4Hh39YKxzJf6fmsN8B0HYjM7AGtGnPLDyQc4U2VuBpxV9E5LhoMgi3gKvoFVaeAt3UwupKZ\
SYQkQ3nrd6JYeLTVJ2dnGRqVPxgrPLelOZ73sY/Iv4hJI9f/01KFcVyl6Km7UmVS5952Pe03PWpU\
ZJHOPilF3FvLch1/nH8=</ds:X509Certificate></ds:X509Data></ds:KeyInfo><xenc:CipherData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:CipherValue xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">G4lP6M1QxUHWYmXkiYG+nbzP/fUeG7Bk72u/PsP7yFGev3RRvYzO+i7m/aK9VIlAFo00qHHjlAjN\
f/jmk5IKW3an1diKNBCsioPFf10yM1yZtOuLH7+E+9NFOnCDWB4hA20QY1LxxznV+UmBhUEsflDf\
M0M4QdslF8pvBmScAEveEdZBIUGEM+UWjlk+LN4VEJyEX6URU7v5tQRIIPDHH4f3BiHxfRNTK5O1\
MTcTycXp7HSA1JQx3bdWA6g/UwO3xwJEdoGAwT2FJjn2ZuKGuLs5D7BYiCLVSBWgbhb8lSdAJizV\
b/GwJVZaoJmQKbRAEatxTp7U7Cyy4wSaES0t2A==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:CipherValue xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">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</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion></samlp:Response>\n"

#define DEC_KEY_PATH "/home/hauke/uni/bachelor-git/mongoose/serviceProvider_decrypt.pem"
#define DEC_KEY_ALIAS "demo_epa_dummy_applet"

int parse()
{
	struct saml_response *response;
	char *elem;

	saml_init();

	if (saml_parse(SAML_RESPONSE, DEC_KEY_PATH, DEC_KEY_ALIAS, NULL,
		       &response)) {
		printf("can not parse saml response \n");
		return -1;
	}

	printf("Assertion: %s\n", response->assertion_char);

	elem = saml_get_char_xpath(response->assertion, "//saml:Assertion/saml:AttributeStatement/saml:Attribute", "FamilyNames");

	printf("elem: %s\n", elem);
	free(elem);
	
	elem = saml_get_char_xpath(response->assertion, "//saml:Assertion/saml:AttributeStatement/saml:Attribute", "GivenNames");

	printf("elem: %s\n", elem);
	free(elem);
	
	elem = saml_get_char_xpath(response->assertion, "//saml:Assertion/saml:AttributeStatement/saml:Attribute", "PlaceOfResidence");

	printf("elem: %s\n", elem);
	free(elem);
	saml_free_response(response);
	saml_term();

	return 0;
}

int create()
{
	char *result;

	saml_init();

	saml_create("demo_epa_dummy_applet", "123", "https://192.168.56.1:8443/gov_autent/async",NULL, NULL, NULL, "/home/hauke/uni/bachelor-git/mongoose/serviceProvider_new.pem", "/home/hauke/uni/bachelor-git/mongoose/serviceProvider_new_cert.pem", &result);
	printf("elem: %s\n", result);
	
	free(result);
	saml_term();

	return 0;
}

int main()
{
	return create();
}
