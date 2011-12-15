// http://www.parashift.com/c++-faq-lite/mixing-c-and-cpp.html

#ifdef __cplusplus
extern "C" {
#endif

struct saml_response {
	void *data;
	char *destination;
	char *id;
	char *in_response_to;
	char *issue_instant;
	char *issuer;
	char *status;
	char *assertion_char;
	void *assertion;
};

int saml_create(char *providerName, char *id, char *receiver, char *consumer, char *username, char *password, char *sigKeyPath, char *sigCertPath, char **result);

int saml_parse(char *xmlResponse, char *decKeyPath, char *decKeyAlias, char *sigCertPath, struct saml_response **response);

void saml_free_response(struct saml_response *response);

char *saml_get_char_xpath(void *xmlptr, char *xpath, char *name);

void saml_term();

void saml_init();

#ifdef __cplusplus
}
#endif
