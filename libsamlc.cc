
#include <xmltooling/util/DateTime.h>
#include <xmltooling/XMLObject.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/security/Credential.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/ParserPool.h>
#include <saml/saml2/core/Protocols.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <saml/saml2/metadata/MetadataCredentialCriteria.h>
#include <saml/SAMLConfig.h>
#include <sstream>
#include <xmltooling/signature/SignatureValidator.h>

#include "samlc.h"

using namespace opensaml::saml2;
using namespace opensaml::saml2p;
using namespace opensaml;
using namespace xmltooling;
using namespace xercesc;
using namespace std;
using namespace xmlsignature;

void saml_init()
{
	SAMLConfig::getConfig().init();
}

void saml_term()
{
	SAMLConfig::getConfig().term();
}
 // opensaml-2.4.3/samlsign/samlsign.cpp 
CredentialResolver* buildSimpleResolver(const char* key, const char* cert)
{
	static const XMLCh _CredentialResolver[] =	UNICODE_LITERAL_18(C,r,e,d,e,n,t,i,a,l,R,e,s,o,l,v,e,r);
	static const XMLCh _certificate[] =		UNICODE_LITERAL_11(c,e,r,t,i,f,i,c,a,t,e);
	static const XMLCh _key[] =			UNICODE_LITERAL_3(k,e,y);

	DOMDocument* doc = XMLToolingConfig::getConfig().getParser().newDocument();
	XercesJanitor<DOMDocument> janitor(doc);
	DOMElement* root = doc->createElementNS(NULL, _CredentialResolver);
	if (key) {
		auto_ptr_XMLCh widenit(key);
		root->setAttributeNS(NULL, _key, widenit.get());
	}
	if (cert) {
		auto_ptr_XMLCh widenit(cert);
		root->setAttributeNS(NULL, _certificate, widenit.get());
	}

	return XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(FILESYSTEM_CREDENTIAL_RESOLVER, root);
}

int saml_create(char *providerName, char *id, char *receiver, char *consumer, char *username, char *password, char *sigKeyPath, char *sigCertPath, char **result)
{
	XMLCh *xmlId;
	XMLCh *version;
	DateTime *issueInstant;
	XMLCh *destination;
	XMLCh *xmlProviderName;
	XMLCh *user;
	SubjectConfirmationData* subjectConfirmationData;
	string result_str;
	const char *result_char;

	XMLCh *assertionConsumerServiceURL;

	XMLCh *subjectConfirmationMethod;
	Subject *subject;
	NameID *nameID;

	XMLCh *passwordTag;
	XMLCh *secret;
	vector<Signature*> sigs;
	const Credential* cred = NULL;
	CredentialResolver *resolver = NULL;

	xmlId = XMLString::transcode(id);
	version = XMLString::transcode("2.0");
	issueInstant = new DateTime(time(NULL));
	destination = XMLString::transcode(receiver);

	xmlProviderName = XMLString::transcode(providerName);

	auto_ptr<AuthnRequest> request(AuthnRequestBuilder::buildAuthnRequest());
	request->setID(xmlId);
	request->setIssueInstant(issueInstant);
	request->setVersion(version);
	request->setDestination(destination);
	request->setProviderName(xmlProviderName);

	if (consumer) {
		assertionConsumerServiceURL = XMLString::transcode(consumer);
		request->setAssertionConsumerServiceURL(assertionConsumerServiceURL);
	}

	Issuer *issuer = IssuerBuilder::buildIssuer();
	issuer->setTextContent(xmlProviderName);
	request->setIssuer(issuer);

	if (username) {
		user = XMLString::transcode(username);
		subjectConfirmationMethod = XMLString::transcode("http://bos-bremen.de/password");
		subject = SubjectBuilder::buildSubject();

		nameID = NameIDBuilder::buildNameID();
		nameID->setTextContent(user);
		subject->setNameID(nameID);

		SubjectConfirmation* subjectConfirmation = SubjectConfirmationBuilder::buildSubjectConfirmation();
		subjectConfirmation->setMethod(subjectConfirmationMethod);

		subjectConfirmationData = SubjectConfirmationDataBuilder::buildSubjectConfirmationData();
		subjectConfirmation->setSubjectConfirmationData(subjectConfirmationData);

		subject->getSubjectConfirmations().push_back(subjectConfirmation);

		request->setSubject(subject);
	}

	if (sigKeyPath != NULL && sigCertPath != NULL) {
		// Append a Signature.
		Signature *sig = SignatureBuilder::buildSignature();
		request->setSignature(sig);

		// Sign while marshalling.
		try {
			sigs = vector<Signature*>(1, sig);
			resolver = buildSimpleResolver(sigKeyPath, sigCertPath);
		}
		catch (XMLToolingException& e) {
			printf("an error occurred while signing the saml request: \n%s\n", e.what());
			return -1;
		}

		CredentialCriteria cc;
		cc.setUsage(Credential::SIGNING_CREDENTIAL);
		cred = resolver->resolve(&cc);
	}

	DOMElement* requestElement = NULL;
	try {
		requestElement = request->marshall((DOMDocument*)NULL, &sigs, cred);
	}
	catch (XMLToolingException& e) {
		printf("an error occurred while marshalling the saml request: \n%s\n", e.what());
		return -1;
	}
	if (sigKeyPath != NULL && sigCertPath != NULL) {
		delete resolver;
	}

	if (username && password) {
		passwordTag = XMLString::transcode("password");
		secret = XMLString::transcode(password);
		subjectConfirmationData->getDOM()->setAttribute(passwordTag, secret);
	}

	XMLHelper::serialize(requestElement, result_str);

	result_char = result_str.c_str();
	*result = (char *)malloc(strlen(result_char) + 1);
	memcpy(*result, result_char, strlen(result_char) + 1);

	XMLString::release(&version);
	XMLString::release(&xmlId);
	delete issueInstant;
	XMLString::release(&destination);
	XMLString::release(&xmlProviderName);
	if (consumer) {
		XMLString::release(&assertionConsumerServiceURL);
	}
	if (username) {
		XMLString::release(&user);
		XMLString::release(&subjectConfirmationMethod);
		delete subject;
		delete nameID;
	}
	if (username && password) {
		XMLString::release(&passwordTag);
		XMLString::release(&secret);
	}

	return 0;
}

static char *convert_to_char(XMLObject *xml) {
	string result_str;
	DOMElement *requestElement = xml->marshall();
	XMLHelper::serialize(requestElement, result_str);
	return strdup(result_str.c_str());
}

int saml_parse(char *xmlResponse, char *decKeyPath, char *decKeyAlias, char *sigCertPath, struct saml_response **response)
{
	struct saml_response *result;

	result = (struct saml_response *)calloc(1, sizeof(struct saml_response));
	if (!result)
		return -1;

	try {
		ParserPool& p = XMLToolingConfig::getConfig().getParser();
		istringstream fs(xmlResponse);
		DOMDocument* doc = p.parse(fs);
		const XMLObjectBuilder* b = XMLObjectBuilder::getBuilder(doc->getDocumentElement());

		Response *response(dynamic_cast<Response*>(b->buildFromDocument(doc)));

		if (sigCertPath) {
			if (!response->getSignature())
				return -1;
			auto_ptr<CredentialResolver> resolver(buildSimpleResolver(NULL, sigCertPath));

			CredentialCriteria cc;
			cc.setUsage(Credential::SIGNING_CREDENTIAL);
			const Credential* cred = resolver->resolve(&cc);

			try {
				SignatureValidator sigVali(cred);
				sigVali.validate(response->getSignature());
			}
			catch (XMLToolingException& e) {
				printf("the signature of the saml response does not match: \n%s\n", e.what());
				return -1;
			}
		}

		result->data = response;
		result->destination = XMLString::transcode(response->getDestination());
		result->id = XMLString::transcode(response->getID());
		result->in_response_to = XMLString::transcode(response->getInResponseTo());

		if (response->getIssueInstant()) {
			result->issue_instant = XMLString::transcode(response->getIssueInstant()->getFormattedString());
		}
		if (response->getIssuer()) {
			result->issuer = XMLString::transcode(response->getIssuer()->getTextContent());
		}
		if (response->getStatus() && response->getStatus()->getStatusCode()) {
			result->status = XMLString::transcode(response->getStatus()->getStatusCode()->getValue());
		}
		if (!response->getAssertions().empty()) {
			saml2::Assertion *assertion = response->getAssertions()[0];
			result->assertion = assertion;
			result->assertion_char = convert_to_char(assertion);
		}
		if (!response->getEncryptedAssertions().empty()) {
			EncryptedAssertion *encrypted = response->getEncryptedAssertions()[0];

			auto_ptr<CredentialResolver> resolver(buildSimpleResolver(decKeyPath, NULL));
			saml2::Assertion *assertion(dynamic_cast<saml2::Assertion*>(encrypted->decrypt(*resolver, XMLString::transcode(decKeyAlias))));

			result->assertion = assertion;
			result->assertion_char = convert_to_char(assertion);
		}
	}
	catch (XMLToolingException& e) {
		printf("an error occurred while parsing the saml response: \n%s\n", e.what());
		return -1;
	}
	*response = result;

	return 0;
}

void saml_free_response(struct saml_response *response)
{
	if (response == NULL)
		return;

	if (response->data) {
		Response *xml(static_cast<Response*>(response->data));
		delete xml;
	}
	delete response->destination;
	delete response->id;
	delete response->in_response_to;
	delete response->issue_instant;
	delete response->issuer;
	delete response->status;
	free(response->assertion_char);
	if (response->assertion) {
		saml2::Assertion *xml(static_cast<saml2::Assertion*>(response->assertion));
		delete xml;
	}
	free(response);
}

// source http://www.codesynthesis.com/~boris/blog/2009/05/18/running-xpath-on-cxx-tree-object-model/
char *saml_get_char_xpath(void *xmlptr, char *xpath, char *name)
{
	XMLObject *xml(dynamic_cast<XMLObject*>((XMLObject *)xmlptr));
	DOMElement *root = xml->marshall();
	DOMDocument* doc (root->getOwnerDocument ());
	XMLSize_t i;
	char *result = NULL;

	const DOMXPathNSResolver* resolver=doc->createNSResolver(doc->getDocumentElement());

	XMLCh xpathStr[100];
	XMLString::transcode(xpath,xpathStr,99);
	DOMXPathResult* xmlResult = dynamic_cast<DOMXPathResult*>(doc->evaluate(xpathStr, doc->getDocumentElement(), resolver, DOMXPathResult::ORDERED_NODE_SNAPSHOT_TYPE , NULL));
	if (!xmlResult) {
		goto err_resolver;
	}

	for (i = 0; i < xmlResult->getSnapshotLength(); i++) {
		xmlResult->snapshotItem(i);
		DOMNode *n = xmlResult->getNodeValue();
		if (!n || !n->getFirstChild())
			continue;
		if (name) {
			DOMNode *name_attr = n->getAttributes()->getNamedItem(XMLString::transcode("Name"));
			if (!name_attr)
				continue;
			char *att_name = XMLString::transcode(name_attr->getTextContent());
			if (strlen(att_name) != strlen(name) || strncmp(name,att_name, strlen(name))) {
				delete att_name;
				continue;
			}
			delete att_name;
		}
		char * childname = XMLString::transcode(n->getFirstChild()->getTextContent());
		result = strdup(childname);
		delete childname;
		goto end;
	}
end:
	delete xmlResult;
err_resolver:
	delete resolver;

	return result;
}
