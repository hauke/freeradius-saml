/*
 * rlm_saml.c
 *
 * Version:     $Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2011 Hauke Mehrtens
 */

#include <freeradius/ident.h>
#include <freeradius/radiusd.h>
#include <freeradius/modules.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>

#include "samlc.h"
#include <ctype.h>
#include <mongoose.h>

// page show to forward the SAML Request.
#define PAGE_SAML_REQUEST "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n\
<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"de\">\n\
<head>\n\
<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\n\
<title>Weiterleitung zu Governikus Autent</title>\n\
</head>\n\
<body onload=\"document.forms[0].submit()\" style=\"background-color: #F0EEEE; font-size: 0.75em; font-family: Verdana, sans-serif, Arial\">\n\
<h1>Weiterleitung zu Governikus Autent</h1>\n\
<noscript>\n\
<p>\n\
Der SAML-Request soll nun per HTTP Post an den Server Governikus Autent &uuml;bertragen werden. Da Ihr\n\
 Browser kein Java Script ausf&uuml;hrt, klicken Sie bitte auf den folgenden Button, um fortzufahren.\n\
</p>\n\
</noscript>\n\
<form action=\"%s\" method=\"post\">\n\
<div>\n\
<input type=\"hidden\" name=\"SAMLRequest\" value=\"%s\"/>\n\
<input type=\"hidden\" name=\"RelayState\" value=\"State#1314017600299\"/>\n\
<input type=\"submit\" value=\"Weiter\"/>\n\
</div>\n\
</form>\n\
</body>\n\
</html>\n"

#define ID_LEN 32

// based on max from http://gcc.gnu.org/onlinedocs/gcc/Typeof.html
#define min(a,b) \
       ({ typeof (a) _a = (a); \
	   typeof (b) _b = (b); \
	 _a < _b ? _a : _b; })

// congiguration for this module
typedef struct rlm_saml_config_t {
	char *saml_receiver_url;
	char *saml_client_url;
	char *saml_entityID;
	char *saml_request_sig_key;
	char *saml_request_sig_cert;
	char *saml_response_sig_cert;
	char *saml_response_dec_key;
	char *saml_response_dec_alias;
	char *web_ssl_cert;
	char *web_hostname;
	int web_port;
	int username_restictedID;
	int username_name;
} rlm_saml_config_t;

typedef struct rlm_saml_web_t {
	unsigned char id[ID_LEN + 2];
	time_t expiry_date;
	char *saml_request;
	char *saml_response;
	struct saml_response *response;
	pthread_mutex_t response_available;
	struct rlm_saml_web_t *next;
	struct rlm_saml_web_t *priv;
	struct rlm_saml_data_t *head;
} rlm_saml_web_t;

typedef struct rlm_saml_data_t {
	rlm_saml_config_t config;
	pthread_mutex_t web_lock;
	rlm_saml_web_t *web;
	struct mg_context *webserver;
} rlm_saml_data_t;

static const CONF_PARSER module_config[] = {
	{ "web_port", PW_TYPE_INTEGER, offsetof(rlm_saml_config_t,web_port), NULL, NULL},
	{ "web_ssl_cert", PW_TYPE_STRING_PTR, offsetof(rlm_saml_config_t,web_ssl_cert), NULL, NULL},
	{ "web_hostname", PW_TYPE_STRING_PTR, offsetof(rlm_saml_config_t,web_hostname), NULL, NULL},
	{ "saml_receiver_url", PW_TYPE_STRING_PTR, offsetof(rlm_saml_config_t,saml_receiver_url), NULL, NULL},
	{ "saml_request_sig_key", PW_TYPE_STRING_PTR, offsetof(rlm_saml_config_t,saml_request_sig_key), NULL, NULL},
	{ "saml_request_sig_cert", PW_TYPE_STRING_PTR, offsetof(rlm_saml_config_t,saml_request_sig_cert), NULL, NULL},
	{ "saml_response_sig_cert", PW_TYPE_STRING_PTR, offsetof(rlm_saml_config_t,saml_response_sig_cert), NULL, NULL},
	{ "saml_response_dec_key", PW_TYPE_STRING_PTR, offsetof(rlm_saml_config_t,saml_response_dec_key), NULL, NULL},
	{ "saml_response_dec_alias", PW_TYPE_STRING_PTR, offsetof(rlm_saml_config_t,saml_response_dec_alias), NULL, NULL},
	{ "saml_client_url", PW_TYPE_STRING_PTR, offsetof(rlm_saml_config_t,saml_client_url), NULL, NULL},
	{ "saml_entityID", PW_TYPE_STRING_PTR, offsetof(rlm_saml_config_t,saml_entityID), NULL, NULL},
	{ "username_restictedID", PW_TYPE_BOOLEAN, offsetof(rlm_saml_config_t,username_restictedID), NULL, NULL},
	{ "username_name", PW_TYPE_BOOLEAN, offsetof(rlm_saml_config_t,username_name), NULL, NULL},
	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

// source: https://devenix.wordpress.com/2008/01/18/howto-base64-encode-and-decode-with-c-and-openssl-2/
static char *base64(const unsigned char *input, int length)
{
	BIO *bmem, *b64;
	BUF_MEM *bptr;

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, input, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	char *buff = (char *)malloc(bptr->length);
	memcpy(buff, bptr->data, bptr->length-1);
	buff[bptr->length-1] = 0;

	BIO_free_all(b64);

	return buff;
}

// source: https://devenix.wordpress.com/2008/01/18/howto-base64-encode-and-decode-with-c-and-openssl-2/
static char *unbase64(unsigned char *input, int length)
{
	BIO *b64, *bmem;

	char *buffer = (char *)malloc(length);
	memset(buffer, 0, length);

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new_mem_buf(input, length);
	bmem = BIO_push(b64, bmem);

	BIO_read(bmem, buffer, length);

	BIO_free_all(bmem);

	return buffer;
}

static rlm_saml_web_t *saml_web_add_elem(rlm_saml_data_t *data, char *id, char *saml_request)
{
	rlm_saml_web_t *elem;
	
	elem = rad_malloc(sizeof(*elem));
	if (!elem) {
		return NULL;
	}
	memset(elem, 0, sizeof(*elem));
	
	memcpy(elem->id, id, ID_LEN + 2);
	elem->saml_request = saml_request;
	elem->head = data;
	elem->expiry_date = time(0) + 120;
	pthread_mutex_init(&elem->response_available, NULL);
	pthread_mutex_lock(&elem->response_available);

	pthread_mutex_lock(&data->web_lock);
	if (data->web != NULL) {
		elem->next = data->web;
		elem->priv = data->web->priv;
		elem->next->priv = elem;
		elem->priv->next = elem;
	} else {
		elem->next = elem;
		elem->priv = elem;
	}
	data->web = elem;
	pthread_mutex_unlock(&data->web_lock);
	return elem;
}

static void saml_web_free_elem(rlm_saml_web_t *elem)
{
	free(elem->saml_request);
	free(elem->saml_response);
	saml_free_response(elem->response);
	pthread_mutex_destroy(&elem->response_available);
	free(elem);
}

static void saml_web_remove_elem_no_lock(rlm_saml_web_t *elem)
{
	rlm_saml_data_t *data = elem->head;
	if (elem->next == elem) {
		data->web = NULL;
		saml_web_free_elem(elem);
		return;
	}
	elem->next->priv = elem->priv;
	elem->priv->next = elem->next;
	saml_web_free_elem(elem);
}

static rlm_saml_web_t *saml_web_get_elem(rlm_saml_data_t *data, char *id)
{
	rlm_saml_web_t *elem;
	rlm_saml_web_t *current;
	time_t now;

	now = time(0);

	pthread_mutex_lock(&data->web_lock);	
	if (data->web == NULL) {
		pthread_mutex_unlock(&data->web_lock);
		return NULL;
	}

	elem = data->web;
	do {
		if (!memcmp(id, elem->id, ID_LEN + 2)) {
			pthread_mutex_unlock(&data->web_lock);
			return elem;
		}

		current = elem;
		elem = elem->next;
		if (elem->expiry_date < now)
			saml_web_remove_elem_no_lock(current);
	} while (elem != data->web);
	pthread_mutex_unlock(&data->web_lock);

	return NULL;
}

static void saml_web_remove_elem(rlm_saml_web_t *elem)
{
	rlm_saml_data_t *data = elem->head;

	pthread_mutex_lock(&data->web_lock);
	saml_web_remove_elem_no_lock(elem);
	pthread_mutex_unlock(&data->web_lock);
}

static void saml_web_write_error_message(struct mg_connection *conn, char* message) {
	printf("Write error message: %s\n", message);
	mg_printf(conn, "HTTP/1.1 200 OK\r\n"
		"Content-Length: %i\r\n"
		"Content-Type: text/html\r\n\r\n"
		"%s", strlen(message), message);
}

static void *saml_web_callback(enum mg_event event, struct mg_connection *conn,
				const struct mg_request_info *request_info) {
	rlm_saml_data_t *user_data = (rlm_saml_data_t *)request_info->user_data;

	printf("SAML: WEB: got request for uri: %s query_string: %s\n", request_info->uri, request_info->query_string);

	if (event == MG_NEW_REQUEST) {
		char *result = NULL;

		if (strlen(request_info->uri) == strlen("/samlRequest") &&
		    !strncmp("/samlRequest", request_info->uri, strlen("/samlRequest")) &&
		    strlen(request_info->query_string) > ID_LEN + 2 + 2 &&
		    !strncmp("id=", request_info->query_string, strlen("id="))) {
			char *id;
			rlm_saml_web_t *elem;
			char *saml_request_base64;
			char *html_page;
			size_t size;
			
			id = request_info->query_string + strlen("id=");
			elem = saml_web_get_elem(user_data, id);
			if (!elem) {
				saml_web_write_error_message(conn, "id not found");
				goto out;
			}

			saml_request_base64 = base64((const unsigned char *)elem->saml_request, strlen(elem->saml_request));
			size = strlen(PAGE_SAML_REQUEST) + strlen(saml_request_base64) + strlen(user_data->config.saml_receiver_url) - 4 + 1;
			html_page = rad_malloc(size);
			if (!html_page) {
				saml_web_write_error_message(conn, "malloc failed");
				goto out;
			}

			if (snprintf(html_page, size, PAGE_SAML_REQUEST, user_data->config.saml_receiver_url, saml_request_base64) < 0) {
				free(html_page);
				saml_web_write_error_message(conn, "writing html_page failed");
				goto out;
			}

			mg_printf(conn, "HTTP/1.1 200 OK\r\n"
				"Content-Length: %i\r\n"
				"Content-Type: text/html\r\n\r\n",
				strlen(html_page));
			mg_write(conn, html_page, strlen(html_page));
			free(html_page);

			result = "";
			goto out;
		} else if (strlen(request_info->uri) == strlen("/samlResponse") &&
		    !strncmp("/samlResponse", request_info->uri, min(strlen(request_info->uri), strlen("/samlResponse")))) {
			struct saml_response *response_data;
			rlm_saml_web_t *elem;

			result = "";
			// Read data from the remote end, return number of bytes read.
			const char *size_str = mg_get_header(conn, "Content-Length");
			if (!size_str) {
				saml_web_write_error_message(conn, "No Content-Length");
				goto out;
			}
			long int size = strtol(size_str, NULL, 10);
			if (size <= 0 || size >= 30000) {
				saml_web_write_error_message(conn, "Content-Length too big");
				goto out;
			}
			char *post_message = rad_malloc(size);
			if (!post_message) {
				saml_web_write_error_message(conn, "malloc failed");
				goto out;
			}
			mg_read(conn, post_message, size);

			char *saml_response_base64 = rad_malloc(size);
			if (!saml_response_base64) {
				free(post_message);
				saml_web_write_error_message(conn, "malloc failed");
				goto out;
			}
			mg_get_var(post_message, size, "SAMLResponse", saml_response_base64, size);
			free(post_message);
			char *saml_response = unbase64((unsigned char *)saml_response_base64, strlen(saml_response_base64));
			free(saml_response_base64);
			if (!saml_response) {
				saml_web_write_error_message(conn, "malloc failed");
				goto out;
			}
			if (saml_parse(saml_response,
				       user_data->config.saml_response_dec_key,
				       user_data->config.saml_response_dec_alias,
				       user_data->config.saml_response_sig_cert,
				       &response_data)) {
				free(saml_response);
				saml_web_write_error_message(conn, "can not parse saml response");
				goto out;
			}
			elem = saml_web_get_elem(user_data, response_data->in_response_to);
			if (!elem) {
				free(saml_response);
				saml_free_response(response_data);
				saml_web_write_error_message(conn, "id not found");
				goto out;
			}
			elem->response = response_data;
			elem->saml_response = saml_response;
			pthread_mutex_unlock(&elem->response_available);
			
			mg_printf(conn, "HTTP/1.1 200 OK\r\n"
				"Content-Length: %i\r\n"
				"Content-Type: text/text\r\n\r\n",
				strlen(saml_response));
			mg_write(conn, saml_response, strlen(saml_response));

			result = "";
			goto out;
		} else {
			// Echo requested URI back to the client
			mg_printf(conn, "HTTP/1.1 200 OK\r\n"
				"Content-Length: %i\r\n"
				"Content-Type: text/html\r\n\r\n"
				"%s", strlen(request_info->uri), request_info->uri);
			result = "";
			goto out;
		}
out:
		return result;
	} else {
		return NULL;
	}
}

static int saml_web_start(rlm_saml_data_t *data)
{
	char port[10];

	snprintf(port, 10, "%is", data->config.web_port);
	const char *options[] = {
		"listening_ports", port,
		"ssl_certificate", data->config.web_ssl_cert,
		NULL};

	data->webserver = mg_start(&saml_web_callback, data, options);
	if (!data->webserver)
		return -1;
	return 0;
}

static int saml_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_saml_data_t *data;

	data = rad_malloc(sizeof(*data));
	if (!data) {
		goto err_return;
	}
	memset(data, 0, sizeof(*data));

	if (cf_section_parse(conf, &data->config, module_config) < 0) {
		goto err_malloc;
	}

	pthread_mutex_init(&data->web_lock, NULL);

	if (saml_web_start(data)){
		goto err_malloc;
	}

	saml_init();

	*instance = data;

	return 0;

err_malloc:
	free(data);
err_return:
	return -1;
}

static int saml_detach(void *instance)
{
	rlm_saml_data_t *data = (rlm_saml_data_t *)instance;

	mg_stop(data->webserver);
	saml_term();
	return 0;
}

// based on: http://codepad.org/lCypTglt
// and http://www.geekhideout.com/urlcode.shtml

static const char* hexDigest = "0123456789abcdef";

static char toHex(char from)
{
	return hexDigest[from & 15];
}

static void toHexStr(unsigned char *from, size_t from_len, char *buf, size_t buf_len)
{
	int write = 0;
	int read = 0;

	while (read < from_len && write < buf_len) {
		buf[write] = toHex(from[read] >> 4);
		write++;
		buf[write] = toHex(from[read]);
		write++;
		read++;
	}
}

void remove_spaces(char *source, char *dest)
{
	while(*source) {
		if (!ispunct(*source) && !isspace(*source)) {
			*dest = *source;
			dest++;
		}
		source++;
	}
	*dest = 0;
}

#define FRAGEMNT_MAX_LENGTH 240
static int add_fragmented(void *message, int len, VALUE_PAIR **vp, char *pairName)
{
	int pos = 0;
	VALUE_PAIR *pair;

	for(; len > 0 ; len = len - FRAGEMNT_MAX_LENGTH){
		char part[FRAGEMNT_MAX_LENGTH + 1];
		memcpy(part, message + pos, min(FRAGEMNT_MAX_LENGTH, len));
		part[min(FRAGEMNT_MAX_LENGTH, len)] = 0;
		printf("message_part: %s\n", part);
		pair = pairmake(pairName, part, T_OP_EQ);
		if (!pair)
			return -1;
		pairadd(vp, pair);
		pos = pos + FRAGEMNT_MAX_LENGTH;
	}
	return 0;
}

#define SAML_URL_STR "https://%s:%i/samlRequest?id=%s"
static int saml_authorize(void *instance, REQUEST *request)
{
	VALUE_PAIR *pair;
	char *url;
	char *url_to_send;
	size_t size;
	unsigned char rand[ID_LEN / 2];
	char randHex[ID_LEN + 3];
	char *saml_request;
	rlm_saml_data_t *data = (rlm_saml_data_t *)instance;
	rlm_saml_web_t * elem;

	printf("SAML: saml_authorize\n");

	if (!RAND_bytes(rand, ID_LEN / 2))
		return 0;

	toHexStr(rand, sizeof(rand), randHex + 2, sizeof(randHex) - 3);
	randHex[0] = '0';
	randHex[1] = 'x';
	randHex[ID_LEN + 2] = 0;

	if (saml_create(data->config.saml_entityID, randHex,
			data->config.saml_receiver_url, NULL, NULL, NULL,
			data->config.saml_request_sig_key,
			data->config.saml_request_sig_cert, &saml_request)) {
		return 0;
	}

	printf("SAML: saml_authorize: saml_request: %s\n", saml_request);
	elem = saml_web_add_elem(data, randHex, saml_request);
	if (!elem)
		return 0;

	size = strlen(SAML_URL_STR) + 1 - 6 + strlen(data->config.web_hostname) + 5 + ID_LEN +2;
	url = rad_malloc(size);
	if (!url)
		return 0;
	if (snprintf(url, size, SAML_URL_STR, data->config.web_hostname, data->config.web_port, randHex) < 0) {
		free(url);
		return 0;
	}

	if (data->config.saml_client_url) {
		char *url_encode;

		size = strlen(url) * 2;
		url_encode = rad_malloc(size);
		if (!url_encode) {
			free(url);
			return 0;
		}
		mg_url_encode(url, url_encode, size);
		free(url);

		size = strlen(url_encode) + strlen(data->config.saml_client_url) + 1;
		url_to_send = rad_malloc(size);
		if (!url_to_send) {
			free(url_encode);
			return 0;
		}

		if (snprintf(url_to_send, size, data->config.saml_client_url, url_encode) < 0) {
			free(url_encode);
			free(url_to_send);
			return 0;
		}
		free(url_encode);
	} else {
		url_to_send = url;
	}

	size = strlen(url_to_send) + 8 + 1;
	url = rad_malloc(size);
	if (!url) {
		free(url_to_send);
		return 0;
	}
			
	if (snprintf(url, size, "OPENURL=%s", url_to_send) < 0) {
		free(url_to_send);
		free(url);
		return 0;
	}
	free(url_to_send);

	pair = pairmake("Crypt-Password", url, T_OP_EQ);
	if (!pair) {
		free(url);
		return 0;
	}
	pairadd(&request->config_items, pair);
	free(url);

	return RLM_MODULE_NOOP;
}

static int saml_authenticate(void *instance, REQUEST *request)
{
	VALUE_PAIR *vp;
	int ret;
	rlm_saml_data_t *data = (rlm_saml_data_t *)instance;
	rlm_saml_web_t *elem;
	struct timespec timeout = {0,0};
	char result[300];
	char decoded[300];
	char id[64];
	char *name = NULL;
	int size;

	printf("SAML: saml_authenticate\n");

	vp = pairfind(request->config_items, PW_AUTHTYPE);
	if (vp != NULL) {
		printf("SAML: PW_AUTHTYPE: %s\n", vp->vp_strvalue);
	} else {
		pairadd(&request->config_items,
			pairmake("Auth-Type", "SAML", T_OP_EQ));
	}


	vp = pairfind(request->packet->vps, PW_CRYPT_PASSWORD);
	if (!vp) {
		return 0;
	}
	printf("SAML: url: %s\n", vp->vp_strvalue);

	sscanf(vp->vp_strvalue + strlen("OPENURL="), data->config.saml_client_url, result);
	
	char *end = strchr(result, '&');
	if (end > 0)
		*end = 0;
	printf("SAML: id: %s\n", result);

	mg_url_decode(result, strlen(result), decoded, 300, 1);
	printf("SAML: mg_url_decode: %s\n", decoded);
	

	sscanf(decoded, "https://bachelor.lan:9875/samlRequest?id=%s", id);

	elem = saml_web_get_elem(data, id);
	if (!elem) {
		printf("can not find elem for id: %s\n", id);
		return 0;
	}
	
	timeout.tv_sec = time(0) + 120;

	ret = pthread_mutex_timedlock(&elem->response_available, &timeout);
	if (ret) {
		printf("No saml response in current time\n");
		return 0;
	}

	if (data->config.username_restictedID) {
		name = saml_get_char_xpath(elem->response->assertion, "//saml:Assertion/saml:AttributeStatement/saml:Attribute", "RestrictedId");	
	} else if (data->config.username_name) {
		char *given_name;
		char *family_name;
		char *placeOfResidence;
		char *name_with_spaces;

		given_name = saml_get_char_xpath(elem->response->assertion, "//saml:Assertion/saml:AttributeStatement/saml:Attribute", "GivenNames");
		if (!given_name)
			return 0;
		family_name = saml_get_char_xpath(elem->response->assertion, "//saml:Assertion/saml:AttributeStatement/saml:Attribute", "FamilyNames");
		if (!family_name) {
			free(given_name);
			return 0;
		}
		placeOfResidence = saml_get_char_xpath(elem->response->assertion, "//saml:Assertion/saml:AttributeStatement/saml:Attribute", "PlaceOfResidence");
		if (!placeOfResidence) {
			free(given_name);
			free(family_name);
			return 0;
		}
		size = strlen(given_name) + strlen(family_name) + strlen(placeOfResidence) + 1;
		name_with_spaces = rad_malloc(size);
		if (!name_with_spaces) {
			free(given_name);
			free(family_name);
			free(placeOfResidence);
			return 0;
		}
		if (snprintf(name_with_spaces, size, "%s%s%s", given_name, family_name, placeOfResidence) < 0) {
			free(name_with_spaces);
			free(given_name);
			free(family_name);
			free(placeOfResidence);
			return 0;
		}
		free(given_name);
		free(family_name);
		free(placeOfResidence);

		name = rad_malloc(size);
		if (!name) {
			free(name_with_spaces);
			return 0;
		}
		remove_spaces(name_with_spaces, name);
		free(name_with_spaces);
	}

	if (name) {
		vp = pairmake("User-Name", name, T_OP_EQ);
		if (!vp) {
			free(name);
			return 0;
		}
		pairadd(&request->reply->vps, vp);
		free(name);
	}

	add_fragmented(elem->response->assertion_char, strlen(elem->response->assertion_char), &request->reply->vps, "SAML-AAA-Assertion");
	saml_web_remove_elem(elem);

	vp_printlist(stdout, request->reply->vps);

	return RLM_MODULE_OK;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_saml = {
	RLM_MODULE_INIT,
	"SAML",
	RLM_TYPE_THREAD_SAFE,		/* type */
	saml_instantiate,		/* instantiation */
	saml_detach,			/* detach */
	{
		saml_authenticate,		/* authentication */
		saml_authorize,			/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
