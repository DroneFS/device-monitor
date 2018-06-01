/*
 * formatter-xml.c
 *
 *  Created on: Apr 23, 2018
 *      Author: Ander Juaristi
 */
#include "mm.h"
#include "base64.h"
#include "formatter.h"
#include <errno.h>
#include <stdbool.h>
#include <libxml/tree.h>
#include <libxml/xmlsave.h>
#include <libxml/xmlstring.h>

struct fmt_private
{
	xmlDocPtr doc;
	xmlNodePtr header_root;
	bool free_header_root;
	xmlNodePtr body_root;
	bool free_body_root;
	xmlNodePtr ciphertext;
	bool free_ciphertext;
};

static void destroy_fmt_private(struct fmt_private **ppriv)
{
	struct fmt_private *priv;

	if (!ppriv || !*ppriv)
		return;

	priv = *ppriv;

	if (priv->free_header_root && priv->header_root) {
		xmlFreeNode(priv->header_root);
		priv->free_header_root = false;
		priv->header_root = NULL;
	}
	if (priv->free_body_root && priv->body_root) {
		xmlFreeNode(priv->body_root);
		priv->free_body_root = false;
		priv->body_root = NULL;
	}
	if (priv->free_ciphertext && priv->ciphertext) {
		xmlFreeNode(priv->ciphertext);
		priv->free_ciphertext = false;
		priv->ciphertext = NULL;
	}
	if (priv->doc) {
		xmlFreeDoc(priv->doc);
		priv->doc = NULL;
	}

	xmlCleanupParser();
	mm_free(*ppriv);
}

static int start_document(file_formatter_t *fmt)
{
	struct fmt_private *priv = mm_new0(struct fmt_private);

	priv->doc = xmlNewDoc(BAD_CAST "1.0");
	if (!priv->doc)
		return E_UNKNOWN;

	priv->free_header_root = false;
	priv->free_body_root = false;
	priv->free_ciphertext = false;

	fmt->priv = priv;
	return S_OK;
}

static int end_document(file_formatter_t *fmt, int fd)
{
	int written = E_SYSCALL;
	struct fmt_private *priv;
	xmlNodePtr root_node;
	xmlSaveCtxtPtr ctxt;

	if (!fmt || !fmt->priv || fd < 0)
		return E_BADARGS;

	priv = fmt->priv;

	/* Build up our XML document */
	root_node = xmlNewNode(NULL, BAD_CAST "DroneFS");
	if (!root_node)
		goto end;

	xmlDocSetRootElement(priv->doc, root_node);

	/* Add the header element */
	if (!xmlAddChild(root_node, priv->header_root))
		goto end;
	priv->free_header_root = false;

	/* Add the body element */
	if (!xmlAddChild(root_node, priv->body_root))
		goto end;
	priv->free_body_root = false;

	/* Add the ciphertext element */
	if (!xmlAddChild(root_node, priv->ciphertext))
		goto end;
	priv->free_ciphertext = false;

	/* Write XML document to file */
	ctxt = xmlSaveToFd(fd, NULL, XML_SAVE_FORMAT);
	if (!ctxt)
		goto end;

	xmlSaveDoc(ctxt, priv->doc);
	written = xmlSaveClose(ctxt);

end:
	destroy_fmt_private((struct fmt_private **) &fmt->priv);
	return written;
}

static void start_header(file_formatter_t *fmt)
{
	struct fmt_private *priv = fmt->priv;
	if (!priv->header_root) {
		priv->header_root = xmlNewNode(NULL, BAD_CAST "Header");
		priv->free_header_root = true;
	}
}

static void start_body(file_formatter_t *fmt)
{
	struct fmt_private *priv = fmt->priv;
	if (!priv->body_root) {
		priv->body_root = xmlNewNode(NULL, BAD_CAST "Challenges");
		priv->free_body_root = true;
	}
}

static void set_file_name(file_formatter_t *fmt, const char *filename)
{
	struct fmt_private *priv;

	if (fmt && fmt->priv) {
		priv = fmt->priv;
		start_header(fmt);
		xmlNewChild(priv->header_root, NULL, BAD_CAST "fileName", BAD_CAST filename);
	}
}

static void set_version(file_formatter_t *fmt, int version)
{
	struct fmt_private *priv;
	int len = sizeof(int) * 4 + 1;
	char str_version[len];

	if (fmt && fmt->priv) {
		priv = fmt->priv;
		start_header(fmt);
		snprintf(str_version, len, "%d", version);
		xmlNewChild(priv->header_root, NULL, BAD_CAST "version", BAD_CAST str_version);
	}
}

static int set_init_vector(file_formatter_t *fmt,
		const unsigned char *iv, size_t iv_length)
{
	xmlNodePtr child;
	struct fmt_private *priv;
	size_t b64_len = base64_encoded_length(iv_length);
	char b64_iv[b64_len];
	size_t iv_str_len = sizeof(size_t) * 4 + 1;
	xmlChar iv_length_str[iv_str_len];

	if (!fmt || !fmt->priv)
		return E_BADARGS;

	priv = fmt->priv;

	/* Write the base64-encoded IV */
	if (iv_length > UINT_MAX)
		return E_TOOLARGE;
	if (base64_encode(iv, iv_length, b64_iv) != BASE64_OK)
		return E_UNKNOWN;

	start_header(fmt);
	b64_iv[b64_len - 1] = '\0';

	xmlStrPrintf(iv_length_str, iv_str_len, "%zu", iv_length);

	child = xmlNewChild(priv->header_root, NULL, BAD_CAST "vector", BAD_CAST b64_iv);
	if (!child)
		return E_UNKNOWN;
	if (!xmlNewProp(child, BAD_CAST "size", iv_length_str))
		return E_UNKNOWN;

	return S_OK;
}

static void set_plaintext_length(file_formatter_t *fmt, size_t length)
{
	struct fmt_private *priv;
	int len = sizeof(size_t) * 4 + 1;
	char str_length[len];

	if (fmt && fmt->priv) {
		priv = fmt->priv;
		start_header(fmt);
		snprintf(str_length, len, "%zd", length);
		xmlNewChild(priv->header_root, NULL, BAD_CAST "size", BAD_CAST str_length);
	}
}

static void *challenge_start(file_formatter_t *fmt, const char *chall_name)
{
	xmlNodePtr node = NULL;

	if (!fmt || !fmt->priv || !chall_name || !*chall_name)
		goto end;

	start_body(fmt);

	node = xmlNewNode(NULL, BAD_CAST "Challenge");
	if (!node)
		goto end;

	if (!xmlSetProp(node, BAD_CAST "name", BAD_CAST chall_name)) {
		xmlUnlinkNode(node);
		xmlFreeNode(node);
		goto end;
	}

end:
	return node;
}

static void challenge_end(file_formatter_t *fmt, void *h)
{
	xmlNodePtr node;

	if (fmt && fmt->priv && h) {
		node = (xmlNodePtr) h;
		xmlAddChild(((struct fmt_private *) fmt->priv)->body_root, node);
	}
}

static int set_param(void *h,
		const char *param_name, const char *param_value)
{
	int retval = E_UNKNOWN;
	xmlNodePtr node, child;

	if (!h || !param_name || !*param_name)
		return E_BADARGS;

	if (!param_value)
		param_value = "";

	node = (xmlNodePtr) h;

	child = xmlNewChild(node, NULL, BAD_CAST "param", BAD_CAST param_value);
	if (!child)
		goto end;

	if (!xmlSetProp(child, BAD_CAST "name", BAD_CAST param_name)) {
		xmlUnlinkNode(child);
		xmlFreeNode(child);
		goto end;
	}

	retval = S_OK;

end:
	return retval;
}

static int set_ciphertext(file_formatter_t *fmt,
		const unsigned char *ciphertext, size_t ciphertext_length)
{
	xmlNodePtr txt = NULL;
	struct fmt_private *priv;
	size_t b64_len = base64_encoded_length(ciphertext_length);
	char b64_ciphertext[b64_len];
	size_t ct_str_len = sizeof(size_t) * 4 + 1;
	xmlChar ciphertext_length_str[ct_str_len];

	if (!fmt || !fmt->priv || !ciphertext || !ciphertext_length)
		return E_BADARGS;

	priv = fmt->priv;

	priv->ciphertext = xmlNewNode(NULL, BAD_CAST "Ciphertext");
	if (!priv->ciphertext)
		return E_UNKNOWN;
	priv->free_ciphertext = true;

	if (ciphertext_length > UINT_MAX)
		return E_TOOLARGE;
	if (base64_encode(ciphertext, ciphertext_length, b64_ciphertext) != BASE64_OK)
		return E_UNKNOWN;

	b64_ciphertext[b64_len - 1] = '\0';
	txt = xmlNewText(BAD_CAST b64_ciphertext);
	if (!txt)
		goto error;

	xmlStrPrintf(ciphertext_length_str, ct_str_len, "%zu", ciphertext_length);

	if (!xmlAddChild(priv->ciphertext, txt))
		goto error;
	if (!xmlNewProp(priv->ciphertext, BAD_CAST "size", ciphertext_length_str))
		goto error;

	return S_OK;

error:
	xmlFreeNode(txt);
	return E_UNKNOWN;
}

static int start_document_read(file_reader_t *r, const uint8_t *in, size_t inlen)
{
	xmlDocPtr doc;

	if (!r || !in)
		return E_BADARGS;
	if (inlen > INT_MAX)
		return E_TOOLARGE;

	doc = xmlReadMemory((const char *) in, inlen,
			r->file_path,
			NULL,
			0);
	if (!doc)
		return E_UNKNOWN;

	r->priv = doc;
	return S_OK;
}

static int end_document_read(file_reader_t *r)
{
	if (!r || !r->priv)
		return E_BADARGS;

	xmlFreeDoc((xmlDocPtr) r->priv);
	r->priv = NULL;
	return S_OK;
}

static size_t get_plaintext_length(file_reader_t *r)
{
	bool found = false;
	xmlDocPtr doc;
	xmlNodePtr root_node;
	size_t size;
	xmlChar *size_str;

	if (!r || !r->priv)
		return E_BADARGS;

	doc = r->priv;

	/* Get to the <Header> tag */
	root_node = xmlDocGetRootElement(doc);
	if (!root_node)
		return E_NOTFOUND;

	for (xmlNodePtr cur_node = root_node->children;
			cur_node;
			cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE &&
				xmlStrcasecmp(cur_node->name, BAD_CAST "Header") == 0) {
			root_node = cur_node;
			break;
		}
	}

	for (xmlNodePtr cur_node = root_node->children;
			cur_node && !found;
			cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE &&
				xmlStrcasecmp(cur_node->name, BAD_CAST "size") == 0) {
			size_str = xmlNodeGetContent(cur_node);
			if (!size_str)
				goto end;

			size = strtol((const char *) size_str, NULL, 10);
			if (errno == ERANGE) {
				xmlFree(size_str);
				goto end;
			}

			xmlFree(size_str);
			found = true;
		}
	}

end:
	return found ? size : 0;
}

static int get_init_vector(file_reader_t *r, uint8_t **iv_out, size_t *ivlen_out)
{
	bool found = false;
	xmlDocPtr doc;
	xmlNodePtr root_node;
	xmlChar *b64_iv, *ivlen_str;
	size_t ivlen;

	if (!r || !r->priv || !iv_out || !ivlen_out)
		return E_BADARGS;

	doc = r->priv;

	/* Get to the <Header> tag */
	root_node = xmlDocGetRootElement(doc);
	if (!root_node)
		return E_NOTFOUND;

	for (xmlNodePtr cur_node = root_node->children;
			cur_node;
			cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE &&
				xmlStrcasecmp(cur_node->name, BAD_CAST "Header") == 0) {
			root_node = cur_node;
			break;
		}
	}

	for (xmlNodePtr cur_node = root_node->children; cur_node && !found;
			cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE &&
				xmlStrcasecmp(cur_node->name, BAD_CAST "vector") == 0) {
			b64_iv = xmlNodeGetContent(cur_node);
			if (!b64_iv)
				return E_NOTFOUND;

			/* Length of the original (decoded) IV */
			ivlen_str = xmlGetProp(cur_node, BAD_CAST "size");
			if (!ivlen_str)
				goto error;

			ivlen = strtol((const char *) ivlen_str, NULL, 10);
			if (errno == ERANGE)
				goto error;

			*ivlen_out = ivlen;
			*iv_out = mm_malloc0(ivlen);

			/* Decode Base64, and obtain the IV back */
			if (base64_decode((const char *) b64_iv, xmlStrlen(b64_iv), *iv_out) != BASE64_OK)
				goto error;

			xmlFree(ivlen_str);
			xmlFree(b64_iv);
			found = true;
		}
	}

	return found ? S_OK : E_NOTFOUND;

error:
	mm_free(*iv_out);
	*ivlen_out = 0;
	xmlFree(b64_iv);
	xmlFree(ivlen_str);
	return E_UNKNOWN;
}

static int get_ciphertext(file_reader_t *r, uint8_t **ct_out, size_t *ctlen_out)
{
	bool found = false;
	xmlDocPtr doc;
	xmlNodePtr root_node;
	xmlChar *b64_ct, *ctlen_str;
	size_t ctlen;

	if (!r || !r->priv || !ct_out || !ctlen_out)
		return E_BADARGS;

	doc = r->priv;

	/* Get to the <Ciphertext> tag */
	root_node = xmlDocGetRootElement(doc);
	if (!root_node)
		return E_NOTFOUND;

	for (xmlNodePtr cur_node = root_node->children;
			cur_node && !found;
			cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE &&
				xmlStrcasecmp(cur_node->name, BAD_CAST "Ciphertext") == 0) {
			b64_ct = xmlNodeGetContent(cur_node);
			if (!b64_ct)
				return E_NOTFOUND;

			/* Length of the original (decoded) ciphertext */
			ctlen_str = xmlGetProp(cur_node, BAD_CAST "size");
			if (!ctlen_str)
				goto error;

			ctlen = strtol((const char *) ctlen_str, NULL, 10);
			if (errno == ERANGE)
				goto error;

			*ctlen_out = ctlen;
			*ct_out = mm_malloc0(ctlen);

			/* Decode Base64, and obtain the ciphertext back */
			if (base64_decode((const char *) b64_ct, xmlStrlen(b64_ct), *ct_out) != BASE64_OK)
				goto error;

			xmlFree(ctlen_str);
			xmlFree(b64_ct);
			found = true;
		}
	}

	return found ? S_OK : E_NOTFOUND;

error:
	mm_free(*ct_out);
	*ctlen_out = 0;
	if (ctlen_str)
		xmlFree(ctlen_str);
	xmlFree(b64_ct);
	return E_UNKNOWN;
}

static void *challenge_start_read(file_reader_t *r, const char *name)
{
	xmlDocPtr doc;
	xmlNodePtr root_node, /* this points to tag <Challenges> */
		node = NULL;
	xmlChar *attr;

	if (!r || !r->priv || !name)
		return NULL;

	doc = (xmlDocPtr) r->priv;

	/* Get the <Challenges> tag */
	root_node = xmlDocGetRootElement(doc);
	if (!root_node)
		goto end;

	for (xmlNodePtr cur_node = root_node->children;
			cur_node;
			cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE &&
				xmlStrcasecmp(cur_node->name, BAD_CAST "Challenges") == 0) {
			root_node = cur_node;
			break;
		}
	}

	/* Now find the <Challenge> tag with the requested name */
	for (xmlNodePtr cur_node = root_node->children; cur_node && !node;
			cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE &&
				xmlStrcasecmp(cur_node->name, BAD_CAST "Challenge") == 0) {

			attr = xmlGetProp(cur_node, BAD_CAST "name");

			if (attr) {
				if (xmlStrcmp(attr, BAD_CAST name) == 0)
					node = cur_node;
				xmlFree(attr);
			}
		}
	}

end:
	return node;
}

static int get_num_params(void *ch)
{
	int num_params = 0;
	xmlNodePtr node = ch;

	if (!node)
		return E_BADARGS;

	for (xmlNodePtr cur_node = node->children; cur_node;
			cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE &&
				xmlStrcasecmp(cur_node->name, BAD_CAST "param") == 0)
			num_params++;
	}

	return num_params;
}

static int get_param(void *ch,
		unsigned int index,
		unsigned char **name_out, unsigned char **value_out)
{
	bool found = false;
	xmlNodePtr node = ch;
	xmlChar *name, *content;
	unsigned int cur_index = 0;

	if (!node || !name_out || !value_out)
		return E_BADARGS;

	for (xmlNodePtr cur_node = node->children; cur_node && !found;
			cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE &&
				xmlStrcasecmp(cur_node->name, BAD_CAST "param") == 0 &&
				cur_index++ == index) {
			name = xmlGetProp(cur_node, BAD_CAST "name");
			if (name) {
				*name_out = xmlStrdup(name);
				xmlFree(name);
			} else {
				*name_out = NULL;
			}

			content = xmlNodeGetContent(cur_node);
			if (content) {
				*value_out = xmlStrdup(content);
				xmlFree(content);
			} else {
				*value_out = NULL;
			}

			found = true;
		}
	}

	return found ? S_OK : E_NOTEXISTS;
}

static void challenge_end_read(file_reader_t *r, void *ch)
{
	/* We don't need to do anything here */
	return;
}

file_formatter_t *create_xml_formatter()
{
	file_formatter_t *fmt = mm_new0(file_formatter_t);

	fmt->start_document = start_document;
	fmt->end_document = end_document;

	fmt->set_file_name = set_file_name;
	fmt->set_init_vector = set_init_vector;
	fmt->set_version = set_version;
	fmt->set_plaintext_length = set_plaintext_length;

	fmt->challenge_start = challenge_start;
	fmt->challenge_end = challenge_end;
	fmt->set_param = set_param;

	fmt->set_ciphertext = set_ciphertext;

	return fmt;
}

void destroy_xml_formatter(file_formatter_t *fmt)
{
	if (fmt) {
		if (fmt->priv)
			destroy_fmt_private((struct fmt_private **) &fmt->priv);
		mm_free(fmt);
	}
}

file_reader_t *create_xml_reader()
{
	file_reader_t *r = mm_new0(file_reader_t);

	r->start_document = start_document_read;
	r->end_document = end_document_read;

	r->get_ciphertext = get_ciphertext;
	r->get_init_vector = get_init_vector;

	r->get_plaintext_length = get_plaintext_length;

	r->challenge_start = challenge_start_read;
	r->challenge_end = challenge_end_read;

	r->get_num_params = get_num_params;
	r->get_param = get_param;

	return r;
}

void destroy_xml_reader(file_reader_t *r)
{
	if (r) {
		if (r->priv) {
			xmlFreeDoc((xmlDocPtr) r->priv);
			r->priv = NULL;
		}
		mm_free(r);
	}
}
