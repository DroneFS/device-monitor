/*
 * config-xml.c
 *
 *  Created on: 5 Dec 2017
 *      Author: Ander Juaristi
 */
#include <string.h>
#include "mm.h"
#ifndef ANDROID
#include "config.h"
#endif
#include "configuration.h"

#ifndef HAVE_LIBXML
int config_init_xml(config_t *c, const char *filename)
{
	return CONFIG_E_UNSUPPORTED_TYPE;
}
#else
#include <libxml/xpath.h>
#include <libxml/tree.h>

static void deinit(config_t **);
static size_t get_challenges_list(config_t *, list_head_t *);
static char *get_crypto_algorithm(config_t *);

int config_init_xml(config_t *c, const char *filename)
{
	xmlDocPtr doc;

	if (!filename || !*filename)
		return CONFIG_E_BADARGS;

	xmlInitParser();

	doc = xmlParseFile(filename);
	if (!doc)
		return CONFIG_E_NO_SUCH_VALUE;

	c->deinit = deinit;
	c->get_challenges_list = get_challenges_list;
	c->get_crypto_algorithm = get_crypto_algorithm;
	c->priv = doc;
	return CONFIG_OK;
}

static void deinit(config_t **c)
{
	if (c && *c && (*c)->priv) {
		xmlFreeDoc((xmlDocPtr)(*c)->priv);
		xmlCleanupParser();
	}
}

static void fill_challenge_list(xmlNodeSetPtr nodeset, list_head_t *h)
{
	xmlNode *cur_node;
	xmlChar *chall_name = NULL;
	unsigned num_nodes = nodeset->nodeNr;
	char *chall_name_full;

	for (unsigned i = 0; i < num_nodes; i++) {
		cur_node = nodeset->nodeTab[i];

		chall_name = xmlGetProp(cur_node, BAD_CAST "name");
		if (chall_name) {
			chall_name_full = mm_malloc0(strlen((const char *) chall_name) + 4);
			strcpy(chall_name_full, (const char *) chall_name);
			strcat(chall_name_full, ".so");
			list_push_back_noalloc(h, chall_name_full);
		}
	}
}

static size_t get_challenges_list(config_t *c, list_head_t *h)
{
	xmlDocPtr doc;
	xmlXPathContextPtr xpath_ctx = NULL;
	xmlXPathObjectPtr xpath_obj = NULL;

	doc = c->priv;
	if (!doc)
		goto end;

	xpath_ctx = xmlXPathNewContext(doc);
	if (!xpath_ctx)
		goto end;

	xpath_obj = xmlXPathEvalExpression(BAD_CAST "/DroneFSConfig/Challenges/Challenge",
			xpath_ctx);
	if (!xpath_obj)
		goto end;

	if (xpath_obj->nodesetval)
		fill_challenge_list(xpath_obj->nodesetval, h);

end:
	xmlXPathFreeObject(xpath_obj);
	xmlXPathFreeContext(xpath_ctx);

	return list_count(h);
}

static char *read_algo(xmlNodePtr child)
{
	return (child && child->type == XML_TEXT_NODE && child->content) ?
			strdup((const char *) child->content) :
			NULL;
}

static char *get_crypto_algorithm(config_t *c)
{
	char *algo = NULL;
	xmlDocPtr doc = NULL;
	xmlXPathContextPtr xpath_ctx = NULL;
	xmlXPathObjectPtr xpath_obj = NULL;

	doc = c->priv;
	if (!doc)
		goto end;

	xpath_ctx = xmlXPathNewContext(doc);
	if (!xpath_ctx)
		goto end;

	xpath_obj = xmlXPathEvalExpression(BAD_CAST "/DroneFSConfig/CipherData",
			xpath_ctx);
	if (!xpath_obj)
		goto end;

	if (xpath_obj->nodesetval &&
			xpath_obj->nodesetval->nodeTab[0] &&
			xpath_obj->nodesetval->nodeTab[0]->type == XML_ELEMENT_NODE &&
			xpath_obj->nodesetval->nodeTab[0]->children)
		algo = read_algo(&xpath_obj->nodesetval->nodeTab[0]->children[0]);

end:
	xmlXPathFreeObject(xpath_obj);
	xmlXPathFreeContext(xpath_ctx);

	return algo;
}
#endif /* HAVE_LIBXML */
