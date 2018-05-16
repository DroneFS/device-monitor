/*
 * formatter-xml.h
 *
 *  Created on: Apr 23, 2018
 *      Author: Ander Juaristi
 */

#ifndef FORMATTER_XML_H_
#define FORMATTER_XML_H_

#include "formatter.h"

file_formatter_t *create_xml_formatter();
void destroy_xml_formatter(file_formatter_t *);

file_reader_t *create_xml_reader();
void destroy_xml_reader(file_reader_t *);

#endif /* FORMATTER_XML_H_ */
