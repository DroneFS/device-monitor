#include <string.h>
#include <malloc.h>
#include <gps.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>

#define N_PARAMS 4

typedef unsigned char *PUCHAR;

float damepos(char* val) {
    int rc;
    //struct timeval tv;

    struct gps_data_t gps_data;
    if ((rc = gps_open("localhost", "2947", &gps_data)) == -1) {
        //printf("code: %d, reason: %s\n", rc, gps_errstr(rc));
        return EXIT_FAILURE;
    }
    gps_stream(&gps_data, WATCH_ENABLE | WATCH_JSON, NULL);

    while (1) {
        /* wait for 2 seconds to receive data */
        if (gps_waiting (&gps_data, 2000000)) {
            /* read data */
            if ((rc = gps_read(&gps_data)) == -1) {
                //printf("error occured reading gps data. code: %d, reason: %s\n", rc, gps_errstr(rc));
            } else {
                /* Display data from the GPS receiver. */
                if ((gps_data.status == STATUS_FIX) && 
                    (gps_data.fix.mode == MODE_2D || gps_data.fix.mode == MODE_3D) &&
                    !isnan(gps_data.fix.latitude) && 
                    !isnan(gps_data.fix.longitude)) {
                        //gettimeofday(&tv, NULL); EDIT: tv.tv_sec isn't actually the timestamp!
                        //printf("latitude: %f, longitude: %f, speed: %f, timestamp: %lf\n", gps_data.fix.latitude, gps_data.fix.longitude, gps_data.fix.speed, gps_data.fix.time); //EDIT: Replaced tv.tv_sec with gps_data.fix.time
                } else {
                    //printf("no GPS data available\n");
                }
            }
        }

        sleep(3);
    }

    /* When you are done... */
    gps_stream(&gps_data, WATCH_DISABLE, NULL);
    gps_close (&gps_data);

    //return EXIT_SUCCESS;
    if (strcmp(val,"lat")==0){return gps_data.fix.latitude;}
    else {return gps_data.fix.longitude;}
}

int getNParams()
{
	return N_PARAMS;
}

PUCHAR *getParamNames()
{
	unsigned char **names = malloc(sizeof(unsigned char *) * N_PARAMS);
	if (names) {
		names[0] = (unsigned char *) strdup("param-1");
		names[1] = (unsigned char *) strdup("param-2");
		names[2] = (unsigned char *) strdup("param-3");
		names[3] = (unsigned char *) strdup("param-4");
	}
	return names;
}

float getlat(){
	return 40.455;
}

float getlong(){
	return 3.616;
}

PUCHAR *executeParam()
{

	FILE* fp;
    char  line[255];

    double lat;
    double lon;
    double lat_min = 90;
    double lat_max = -90;
    double lon_min = 180;
    double lon_max = -180;

    double lat_min0 = 0;
    double lat_max0 = 0;
    double lon_min0 = 0;
    double lon_max0 = 0;

    int offsetyi;
	int offsetxi;

    int numtesela;

	unsigned char *key, **params;
	const size_t keylen = 16;

	//get ruta y guarda esquinas
	fp = fopen("gpsrutas" , "r");
    while (fgets(line, sizeof(line), fp) != NULL)
    {
        const char* val1 = strtok(line, ";");
        const char* val2 = strtok(NULL, ";");

        //printf("%s y %s\n", val1, val2);
        lat = atof(val1);
        lon = atof(val2);
        //tengo q apuntar las esquinas en este bucle
        if (lat<lat_min) {lat_min= lat;}
        if (lat>lat_max) {lat_max= lat;}
        if (lon<lon_min) {lon_min= lon;}
        if (lon>lon_max) {lon_max= lon;}
        
    }

	//calcula tesela 0
	double ancho = lat_max - lat_min;
    double alto =  lon_max-lon_min;
    //calculo offset respecto a 0 y lo meto en params0
	double offsetx = lat_max/ancho;
	double offsety = lon_max/alto;
	//Me quedo con la parte decimal y tengo los puntos donde empieza	
	offsetxi = (int)offsetx;
	offsetyi = (int)offsety;

	offsetx = offsetx-offsetxi;
	offsety = offsety-offsetyi;
	//Les sumo alto y ancho y obtengo los params0
	lat_max0 = offsetx + ancho;
	lat_min0 = offsetx;
	lon_max0 =	offsety + alto;
	lon_min0 =	offsety;

    int i = 0;
    int j =0;
    while (lat_max>lat_max0) {lat_max= lat_max-ancho; i++;}
    while (lon_max>lon_max0) {lon_max= lon_max-alto; j++;}
    numtesela = i+j;

	key = malloc(keylen);
	if (!key)
		return NULL;

	params = malloc(sizeof(unsigned char *) * 5);
	if (!params) {
		free(key);
		return NULL;
	}

	//params[1] = (unsigned char *) strdup("aja");
	//params[2] = (unsigned char *) strdup("AJA");
	char value[4];
	sprintf(value,"%.10f",lat_max0);
	params[1] = (unsigned char *) strdup(value);
	sprintf(value,"%.10f",lat_min0);
	params[2] = (unsigned char *) strdup(value);
	sprintf(value,"%.10f",lon_max0);
	params[3] = (unsigned char *) strdup(value);
	sprintf(value,"%.10f",lon_min0);
	params[4] = (unsigned char *) strdup(value);

	memset(key, numtesela, keylen);
	params[0] = key;
	//TODO
	/*memcpy(key, params[1], 4);
	memcpy(key + keylen - 12, params[2], 4);
	memcpy(key + keylen - 8, params[3], 4);
	memcpy(key + keylen - 4, params[4], 4);*/

	return params;
}

PUCHAR execute(PUCHAR *paramsXml)
{
	//double lat;
    //double lon;
    double lat_min = 90;
    double lat_max = -90;
    double lon_min = 180;
    double lon_max = -180;

	unsigned char *key;
	const size_t keylen = 16;
    
    //char params[4];
    int i = 0;
    int j = 0;
    int numtesela;

	if (!paramsXml)
		return NULL;

	key = malloc(keylen);
	if (!key)
		return NULL;

	//memset(key, 0, keylen);

	/* Walk over the params */
	for (unsigned i = 0; i < N_PARAMS; i++) {
		if (!paramsXml[i]) {
			free(key);
			key = NULL;
			break;
		}

		/*if (i == 0)
			memcpy(key, paramsXml[i], 3);
		else if (i == 1)
			memcpy(key + keylen - 3, paramsXml[i], 3);*/
		//paramsxml son los parametros de codigo 0 y 1 en este caso
		//TODO: Calcular tesela con los dos parametros y meterla en la clave
        char* valor;
		if (i == 0){
			//memcpy(key, paramsXml[i], 3);
            //params[1] = (unsigned char *) strdup(value);
            valor = strdup(paramsXml[i]);
			lat_max = atof(valor);}
		else if (i == 1){
			//memcpy(key + keylen - 3, paramsXml[i], 3);
            valor = strdup(paramsXml[i]);
			lat_min = atof(valor);}
		else if (i == 2){
			//memcpy(key + keylen - 3, paramsXml[i], 3);
            valor = strdup(paramsXml[i]);
			lon_max = atof(valor);}
		else if (i == 3){
			//memcpy(key + keylen - 3, paramsXml[i], 3);
            valor = strdup(paramsXml[i]);
			lon_min = atof(valor);}
	/*calculate tesela*/
	}
    
	double ancho = lat_max - lat_min;
    double alto =  lon_max-lon_min;
    //punto actual: 40.4550000000 ; 3,6160000000
    double latpunto = 40.4550000000 ;//damepos("lat");
    double lonpunto =  3.6160000000;//damepos("lon");
    //distancia de tesela 0
    i = 0;
    j = 0;
    while (latpunto > lat_max) {
        lat_max = lat_max+ancho; 
        i++;
    }
    while (lonpunto > lon_max) {
        lon_max = lon_max+alto; 
        j++;
       }
    /*lat_min = lat_max - ancho;
    lon_min = lon_max - alto;
    offsetyi = (int)lat_min0/ancho;
	offsetxi = (int)lon_min0/alto;*/
    numtesela = i+j;

    memset(key, numtesela, keylen);

	return key;
}

