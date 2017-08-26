/*
 * main.cpp
 *
 *  Created on: 02/ago/2017
 *      Author: giuseppe
 */
#include "sslserver.h"
#include "urnavirtuale.h"

int main(){
	UrnaVirtuale *uv = new UrnaVirtuale();
	SSLServer *serverUrna = new SSLServer(uv);
	while(1){
	serverUrna->startListen();
	}


	return 0;
}


