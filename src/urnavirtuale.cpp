/*
 * urnavirtuale.cpp
 *
 *  Created on: 03/ago/2017
 *      Author: giuseppe
 */

#include "urnavirtuale.h"

UrnaVirtuale::UrnaVirtuale() {
	// TODO Auto-generated constructor stub

}

UrnaVirtuale::~UrnaVirtuale() {
	// TODO Auto-generated destructor stub
}

uint UrnaVirtuale::getIdProceduraCorrente(){
	//contattare il db e ottenere l'id della procedura corrente


	return idProcedura;
}

uint UrnaVirtuale::getNumeroSchede(uint idProcedura){
	//contattare il db per ottenere il numero di schede abbinate alla procedura

	uint numSchede = 2;
	return numSchede;
}
