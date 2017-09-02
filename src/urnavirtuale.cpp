/*
 * urnavirtuale.cpp
 *
 *  Created on: 03/ago/2017
 *      Author: giuseppe
 */

#include "urnavirtuale.h"

UrnaVirtuale::UrnaVirtuale() {
	// TODO Auto-generated constructor stub
	model = new DataManager();
}

UrnaVirtuale::~UrnaVirtuale() {
	// TODO Auto-generated destructor stub
}

uint UrnaVirtuale::getIdProceduraCorrente(){
	//contattare il db e ottenere l'id della procedura corrente
	proceduraCorrente = model->getProceduraCorrente();

	return proceduraCorrente.getIdProceduraVoto();
}

uint UrnaVirtuale::getNumeroSchede(uint idProceduraCorrente){
	//contattare il db per ottenere il numero di schede abbinate alla procedura

	uint numSchede = proceduraCorrente.getNumSchedeVoto();
	return numSchede;
}

vector<string> UrnaVirtuale::getSchede() {
	uint idProcedura = proceduraCorrente.getIdProceduraVoto();
	cout << "richiedo al model le schede per la procedura: " << idProcedura << endl;
	return model->getSchedeVoto(idProcedura);
}

string UrnaVirtuale::getPublicKeyRP(uint idProceduraCorrente){
	return model->getPublicKeyRP(idProceduraCorrente);
}
