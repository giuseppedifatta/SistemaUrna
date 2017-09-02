/*
 * urnavirtuale.h
 *
 *  Created on: 03/ago/2017
 *      Author: giuseppe
 */

#ifndef URNAVIRTUALE_H_
#define URNAVIRTUALE_H_
#include <string>
#include <cstdlib>
#include "tinyxml2.h"
#include "proceduravoto.h"
#include "dataManager.h"

class UrnaVirtuale {
public:
	UrnaVirtuale();
	virtual ~UrnaVirtuale();
	uint getIdProceduraCorrente();
	uint getNumeroSchede(uint idProcedura);
	bool getScrutinioEseguito();
	bool decifravoti_RP();
	bool checkFirmaPV_U();
	void firmaVC_U();
	vector <string> getSchede();
	string getPublicKeyRP(uint idProceduraCorrente);

private:
	ProceduraVoto proceduraCorrente;
	DataManager *model;

};

#endif /* URNAVIRTUALE_H_ */
