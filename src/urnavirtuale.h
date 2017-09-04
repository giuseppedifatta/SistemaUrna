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

#include "cryptopp/osrng.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/hmac.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"
#include "cryptopp/secblock.h"

using namespace CryptoPP;

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
	int verifyMAC(string encodedSessionKey,string plain, string macEncoded);
private:
	ProceduraVoto proceduraCorrente;
	DataManager *model;

};

#endif /* URNAVIRTUALE_H_ */
