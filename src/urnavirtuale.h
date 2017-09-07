/*
 * urnavirtuale.h
 *
 *  Created on: 03/ago/2017
 *      Author: giuseppe
 */

#ifndef URNAVIRTUALE_H_
#define URNAVIRTUALE_H_
#include <string>
#include <stdexcept>
#include <iostream>
#include <fstream>
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
#include "cryptopp/rsa.h"
#include "cryptopp/base64.h"
#include "cryptopp/files.h"
#include "cryptopp/pssr.h"

using namespace CryptoPP;

class UrnaVirtuale {
public:
	UrnaVirtuale();
	virtual ~UrnaVirtuale();
	uint getIdProceduraCorrente();
	uint getNumeroSchede(uint idProcedura);
	bool checkScrutinioEseguito(uint idProcedura);
	bool decifravoti_RP(uint idProcedura, CryptoPP::RSA::PrivateKey chiavePrivataRP);

	vector <string> getSchede();
	string getPublicKeyRP(uint idProceduraCorrente);
	int verifyMAC(string encodedSessionKey,string plain, string macEncoded);
	string calcolaMAC(string encodedSessionKey, string plainText);
	bool checkMACasUniqueID(string macPacchettoVoto);
	bool storePacchettoVoto(string idSchedaCompilata, string schedaCifrata, string kc, string ivc, uint nonce);
	uint getIdSessioneCorrenteSuccessiva();

	const ProceduraVoto& getProceduraCorrente() const {
		return proceduraCorrente;
	}


	const SessioneVoto& getSessioneCorrenteSuccessiva() const {
		return sessioneCorrenteSuccessiva;
	}


private:
	ProceduraVoto proceduraCorrente;
	SessioneVoto sessioneCorrenteSuccessiva;
	DataManager *model;
	string signString_U(string data);
	int verifySignString_U(string data, string encodedSignature);
	string generaDigestSHA256(string data); //non usato
	bool checkDigestSHA256(string digest, string dataToCheck); //non usato
	CryptoPP::RSA::PrivateKey extractPrivatePemKey(const char * client_key_pem);
	void getPublicKeyFromCert(CryptoPP::BufferedTransformation & certin,
			CryptoPP::BufferedTransformation & keyout);
};

#endif /* URNAVIRTUALE_H_ */
