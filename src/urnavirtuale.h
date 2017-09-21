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
#include <mutex>
#include "tinyxml2.h"
#include "proceduravoto.h"
#include "dataManager.h"
#include "schedacompilata.h"
#include "risultatiSeggio.h"

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
#include <cryptopp/pwdbased.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>

using namespace CryptoPP;
using namespace tinyxml2;
using namespace std;

class UrnaVirtuale {
public:
	//mutex per proteggere le sessioni di ricezione dei pacchetti di voto
	mutex mutex_ricezione_pacchetti;

	UrnaVirtuale();
	virtual ~UrnaVirtuale();
	uint getIdProceduraCorrente();
	uint getNumeroSchede(uint idProcedura);
	bool checkScrutinioEseguito(uint idProcedura);

	string getStringProcedure_formattedXML_byUsernameRP(string usernameRP);
	uint tryVote(uint matricola,uint &ruolo);
	vector <string> getSchede();
	string getPublicKeyRP(uint idProceduraCorrente);
	int verifyMAC(string encodedSessionKey,string plain, string macEncoded);
	string calcolaMAC(string encodedSessionKey, string plainText);
	bool checkMACasUniqueID(string macPacchettoVoto);
	//bool storePacchettoVoto(string idSchedaCompilata, string schedaCifrata, string kc, string ivc, uint nonce);
	uint getIdSessioneCorrenteSuccessiva();
	bool getInfoMatricola(uint matricola, string &nome, string &cognome, uint &statoVoto);
	//bool updateVoted(uint matricola);
	bool resetMatricola(uint matricola);
	bool authenticateRP(string userid, string password);
	string hashPassword( string plainPass, string salt);
	string procedureVotoRPtoXML(vector <ProceduraVoto> pvs);
	uint idRPByUsername(string username);
	uint useridByIdProcedura(uint idProcedura);
	bool doScrutinio(uint idProcedura, string derivedKey);
	uint numSchedeCompilate(uint idProcedura);
	void initConnessioneUrnaDB();

	const ProceduraVoto& getProceduraCorrente() const {
		return proceduraCorrente;
	}


	const SessioneVoto& getSessioneCorrenteSuccessiva() const {
		return sessioneCorrenteSuccessiva;
	}

	enum esitoLock{
		locked,
		alredyLocked,
		alredyVoted,
		notExist,
		errorLocking
	};
	enum matricolaExist{
		exist,
		not_exist
	};
	enum autenticato{
		authenticated,
		not_authenticated
	};

	enum compilata{
		bianca,
		valida
	};
	//queste funzioni utilizzano il modelPacchetti
	void presetVoted(uint matricola);
	void storePacchettiVoto(vector <PacchettoVoto> pacchetti);
	void savePacchetti();
	void discardPacchetti();

private:
	ProceduraVoto proceduraCorrente;
	SessioneVoto sessioneCorrenteSuccessiva;

	DataManager *model; //query e update generiche sul DB

//	DataManager *modelPacchetti; //riservato per operazioni di storage dei pacchetti di voto
//
//	DataManager *modelAnagrafica; //riservato per operazioni di aggiornamento di stato voto delle anagrafiche

	string signString_U(string data);
	int verifySignString_U(string data, string encodedSignature);
	string signString_RP(string data,CryptoPP::RSA::PrivateKey privateKey);
	int verifySignString_RP(string data, string encodedSignature,string encodedPublicKey);
	string generaDigestSHA256(string data); //non usato
	bool checkDigestSHA256(string digest, string dataToCheck); //non usato
	bool parseDecryptSchedaCifrata(string schedaCifrata,SecByteBlock k ,SecByteBlock iv, uint nonce,SchedaCompilata* sc,uint &compilata_bianca);
	SecByteBlock RSADecrypt(string cipher, CryptoPP::RSA::PrivateKey privateKey);
	string AESdecryptStdString(string cipher, SecByteBlock key, SecByteBlock iv);
	string AESdecryptStdString(string cipher, SecByteBlock key, byte* iv);

	CryptoPP::RSA::PrivateKey extractPrivatePemKey(const char * key_pem_filePath);
	void getPublicKeyFromCert(CryptoPP::BufferedTransformation & certin,		CryptoPP::BufferedTransformation & keyout);


	void contarePreferenze(SchedaCompilata sc,RisultatiSeggio *rs);
	void addSeggioIfNotExist(vector <RisultatiSeggio> *risultatiSeggi,uint idSeggio,const vector <SchedaVoto> &schedeVoto);
	vector<SchedaVoto> parsingSchedeVotoXML(vector<string> &schede);
	void createScrutinioXML(vector<RisultatiSeggio>& risultatiSeggi,XMLDocument *xmlDoc);


};

#endif /* URNAVIRTUALE_H_ */
