/*
 * dataManager.h
 *
 *  Created on: 26/ago/2017
 *      Author: giuseppe
 */

#ifndef DATAMANAGER_H_
#define DATAMANAGER_H_

#include "proceduravoto.h"
#include "tinyxml2.h"

#include <cppconn/connection.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <sstream>
#include <string>
#include <iostream>
#include <mutex>

using namespace tinyxml2;
using namespace sql;
using namespace std;

class DataManager {
private:

    Driver *driver;
    Connection *connection;
public:
	DataManager();
	virtual ~DataManager();
	ProceduraVoto getProceduraCorrente();
	bool isScrutinioEseguito(uint idProcedura);
	vector <string> getSchedeVoto(uint idProceduraCorrente);
	SessioneVoto getSessioneCorrenteSuccessiva(uint idProceduraCorrente);
	string getSessionKey_Postazione_Urna(string IP_Postazione, uint idSessioneCorrente);
	bool storeVotoFirmato_U(string uniqueMAC, string encryptedSchedaCompilata, string encryptedKey,	string encryptedIV, uint nonce, string digestFirmato, uint idProceduraCorrente);
	string getPublicKeyRP(uint idProcedura);
	bool uniqueIDSchedaCompilata(string id);
	uint tryLockAnagrafica(uint matricola, uint &ruolo);
	bool infoVotanteByMatricola(uint matricola, string &nome, string &cognome, uint &statoVoto);
	bool setVoted(uint matricola);
	bool setNotVoted(uint matricola);
	enum statoVoto{
		non_espresso,
		votando,
		espresso
	};
	enum esitoLock{
		locked,
		alredyLocked,
		alredyVoted,
		notExist,
		errorLocking
	};
	enum ruoloUni{
		studente,
		ricercatore,
		professore
	};
private:
	mutex mutex_anagrafica;
};

#endif /* DATAMANAGER_H_ */
