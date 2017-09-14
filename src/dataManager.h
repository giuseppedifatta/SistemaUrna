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

#include "pacchettoVoto.h"

#include <cppconn/connection.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <sstream>
#include <string>
#include <iostream>
#include <mutex>
#include <time.h>

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
	//bool storeVotoFirmato_U(string uniqueMAC, string encryptedSchedaCompilata, string encryptedKey,	string encryptedIV, uint nonce, string digestFirmato, uint idProceduraCorrente);
	string getPublicKeyRP(uint idProcedura);
	bool uniqueIDSchedaCompilata(string id);
	uint tryLockAnagrafica(uint matricola, uint &ruolo);
	bool infoVotanteByMatricola(uint matricola, string &nome, string &cognome, uint &statoVoto);
	bool setVoted(uint matricola);
	bool setNotVoted(uint matricola);
	bool userSaltAndPassword(string userid,string &storedSalt, string &storedHashedPassword);
	uint getIdRPByUsername(string usernameRP);
	vector <ProceduraVoto> getProcedureRP(uint idRP);
	uint getIdRPByProcedura(uint idProcedura);
	string getEncryptedPR_RP(uint idRP);
	uint getNumberSchedeCompilate(uint idProcedura);
	vector <PacchettoVoto> getPacchettiVoto(uint idProcedura);

	//non usare con l'oggetto model di urnavirtuale.h
	void votedNotCommit(uint matricola);
	void storePacchettiSignedNoCommit(vector <PacchettoVoto> pacchetti);
	void myCommit();
	void myRollback();

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
	string dt_fromDB_toGMAhms(string dateDBformatted);

};

#endif /* DATAMANAGER_H_ */
