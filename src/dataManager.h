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
#include "hardwaretoken.h"

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
	Connection *connectionUrna;
	Connection *connectionAnagrafica;
public:

	void connectToMyDB(Connection *& connection);
	void connectToAnagraficaDB(Connection *& connection);
	void connectToAnagraficaDB();
	void connectToUrnaDB();
	void connectionCloseUrnaAnagrafica();
	void connectionCloseUrna();
	void connectionCloseAnagrafica();

	DataManager();
	virtual ~DataManager();
	ProceduraVoto getProceduraCorrente();
	vector <ProceduraVoto> getProcedureRP(uint idRP);


	bool isScrutinioEseguito(uint idProcedura);
	vector <string> getSchedeVoto(uint idProceduraCorrente);
	SessioneVoto getSessioneCorrenteSuccessiva(uint idProceduraCorrente);
	string getSessionKey_Postazione_Urna(string IP_Postazione, uint idSessioneCorrente);
	//bool storeVotoFirmato_U(string uniqueMAC, string encryptedSchedaCompilata, string encryptedKey,	string encryptedIV, uint nonce, string digestFirmato, uint idProceduraCorrente);
	string getPublicKeyRP(uint idProcedura);
	string getPublicKeyRP(string usernameRP);
	bool uniqueIDSchedaCompilata(string id);
	uint tryLockAnagrafica(uint matricola, uint &idTipoVotante);
	bool infoVotanteByMatricola(uint matricola, string &nome, string &cognome, uint &statoVoto);
	//bool setVoted(uint matricola);
	bool setNotVoted(uint matricola);
	bool userSaltAndPassword(string userid,string &storedSalt, string &storedHashedPassword);
	uint getIdRPByUsername(string usernameRP);

	uint getIdRPByProcedura(uint idProcedura);
	string getEncryptedPR_RP(uint idRP);
	uint getNumberSchedeCompilate(uint idProcedura);
	vector <PacchettoVoto> getPacchettiVoto(uint idProcedura);
	string rpSalt(string usernameRP);
	uint idSeggioByIpPostazione(string ipPostazione);
	vector <HardwareToken> htSeggio(string ipSeggio);



	void votedNotCommit(uint matricola);
	void storePacchettiSignedNoCommit(vector <PacchettoVoto> pacchetti);
	void storeScrutinio(string scrutinioXML,uint idProcedura, string encodedSignatureRP);
	void commitUrnaAnagrafica();
	void rollbackUrnaAnagrafica();

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
private:
	mutex mutex_anagrafica;

	string dt_fromDB_toGMAhms(string dateDBformatted);

	void updateStatiProcedure();
	string currentTimeDbFormatted();


};

#endif /* DATAMANAGER_H_ */
