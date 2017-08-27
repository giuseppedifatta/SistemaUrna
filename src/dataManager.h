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

using namespace tinyxml2;
using namespace sql;
class DataManager {
private:

    Driver *driver;
    Connection *connection;
public:
	DataManager();
	virtual ~DataManager();
	ProceduraVoto getProceduraCorrente();
	bool isScrutinioEseguito();
	vector <string> getSchedeVoto(uint idProceduraCorrente);
	uint getIdSessioneCorrente(uint idProceduraCorrente);
	string getSessionKey_Postazione_Urna(string IP_Postazione, uint idSessioneCorrente);
	bool storeVotoFirmato_U(string uniqueMAC,string encryptedSchedaCompilata, string encryptedKey, string encryptedIV, int nonce, string digest);
};

#endif /* DATAMANAGER_H_ */
