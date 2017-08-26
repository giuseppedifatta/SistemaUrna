/*
 * dataManager.cpp
 *
 *  Created on: 26/ago/2017
 *      Author: giuseppe
 */

#include "dataManager.h"


DataManager::DataManager() {
	// TODO Auto-generated constructor stub
	try{
	        driver=get_driver_instance();
	        connection=driver->connect("localhost:3306","root", "root");
	        connection->setAutoCommit(false);
	        connection->setSchema("mydb");
	    }catch(SQLException &ex){
	        cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
	    }

	    cout << "MySql Server ok." << endl;
}

DataManager::~DataManager() {
	// TODO Auto-generated destructor stub
}

ProceduraVoto DataManager::getProceduraCorrente() {

	ProceduraVoto pv;
	return pv;
}

bool DataManager::isScrutinioEseguito() {
}

vector <XMLDocument> DataManager::getSchedeVoto(uint idProceduraCorrente) {
}

uint DataManager::getIdSessioneCorrente(uint idProceduraCorrente) {
}

string DataManager::getSessionKey_Postazione_Urna(string IP_Postazione,
		uint idSessioneCorrente) {
}

bool DataManager::storeVotoFirmato_U(string uniqueMAC,
		string encryptedSchedaCompilata, string encryptedKey,
		string encryptedIV, int nonce, string digest) {
}
