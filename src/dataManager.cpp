/*
 * dataManager.cpp
 *
 *  Created on: 26/ago/2017
 *      Author: giuseppe
 */

#include "dataManager.h"
#include <time.h>

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
	time_t now = time(0);
	string dt  = ctime(&now);
	tm *ltm = localtime(&now);
	//	int anno = ltm->tm_year +1900;
	//	int mese = ltm->tm_mon + 1;
	//	int day = ltm->tm_mday;
	char buffer[20];
	//date formatted for sql db comparing
	strftime(buffer,20,"%Y-%m-%d %X",ltm); //%F equivalent to %Y-%m-%d 2001-08-23 , %X equivalent to %T 14:55:02
	string currentTime = buffer;
	cout << "current time: " << currentTime << endl;
	PreparedStatement *pstmt;
	ResultSet * resultSet;
	pstmt = connection->prepareStatement("SELECT * FROM ProcedureVoto WHERE inizio <= ? AND fine >= ?");
	try{
		pstmt->setDateTime(1,currentTime);
		pstmt->setDateTime(2,currentTime);
		resultSet = pstmt->executeQuery();

		//si suppone che per una certa data, la procedura corrente sia unica
		if(resultSet->next()){
			cout << "Procedura in corso trovata!" << endl;
			//estrazione dati procedura dalla tupla ottenuta
			pv.setIdProceduraVoto(resultSet->getUInt("idProceduraVoto"));
			pv.setDescrizione(resultSet->getString("descrizione"));
			pv.setNumSchedeVoto(resultSet->getUInt("numSchede"));
			pv.setIdRP(resultSet->getUInt("idResponsabileProcedimento"));

			string i = resultSet->getString("inizio");
			string f = resultSet->getString("fine");

			//potrei metterlo in una funzione utility
			struct tm tmInizio, tmFine;
			memset(&tmInizio, 0, sizeof(struct tm));
			memset(&tmFine, 0, sizeof(struct tm));
			strptime(i.c_str(), "%Y-%m-%d %X", &tmInizio);
			strptime(f.c_str(), "%Y-%m-%d %X", &tmFine);
			char buffer[20];
			strftime(buffer,20,"%d-%m-%Y %X",&tmInizio);
			string inizio = buffer;
			memset(&buffer,0,sizeof(buffer));
			strftime(buffer,20,"%d-%m-%Y %X",&tmFine);

			string fine = buffer;

			pv.setData_ora_inizio(inizio);
			pv.setData_ora_termine(fine);



		}
	}catch(SQLException &ex){
		cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
	}

	delete pstmt;
	delete resultSet;

	return pv;
}

bool DataManager::isScrutinioEseguito() {
	return false;
}

vector <string> DataManager::getSchedeVoto(uint idProceduraCorrente) {
	vector <string> schedeVoto;
	PreparedStatement *pstmt;
	ResultSet *resultSet;
	pstmt = connection->prepareStatement("SELECT * FROM SchedeVoto WHERE idProceduraVoto = ?");
	try{
		pstmt->setUInt(1,idProceduraCorrente);
		resultSet = pstmt->executeQuery();

		//per ogni scheda ottengo il contenuto e aggiungo alla lista delle schede
		while(resultSet->next()){
			std::istream *blobData = resultSet->getBlob("fileScheda");
			std::istreambuf_iterator<char> isb = std::istreambuf_iterator<char>(*blobData);
			std::string blobString = std::string(isb, std::istreambuf_iterator<char>());
			cout << "La scheda ottenuta ha id: " << resultSet->getUInt("codSchedaVoto") << endl;
			cout << blobString << endl;
			schedeVoto.push_back(blobString);
		}
	}catch(SQLException &ex){
		cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
	}
	pstmt->close();
	delete pstmt;
	delete resultSet;

	return schedeVoto;

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
