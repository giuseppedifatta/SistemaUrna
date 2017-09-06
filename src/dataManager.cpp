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
	pstmt->close();
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




string DataManager::getSessionKey_Postazione_Urna(string IP_Postazione,
		uint idSessioneCorrente) {
}


string DataManager::getPublicKeyRP(uint idProcedura){
	PreparedStatement *pstmt;
	ResultSet * resultSet;
	uint idRP;
	pstmt = connection->prepareStatement("SELECT idResponsabileProcedimento AS idRP FROM ProcedureVoto WHERE idProceduraVoto = ?");
	try{
		pstmt->setUInt(1,idProcedura);
		resultSet = pstmt->executeQuery();


		if(resultSet->next()){
			idRP = resultSet->getUInt("idRP");
			cout << "L'RP della procedura " << idProcedura << " ha id: " << idRP << endl;
		}
		else{
			cerr << "La procedura " << idProcedura << " non è presente" << endl;
		}
	}catch(SQLException &ex){
		cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
	}

	//otteniamo la chiave pubblica per l'RP

	pstmt = connection->prepareStatement("SELECT publicKey FROM ResponsabiliProcedimento WHERE idResponsabileProcedimento = ?");
	string publicKey;
	try{
		pstmt->setUInt(1,idRP);
		resultSet = pstmt->executeQuery();


		if(resultSet->next()){
			std::istream *blobData = resultSet->getBlob("publicKey");
			std::istreambuf_iterator<char> isb = std::istreambuf_iterator<char>(*blobData);
			publicKey = std::string(isb, std::istreambuf_iterator<char>());
		}
		else{
			cerr << "L'RP con id " << idRP << " non è presente" << endl;
		}
	}catch(SQLException &ex){
		cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
	}

	pstmt->close();
	delete pstmt;
	delete resultSet;
	//restiruisce la chiave publica encoded esadecimale
	return publicKey;
}

bool DataManager::storeVotoFirmato_U(string uniqueMAC,
		string encryptedSchedaCompilata, string encryptedKey,
		string encryptedIV, uint nonce, string digestFirmato,
		uint idProceduraCorrente) {
	bool stored = true;
	PreparedStatement *pstmt;

	pstmt = connection->prepareStatement("INSERT INTO SchedeCompilate (`idSchedaCompilata`, `idProcedura`,"
			" `fileVotoCifrato`, `chiavecifrata`, `ivcifrato`, `digestUrna`, `nonce`) VALUES(?,?,?,?,?,?,?)");
	try{
		pstmt->setString(1,uniqueMAC);
		pstmt->setUInt(2,idProceduraCorrente);

		std::stringstream ss(encryptedSchedaCompilata);
		pstmt->setBlob(3,&ss);

		ss = std::stringstream(encryptedKey);
		pstmt->setBlob(4,&ss);

		ss = std::stringstream(encryptedIV);
		pstmt->setBlob(5,&ss);

		ss = std::stringstream(digestFirmato);
		pstmt->setBlob(6,&ss);

		pstmt->setUInt(7,nonce);

		pstmt->executeUpdate();
		connection->commit();
	}catch(SQLException &ex){
		cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
		stored = false;
	}

	pstmt->close();
	delete pstmt;

	return stored;
}

SessioneVoto DataManager::getSessioneCorrenteSuccessiva(uint idProceduraCorrente) {
	SessioneVoto sv;
	time_t now = time(0);
	string dt  = ctime(&now);
	tm *ltm = localtime(&now);
	//	int anno = ltm->tm_year +1900;
	//	int mese = ltm->tm_mon + 1;
	//	int day = ltm->tm_mday;
	char buffer[20];
	//date formatted for sql db comparing
	strftime(buffer,20,"%Y-%m-%d",ltm); //%F equivalent to %Y-%m-%d 2001-08-23 , %X equivalent to %T 14:55:02
	string currentDate = buffer;
	cout << "current date: " << currentDate << endl;

	memset(buffer, 0, sizeof(buffer));
	strftime(buffer,20,"%X",ltm);
	string currentHour = buffer;
	cout << "current hour: " << currentHour << endl;

	PreparedStatement * pstmt;
	ResultSet * resultSet;
	pstmt = connection->prepareStatement
			("SELECT * FROM Sessioni WHERE idProceduraVoto=? AND `Sessioni`.`data`>=? AND ?<=chiusura order by apertura");

	try{
		pstmt->setUInt(1,idProceduraCorrente);
		pstmt->setString(2,currentDate);
		pstmt->setString(3,currentHour);

		resultSet = pstmt->executeQuery();

		//si suppone che per una certa data, la procedura corrente sia unica
		if(resultSet->next()){
			cout << "Sessione trovata!" << endl;
			//estrazione dati procedura dalla tupla ottenuta
			sv.setIdSessione(resultSet->getUInt("idSessione"));

			string data = resultSet->getString("data");
			string apertura = resultSet->getString("apertura");
			string chiusura = resultSet->getString("chiusura");

			//inserisco i dati estratti dal database in appositi oggetti struct
			struct tm dtData,tmApertura, tmChiusura;
			memset(&dtData, 0,sizeof(struct tm));
			memset(&tmApertura, 0, sizeof(struct tm));
			memset(&tmChiusura, 0, sizeof(struct tm));
			strptime(data.c_str(), "%Y-%m-%d", &dtData);
			strptime(apertura.c_str(), "%X", &tmApertura);
			strptime(chiusura.c_str(), "%X", &tmChiusura);

			char buffer[20];
			strftime(buffer,20,"%H:%M",&tmApertura);
			string oraApertura = buffer;

			memset(&buffer,0,sizeof(buffer));
			strftime(buffer,20,"%H:%M",&tmChiusura);
			string oraChiusura = buffer;

			memset(&buffer,0,sizeof(buffer));
			strftime(buffer,20,"%d-%m-%Y",&dtData);
			data = buffer;

			sv.setOraApertura(oraApertura);
			sv.setOraChiusura(oraChiusura);
			sv.setData(data);
			cout << "idSessione: " << sv.getIdSessione() << endl;
			cout << "data: " << data << endl;
			cout << "ora apertura seggi: " << oraApertura << endl;
			cout << "ora chiusura seggi: " << oraChiusura << endl;


		}
	}catch(SQLException &ex){
		cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
	}
	pstmt->close();
	delete pstmt;
	delete resultSet;
	return sv;
}

bool DataManager::uniqueIDSchedaCompilata(string idSchedaCompilata) {
	bool isUnique = true;
	PreparedStatement *pstmt;
	ResultSet * resultSet;
	pstmt = connection->prepareStatement("SELECT `idSchedaCompilata` FROM `SchedeCompilate` WHERE idSchedaCompilata =?");
	try{
		pstmt->setString(1,idSchedaCompilata);
		resultSet = pstmt->executeQuery();
		resultSet = pstmt->executeQuery();
		if(resultSet->next()){
			isUnique = false;
			cout << "idSchedaCompilata " << idSchedaCompilata << " già presente, rifiutare la memorizzazione del pacchetto di voto" << endl;
		}
		else{
			cout << "idSchedaCompilata: "<<  idSchedaCompilata<< " non è ancora presente, si può procedere alla memorizzazione del pacchetto di voto" << endl;
		}
	}catch(SQLException &ex){
		cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
	}

	pstmt->close();
	delete pstmt;
	delete resultSet;
	return isUnique;
}
