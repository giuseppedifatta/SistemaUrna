/*
 * dataManager.cpp
 *
 *  Created on: 26/ago/2017
 *      Author: giuseppe
 */

#include "dataManager.h"


DataManager::DataManager() {

	try{
		driver=get_driver_instance();
		//connection=driver->connect("localhost:3306","root", "root");
		//connection->setAutoCommit(false);
		//connection->setSchema("mydb");
	}catch(SQLException &ex){
		cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
	}

	cout << "MySql Server ok." << endl;
}

DataManager::~DataManager() {
	delete connectionAnagrafica;
	delete connectionUrna;
	// TODO Auto-generated destructor stub
}

ProceduraVoto DataManager::getProceduraCorrente() {

	ProceduraVoto pv; //valore determinato dal costruttore: idProceduraVoto=0;
	bool correzioneStato = false;
	bool resetStatoVotanti = false;
	uint statoProceduraAggiornato;
	uint statoVotantiResettato;
	uint idProceduraVoto;

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

	Connection * connection;
	this->connectToMyDB(connection);
	PreparedStatement *pstmt;
	ResultSet * resultSet;

	pstmt = connection->prepareStatement("SELECT * FROM ProcedureVoto WHERE inizio <= ? AND fine >= ?");
	try{
		pstmt->setDateTime(1,currentTime);
		pstmt->setDateTime(2,currentTime);
		resultSet = pstmt->executeQuery();


		//si suppone che per una certa data, la procedura corrente sia unica
		if(resultSet->next()){
			uint numSchedeVoto = resultSet->getUInt("numSchede");
			pv.setNumSchedeVoto(numSchedeVoto);
			uint schedeInserite = resultSet->getUInt("schedeInserite");
			pv.setSchedeInserite(schedeInserite);
			uint statoOttenuto = resultSet->getUInt("stato");


			if(numSchedeVoto==schedeInserite){ //se questa condizione non è vera, la creazione della procedura non è stata completata in tempo
				cout << "Procedura in corso trovata!" << endl;

				//se il valore dello stato non è aggiornato, bisogna correggerlo
				if(statoOttenuto!=ProceduraVoto::statiProcedura::in_corso){
					correzioneStato = true;
					statoProceduraAggiornato = ProceduraVoto::statiProcedura::in_corso;
					//bisogna resettare lo stato di voto dei votanti, sta iniziando la votazione di una nuova procedura
					resetStatoVotanti = true;
					statoVotantiResettato = statoVoto::non_espresso;
				}

				//estrazione dati procedura dalla tupla ottenuta
				idProceduraVoto = resultSet->getUInt("idProceduraVoto");
				pv.setIdProceduraVoto(idProceduraVoto);
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
			else{
				//si tratta di una procedura che dovrebbe essere iniziata, ma tutte o alcune schede sono mancanti, non resta che eliminarla
				cerr << "La creazione della procedura non è stata completata con l'inserimento di tutte le schede necessarie" << endl;
				correzioneStato = true;
				statoProceduraAggiornato = ProceduraVoto::statiProcedura::da_eliminare;
			}



		}
	}catch(SQLException &ex){
		cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
	}
	pstmt->close();
	delete pstmt;
	delete resultSet;

	if(correzioneStato){
		cout << "La procedura " << idProceduraVoto <<  " è da aggiornare" << ", nuovo stato: " << statoProceduraAggiornato << endl;

		PreparedStatement *pstmt2;
		pstmt2 = connection->prepareStatement("UPDATE ProcedureVoto SET stato=? WHERE idProceduraVoto=?");
		try{
			pstmt2->setUInt(1,statoProceduraAggiornato);
			pstmt2->setUInt(2,idProceduraVoto);
			//pstmt2->setUInt(3, statoVotantiResettato);
			pstmt2->executeUpdate();
			connection->commit();
		}catch(SQLException &ex){
			cerr << "Exception occurred: "<<ex.getErrorCode()<<endl;
		}
		pstmt2->close();
		delete pstmt2;

	}
	if(resetStatoVotanti){
		cout << "Rilevata nuova procedura, bisogna resettare lo stato dei votanti" << endl;
		PreparedStatement *pstmt2;

		pstmt2 = connection->prepareStatement("UPDATE Anagrafica SET statoVoto = ?");
		try{

			pstmt2->setUInt(1, statoVotantiResettato);
			pstmt2->executeUpdate();
			connection->commit();
		}catch(SQLException &ex){
			cerr << "Exception occurred: "<<ex.getErrorCode()<<endl;
		}
		pstmt2->close();
		delete pstmt2;

	}

	connection->close();
	delete connection;
	return pv;
}


vector<ProceduraVoto> DataManager::getProcedureRP(uint idRP) {

	//aggiorno gli stati delle procedure prima di estrarre qualsiasi dato
	this->updateStatiProcedure();

	vector <ProceduraVoto> pvs;
	Connection * connection;
	this->connectToMyDB(connection);

	PreparedStatement * pstmt;
	ResultSet * resultSet;
	pstmt = connection->prepareStatement
			("SELECT * FROM ProcedureVoto where idResponsabileProcedimento=?");
	try{
		pstmt->setUInt(1,idRP);
		resultSet = pstmt->executeQuery();
		while(resultSet->next()){
			ProceduraVoto pv;
			uint id = resultSet->getUInt("idProceduraVoto");
			pv.setIdProceduraVoto(id);

			pv.setDescrizione(resultSet->getString("descrizione"));

			uint stato = resultSet->getUInt("stato");
			pv.setStato(stato);


			string i = resultSet->getString("inizio");
			string f = resultSet->getString("fine");

			string dt_inizio = dt_fromDB_toGMAhms(i);
			cout << "inizio procedura :" << dt_inizio << endl;
			string dt_fine = dt_fromDB_toGMAhms(f);
			cout << "termine procedura :" << dt_fine << endl;

			pv.setData_ora_inizio(dt_inizio);
			pv.setData_ora_termine(dt_fine);


			cout << "Stiamo aggiungendo la procedura " << id << " al vettore delle procedure di RP: " << idRP << endl;

			pvs.push_back(pv);
		}
	}catch(SQLException &ex){
		cerr << "Exception occurred: " << ex.getErrorCode() <<endl;
	}
	pstmt->close();
	delete pstmt;
	delete resultSet;

	connection->close();
	delete connection;


	return pvs;
}

bool DataManager::isScrutinioEseguito(uint idProcedura) {

	Connection * connection;
	this->connectToMyDB(connection);

	PreparedStatement *pstmt;
	ResultSet * resultSet;
	bool eseguito = false;
	pstmt = connection->prepareStatement("SELECT stato FROM ProcedureVoto WHERE idProceduraVoto = ?");
	try{
		pstmt->setUInt(1,idProcedura);
		resultSet = pstmt->executeQuery(); //restituisce al più una tupla se la procedura esiste
		if(resultSet->next()){
			uint stato = resultSet->getUInt("stato");
			if(stato == ProceduraVoto::statiProcedura::scrutinata){
				eseguito = true;
			}
		}
	}
	catch(SQLException &ex){
		cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
	}

	pstmt->close();
	delete pstmt;
	delete resultSet;

	connection->close();
	delete connection;
	return eseguito;
}

vector <string> DataManager::getSchedeVoto(uint idProceduraCorrente) {
	vector <string> schedeVoto;
	Connection * connection;
	this->connectToMyDB(connection);


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
			//cout << "La scheda ottenuta ha id: " << resultSet->getUInt("codSchedaVoto") << endl;
			//cout << blobString << endl;
			schedeVoto.push_back(blobString);
		}
	}catch(SQLException &ex){
		cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
	}
	pstmt->close();
	delete pstmt;
	delete resultSet;
	connection->close();
	delete connection;
	return schedeVoto;

}




string DataManager::getSessionKey_Postazione_Urna(string IP_Postazione,
		uint idSessioneCorrente) {
	Connection * connection;
	this->connectToMyDB(connection);
	connection->close();
	delete connection;
}


string DataManager::getPublicKeyRP(uint idProcedura){
	Connection * connection;
	this->connectToMyDB(connection);

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

	connection->close();
	delete connection;
	//restiruisce la chiave publica encoded esadecimale
	return publicKey;
}

//bool DataManager::storeVotoFirmato_U(string uniqueMAC,
//		string encryptedSchedaCompilata, string encryptedKey,
//		string encryptedIV, uint nonce, string digestFirmato,
//		uint idProceduraCorrente) {
//	bool stored = true;
//	PreparedStatement *pstmt;
//
//	pstmt = connection->prepareStatement("INSERT INTO SchedeCompilate (`idSchedaCompilata`, `idProcedura`,"
//			" `fileVotoCifrato`, `chiavecifrata`, `ivcifrato`, `signatureUrna`, `nonce`) VALUES(?,?,?,?,?,?,?)");
//	try{
//		pstmt->setString(1,uniqueMAC);
//		pstmt->setUInt(2,idProceduraCorrente);
//
//		//std::stringstream ss(schedaStr);
//		//        pstmt->setBlob(1,&ss);
//		cout << "toBlob: " << encryptedSchedaCompilata << endl;
//
//		std::istringstream is(encryptedSchedaCompilata);
//
//		pstmt->setBlob(3,&is);
//
//
//
//		std::istringstream key(encryptedKey);
//		pstmt->setBlob(4,&key);
//
//
//		std::istringstream iv(encryptedIV);
//		pstmt->setBlob(5,&iv);
//
//		std::istringstream d(digestFirmato);
//		pstmt->setBlob(6,&d);
//
//		pstmt->setUInt(7,nonce);
//
//		pstmt->executeUpdate();
//		connection->commit();
//
//
//	}catch(SQLException &ex){
//		cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
//		stored = false;
//	}
//
//	pstmt->close();
//	delete pstmt;
//
//	return stored;
//}

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

	Connection * connection;
	this->connectToMyDB(connection);

	PreparedStatement * pstmt;
	ResultSet * resultSet;
	pstmt = connection->prepareStatement
			("SELECT * FROM Sessioni WHERE idProceduraVoto=? AND "
					"((`Sessioni`.`data`=? AND ?<=chiusura) OR `Sessioni`.`data`>? )");

	try{
		pstmt->setUInt(1,idProceduraCorrente);
		pstmt->setString(2,currentDate);
		pstmt->setString(3,currentHour);
		pstmt->setString(4,currentDate);

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


	connection->close();
	delete connection;
	return sv;
}

bool DataManager::uniqueIDSchedaCompilata(string idSchedaCompilata) {
	bool isUnique = true;
	PreparedStatement *pstmt;
	ResultSet * resultSet;
	pstmt = connectionUrna->prepareStatement("SELECT `idSchedaCompilata` FROM `SchedeCompilate` WHERE idSchedaCompilata =?");
	try{
		pstmt->setString(1,idSchedaCompilata);
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

uint DataManager::tryLockAnagrafica(uint matricola, uint &ruolo) {
	uint esito;
	Connection * connection;
	this->connectToAnagraficaDB(connection);

	PreparedStatement *pstmt;
	ResultSet * resultSet;
	pstmt = connection->prepareStatement("SELECT * FROM Anagrafica WHERE matricola =?");

	mutex_anagrafica.lock();
	bool lock = false;
	try{
		pstmt->setUInt(1,matricola);
		resultSet = pstmt->executeQuery();

		if(resultSet->next()){
			uint stato = resultSet->getUInt("statoVoto");
			string ruoloStr = resultSet->getString("ruoloUniversitario");
			if(ruoloStr == "studente"){
				ruolo = ruoloUni::studente;
			}else if(ruoloStr == "ricercatore"){
				ruolo = ruoloUni::ricercatore;
			}else if(ruoloStr == "professore"){
				ruolo = ruoloUni::professore;
			}
			if(stato == statoVoto::non_espresso){
				lock = true;
			}
			else {
				lock = false;
				if(stato == statoVoto::votando){
					esito = esitoLock::alredyLocked; //l'elettore con tale matricola sta già votando
				}
				else{
					esito = esitoLock::alredyVoted; //l'elettore ha già votato
				}
			}
		}
		else{
			cout << "matricola: "<<  matricola << " non è ancora presente in anagrafica" << endl;
			esito = esitoLock::notExist;
		}

	}catch(SQLException &ex){
		cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
	}
	pstmt->close();
	delete pstmt;
	delete resultSet;


	if (lock){
		esito = esitoLock::locked;
		PreparedStatement *pstmt;

		pstmt = connection->prepareStatement("UPDATE Anagrafica SET statoVoto = ? WHERE matricola = ?");

		try{
			pstmt->setUInt(1,statoVoto::votando);
			pstmt->setUInt(2,matricola);
			pstmt->executeUpdate();
			connection->commit();

		}catch(SQLException &ex){
			cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
			esito = esitoLock::errorLocking;
		}
		pstmt->close();
		delete pstmt;

	}



	mutex_anagrafica.unlock();

	connection->close();
	delete connection;
	return esito;

}

bool DataManager::infoVotanteByMatricola(uint matricola, string& nome,
		string& cognome, uint& statoVoto) {
	bool matricolaExist = false;
	Connection * connection;
	this->connectToAnagraficaDB(connection);

	PreparedStatement *pstmt;
	ResultSet * resultSet;
	pstmt = connection->prepareStatement("SELECT * FROM Anagrafica WHERE matricola =?");

	try{
		pstmt->setUInt(1,matricola);
		resultSet = pstmt->executeQuery();

		if(resultSet->next()){ //matricola è chiave primaria, al più un'occorrenza
			matricolaExist = true;
			statoVoto = resultSet->getUInt("statoVoto");
			nome = resultSet->getString("nome");
			cognome = resultSet->getString("cognome");
		}
		else{
			cout << "matricola: "<<  matricola << " non è ancora presente in anagrafica" << endl;
			statoVoto = 10; //matricola assente
		}

	}catch(SQLException &ex){
		cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
	}
	pstmt->close();
	delete pstmt;
	delete resultSet;
	connection->close();
	delete connection;

	return matricolaExist;
}

//bool DataManager::setVoted(uint matricola) {
//	bool voted = true;
//	PreparedStatement *pstmt;
//	pstmt = connection->prepareStatement("UPDATE Anagrafica SET statoVoto=? WHERE matricola=?");
//
//	try{
//		pstmt->setUInt(1,statoVoto::espresso);
//		pstmt->setUInt(2,matricola);
//
//		pstmt->executeUpdate();
//		connection->commit();
//
//	}catch(SQLException &ex){
//		voted = false;
//		cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
//	}
//	pstmt->close();
//	delete pstmt;
//
//	return voted;
//
//}

bool DataManager::setNotVoted(uint matricola) {
	bool unvoted = true;
	Connection * connection;
	this->connectToAnagraficaDB(connection);

	PreparedStatement *pstmt;
	pstmt = connection->prepareStatement("UPDATE Anagrafica SET statoVoto=? WHERE matricola=?");

	mutex_anagrafica.lock();


	try{
		pstmt->setUInt(1,statoVoto::non_espresso);
		pstmt->setUInt(2,matricola);

		pstmt->executeUpdate();
		connection->commit();

	}catch(SQLException &ex){
		unvoted = false;
		cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
	}

	mutex_anagrafica.unlock();

	pstmt->close();
	delete pstmt;

	connection->close();
	delete connection;
	return unvoted;
}

bool DataManager::userSaltAndPassword(string userid,string &storedSalt, string &storedHashedPassword) {
	bool useridExist =false;

	Connection * connection;
//	driver=get_driver_instance();
//	connection = driver->connect("localhost:3306","root", "root");
//	connection->setAutoCommit(false);
//	connection->setSchema("mydb");
	this->connectToMyDB(connection);

	ResultSet * resultSet;
	PreparedStatement * pstmt;
	pstmt = connection->prepareStatement("SELECT salt, hashedPassword FROM Utenti WHERE userid = ?");
	try{
		pstmt->setString(1,userid);
		resultSet = pstmt->executeQuery();
		if(resultSet->next()){
			cout << "utente " << userid << " trovato" << endl;
			useridExist = true;
			storedSalt = resultSet->getString("salt");
			storedHashedPassword = resultSet->getString("hashedPassword");
		}
		else{
			cout << "L'utente " << userid << " non esite" << endl;
		}
	}catch(SQLException &ex){
		cerr << "Exception occurred: " << ex.getErrorCode() <<endl;
	}
	pstmt->close();
	delete pstmt;
	delete resultSet;

	//	connection.close();
	//	delete connection;
	return useridExist;
}

uint DataManager::getIdRPByUsername(string usernameRP) {
	uint idRP;
	Connection * connection;
	this->connectToMyDB(connection);

	PreparedStatement * pstmt;
	ResultSet * resultSet;
	pstmt = connection->prepareStatement
			("SELECT idResponsabileProcedimento FROM ResponsabiliProcedimento WHERE userid=?");
	try{
		pstmt->setString(1,usernameRP);
		resultSet = pstmt->executeQuery();
		if(resultSet->next()){
			idRP = resultSet->getUInt("idResponsabileProcedimento");
		}
		else{
			cerr << "Responsabile di Procedimento non trovato: " << usernameRP << endl;
			idRP = 0;
		}
	}catch(SQLException &ex){
		cerr << "Exception occurred: " << ex.getErrorCode() <<endl;
	}
	pstmt->close();
	delete pstmt;
	delete resultSet;

	connection->close();
	delete connection;
	return idRP;
}

uint DataManager::getIdRPByProcedura(uint idProcedura) {
	uint idRP = 0;
	Connection * connection;
	this->connectToMyDB(connection);

	PreparedStatement * pstmt;
	ResultSet * resultSet;
	pstmt = connection->prepareStatement
			("SELECT idResponsabileProcedimento FROM ProcedureVoto WHERE idProceduraVoto=?");
	try{
		pstmt->setUInt(1,idProcedura);
		resultSet = pstmt->executeQuery();
		if(resultSet->next()){
			idRP = resultSet->getUInt("idResponsabileProcedimento");
		}
		else{
			//non dovrebbe mai verificarsi, se l'idProcedura è stato ricavato dal database
			cerr << "Nessuna procedura con id: " << idProcedura << endl;
			idRP = 0;
		}
	}catch(SQLException &ex){
		cerr << "Exception occurred: " << ex.getErrorCode() <<endl;
	}
	pstmt->close();
	delete pstmt;
	delete resultSet;

	connection->close();
	delete connection;
	return idRP;
}

string DataManager::getEncryptedPR_RP(uint idRP) {
	//restituisce la chiave privata cifrata di RP, codificata esadecimale
	string EncryptedPR_RP;
	Connection * connection;
	this->connectToMyDB(connection);

	PreparedStatement * pstmt;
	ResultSet * resultSet;
	pstmt = connection->prepareStatement
			("SELECT encryptedPrivateKey FROM ResponsabiliProcedimento WHERE idResponsabileProcedimento= ?");
	try{

		pstmt->setUInt(1,idRP);
		resultSet = pstmt->executeQuery();
		if(resultSet->next()){
			std::istream *blobData = resultSet->getBlob("encryptedPrivateKey");
			std::istreambuf_iterator<char> isb = std::istreambuf_iterator<char>(*blobData);
			EncryptedPR_RP = std::string(isb, std::istreambuf_iterator<char>());

		}
		else{
			//non dovrebbe mai verificarsi, se l'idProcedura è stato ricavato dal database
			cerr << "Responsabile di procedimento " << idRP << " non trovato" << endl;
			idRP = 0;
		}
	}catch(SQLException &ex){
		cerr << "Exception occurred: " << ex.getErrorCode() <<endl;
	}
	pstmt->close();
	delete pstmt;
	delete resultSet;

	connection->close();
	delete connection;
	return EncryptedPR_RP; //HexEncoded

}

uint DataManager::getNumberSchedeCompilate(uint idProcedura) {
	uint numSchede;
	PreparedStatement * pstmt;
	ResultSet * resultSet;
	pstmt = connectionUrna->prepareStatement
			("SELECT COUNT(*)  AS totaleSchede FROM SchedeCompilate WHERE idProcedura = ?");
	try{

		pstmt->setUInt(1,idProcedura);
		resultSet = pstmt->executeQuery();
		if(resultSet->next()){
			numSchede = resultSet->getUInt("totaleSchede");

		}

	}catch(SQLException &ex){
		cerr << "Exception occurred: " << ex.getErrorCode() <<endl;
	}
	pstmt->close();
	delete pstmt;
	delete resultSet;

	return numSchede; //HexEncoded
}

vector<PacchettoVoto> DataManager::getPacchettiVoto(uint idProcedura) {
	PreparedStatement *pstmt;
	ResultSet* resultSet;
	pstmt = connectionUrna->prepareStatement("SELECT * FROM SchedeCompilate WHERE idProcedura=?");
	vector <PacchettoVoto> pacchetti;
	try{
		pstmt->setUInt(1,idProcedura);
		resultSet = pstmt->executeQuery();
		while(resultSet->next()){
			PacchettoVoto pv;
			string idSchedaCompilata = resultSet->getString("idSchedaCompilata");
			pv.setMacId(idSchedaCompilata);

			uint idProcedura = resultSet->getUInt("idProcedura");
			pv.setIdProcedura(idProcedura);

			std::istream *blobScheda = resultSet->getBlob("fileVotoCifrato");
			std::istreambuf_iterator<char> isbScheda = std::istreambuf_iterator<char>(*blobScheda);
			std::string fileVotoCifrato = std::string(isbScheda, std::istreambuf_iterator<char>());
			pv.setSchedaCifrata(fileVotoCifrato);

			std::istream *blobKC = resultSet->getBlob("chiavecifrata");
			std::istreambuf_iterator<char> isbKC = std::istreambuf_iterator<char>(*blobKC);
			std::string KC = std::string(isbKC, std::istreambuf_iterator<char>());
			pv.setKc(KC);

			std::istream *blobIVC = resultSet->getBlob("ivcifrato");
			std::istreambuf_iterator<char> isbIVC = std::istreambuf_iterator<char>(*blobIVC);
			std::string IVC = std::string(isbIVC, std::istreambuf_iterator<char>());
			pv.setIvc(IVC);

			std::istream *blobSignature = resultSet->getBlob("signatureUrna");
			std::istreambuf_iterator<char> isbSignature = std::istreambuf_iterator<char>(*blobSignature);
			std::string signature = std::string(isbSignature, std::istreambuf_iterator<char>());
			pv.setEncodedSign(signature);

			uint nonce = resultSet->getUInt("nonce");
			pv.setNonce(nonce);

			pacchetti.push_back(pv);

		}


	}catch(SQLException &ex){
		//voted = false;
		cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
	}
	pstmt->close();
	delete pstmt;

	return pacchetti;
}

string DataManager::dt_fromDB_toGMAhms(string dateDB) {
	struct tm dtData;
	memset(&dtData, 0, sizeof(struct tm));
	strptime(dateDB.c_str(), "%Y-%m-%d %X", &dtData);
	char buffer[20];
	strftime(buffer,20,"%d-%m-%Y %X",&dtData);
	string dataGMAhms = buffer;
	return dataGMAhms;


}

void DataManager::votedNotCommit(uint matricola) {

	// se sono qui è stato bloccato il mutex_commit da chi mi ha chiamato
	this->connectToAnagraficaDB();


	PreparedStatement *pstmt;
	pstmt = connectionAnagrafica->prepareStatement("UPDATE Anagrafica SET statoVoto=? WHERE matricola=?");

	try{
		pstmt->setUInt(1,statoVoto::espresso);
		pstmt->setUInt(2,matricola);

		pstmt->executeUpdate();
		//commit in commitUrnaAnagrafica()

	}catch(SQLException &ex){
		//voted = false;
		cerr<<"Exception occurred: "<<ex.getErrorCode()<<endl;
	}
	pstmt->close();
	delete pstmt;

}

void DataManager::storePacchettiSignedNoCommit(
		vector<PacchettoVoto> pacchetti) {
	// se sono qui è stato bloccato il mutex_commit da chi mi ha chiamato
	for (uint i = 0; i< pacchetti.size(); i++){
		string uniqueMAC = pacchetti.at(i).getMacId();
		string encryptedSchedaCompilata = pacchetti.at(i).getSchedaCifrata();
		string encryptedKey = pacchetti.at(i).getKc();
		string encryptedIV = pacchetti.at(i).getIvc();
		uint nonce = pacchetti.at(i).getNonce();
		string digestFirmato = pacchetti.at(i).getEncodedSign();
		uint idProceduraCorrente = pacchetti.at(i).getIdProcedura();

		PreparedStatement *pstmt;

		pstmt = connectionUrna->prepareStatement("INSERT INTO SchedeCompilate (`idSchedaCompilata`, `idProcedura`,"
				" `fileVotoCifrato`, `chiavecifrata`, `ivcifrato`, `signatureUrna`, `nonce`) VALUES(?,?,?,?,?,?,?)");
		try{
			pstmt->setString(1,uniqueMAC);
			pstmt->setUInt(2,idProceduraCorrente);

			//std::stringstream ss(schedaStr);
			//        pstmt->setBlob(1,&ss);
			cout << "Scheda compilata to Blob: " << encryptedSchedaCompilata << endl;

			std::istringstream is(encryptedSchedaCompilata);

			pstmt->setBlob(3,&is);



			std::istringstream key(encryptedKey);
			pstmt->setBlob(4,&key);


			std::istringstream iv(encryptedIV);
			pstmt->setBlob(5,&iv);

			std::istringstream d(digestFirmato);
			pstmt->setBlob(6,&d);

			pstmt->setUInt(7,nonce);

			pstmt->executeUpdate();
			//commit in commitUrnaAnagrafica();


		}catch(SQLException &ex){
			cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
		}

		pstmt->close();
		delete pstmt;
	}

}

void DataManager::commitUrnaAnagrafica() {

	// se sono qui è stato bloccato il mutex_commit da chi mi ha chiamato
	cout << "commit: pacchetti voto salvati e stato della matricola (espresso) salvati sul db" << endl;
	try{
		connectionUrna->commit();
		connectionAnagrafica->commit();
	}catch(SQLException &ex){
		cerr<<"Exception occurred: "<<ex.getErrorCode()<<endl;
	}

	connectionUrna->close();
	connectionAnagrafica->close();
}

void DataManager::rollbackUrnaAnagrafica() {

	// se sono qui è stato bloccato il mutex_commit da chi mi ha chiamato

	cout << "rollback: pacchetti voto scartati e modifica stato della matricola su (espresso) non salvato sul db" << endl;
	try{
		connectionUrna->rollback();
		connectionAnagrafica->rollback();
	}catch(SQLException &ex){
		cerr<<"Exception occurred: "<<ex.getErrorCode()<<endl;
	}

	connectionUrna->close();
	connectionAnagrafica->close();
}

void DataManager::updateStatiProcedure() {
	//cout << "aggiorno stati procedure" << endl;
	PreparedStatement *pstmt;
	ResultSet * resultSet;
	string currentTime = currentTimeDbFormatted();
	cout << "Current time: " << currentTime << endl;

	Connection * connection;
	this->connectToMyDB(connection);

	//aggiornamento procedure concluse
	//ottengo tute le procedure il cui termine di votazione è trascorso
	pstmt = connection->prepareStatement("SELECT * FROM ProcedureVoto WHERE fine < ?");

	try{
		pstmt->setString(1,currentTime);
		resultSet = pstmt->executeQuery();

		while(resultSet->next()){
			uint stato = resultSet->getUInt("stato");
			uint conclusa = ProceduraVoto::statiProcedura::conclusa;
			uint scrutinata = ProceduraVoto::statiProcedura::scrutinata;
			uint da_eliminare = ProceduraVoto::statiProcedura::da_eliminare;
			uint idProceduraVoto = resultSet->getUInt("idProceduraVoto");

			uint statoAggiornato;
			bool daAggiornare = false;
			if (stato!=conclusa && stato!=scrutinata && stato!=da_eliminare){
				uint numSchedeRichieste = resultSet->getUInt("numSchede");
				uint numSchedeInserite = resultSet->getUInt("schedeInserite");
				daAggiornare = true;
				if(numSchedeRichieste == numSchedeInserite){
					statoAggiornato = ProceduraVoto::statiProcedura::conclusa;
				}
				else{
					statoAggiornato = ProceduraVoto::statiProcedura::da_eliminare;
				}
			}

			if(daAggiornare){
				PreparedStatement *pstmt2;
				cout << "La procedura " << idProceduraVoto <<  " è da aggiornare" << ", nuovo stato: " << statoAggiornato << endl;
				pstmt2 = connection->prepareStatement("UPDATE ProcedureVoto SET stato=?, ultimaModifica=? WHERE idProceduraVoto=?");

				try{
					pstmt2->setUInt(1,statoAggiornato);
					pstmt2->setDateTime(2,currentTime);
					pstmt2->setUInt(3,idProceduraVoto);
					pstmt2->executeUpdate();
					connection->commit();
				}catch(SQLException &ex){
					cerr << "Exception occurred: "<<ex.getErrorCode()<<endl;
				}

				pstmt2->close();
				delete pstmt2;

			}




		}
	}
	catch(SQLException &ex){
		cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
	}
	pstmt->close();
	delete pstmt;
	delete resultSet;



	//aggiornamento della sola ed eventuale procedura in corso
	bool correzioneStato = false;
	bool resetStatoVotanti = false;
	uint statoProceduraAggiornato;
	uint statoVotantiResettato;
	uint idProceduraVoto;
	PreparedStatement *pstmt3;
	ResultSet * resultSet3;
	pstmt3 = connection->prepareStatement("SELECT * FROM ProcedureVoto WHERE inizio <= ? AND fine >= ?");
	try{
		pstmt3->setDateTime(1,currentTime);
		pstmt3->setDateTime(2,currentTime);
		resultSet3 = pstmt3->executeQuery();


		//si suppone che per una certa data, la procedura corrente sia unica
		if(resultSet3->next()){
			uint numSchedeVoto = resultSet3->getUInt("numSchede");

			uint schedeInserite = resultSet3->getUInt("schedeInserite");

			uint statoOttenuto = resultSet3->getUInt("stato");

			idProceduraVoto = resultSet3->getUInt("idProceduraVoto");


			if(numSchedeVoto==schedeInserite){ //se questa condizione non è vera, la creazione della procedura non è stata completata in tempo
				cout << "Procedura in corso trovata!" << endl;

				//se il valore dello stato non è aggiornato, bisogna correggerlo
				if(statoOttenuto!=ProceduraVoto::statiProcedura::in_corso){
					correzioneStato = true;
					statoProceduraAggiornato = ProceduraVoto::statiProcedura::in_corso;
					//bisogna resettare lo stato di voto dei votanti, sta iniziando la votazione di una nuova procedura
					resetStatoVotanti = true;
					statoVotantiResettato = statoVoto::non_espresso;
				}

			}
			else{
				//si tratta di una procedura che dovrebbe essere iniziata, ma tutte o alcune schede sono mancanti, non resta che eliminarla
				cerr << "La creazione della procedura non è stata completata con l'inserimento di tutte le schede necessarie" << endl;
				correzioneStato = true;
				statoProceduraAggiornato = ProceduraVoto::statiProcedura::da_eliminare;
			}



		}
	}catch(SQLException &ex){
		cout<<"Exception occurred: "<<ex.getErrorCode()<<endl;
	}
	pstmt3->close();
	delete pstmt3;
	delete resultSet3;

	if(correzioneStato){
		PreparedStatement *pstmt2;
		cout << "La procedura " << idProceduraVoto <<  " è da aggiornare" << ", nuovo stato: " << statoProceduraAggiornato << endl;
		pstmt2 = connection->prepareStatement("UPDATE ProcedureVoto SET stato=?, ultimaModifica=?  WHERE idProceduraVoto=?");

		//sezione critica
		try{
			pstmt2->setUInt(1,statoProceduraAggiornato);
			pstmt2->setDateTime(2,currentTime);
			pstmt2->setUInt(3,idProceduraVoto);
			//pstmt2->setUInt(3, statoVotantiResettato);
			pstmt2->executeUpdate();
			connection->commit();
		}catch(SQLException &ex){
			cerr << "Exception occurred: "<<ex.getErrorCode()<<endl;
		}
		//fine sezione critica

		pstmt2->close();
		delete pstmt2;

	}
	if(resetStatoVotanti){

		PreparedStatement *pstmt2;
		cout << "Rilevata nuova procedura, bisogna resettare lo stato dei votanti" << endl;
		pstmt2 = connection->prepareStatement("UPDATE Anagrafica SET statoVoto = ?");

		try{

			pstmt2->setUInt(1, statoVotantiResettato);
			pstmt2->executeUpdate();
			connection->commit();
		}catch(SQLException &ex){
			cerr << "Exception occurred: "<<ex.getErrorCode()<<endl;
		}

		pstmt2->close();
		delete pstmt2;

	}


	connection->close();
	delete connection;

}

string DataManager::currentTimeDbFormatted() {
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
	return currentTime;
}

void DataManager::connectToMyDB(Connection *&connection) {

	driver = get_driver_instance();
	connection = driver->connect("localhost:3306","root", "root");
	connection->setAutoCommit(false);
	connection->setSchema("mydb");

	cout << "connessione a mydb" << endl;
}

void DataManager::connectToAnagraficaDB(Connection *& connection) {
	connection=driver->connect("localhost:3306","root", "root");
	connection->setAutoCommit(false);
	connection->setSchema("anagraficaDB");
	cout << "connessione a anagraficaDB" << endl;

}

void DataManager::connectToUrnaDB() {
	connectionUrna=driver->connect("localhost:3306","root", "root");
	connectionUrna->setAutoCommit(false);
	connectionUrna->setSchema("urnaDB");
	cout << "connessione a anagraficaDB" << endl;

}



void DataManager::connectToAnagraficaDB() {
	connectionAnagrafica=driver->connect("localhost:3306","root", "root");
	connectionAnagrafica->setAutoCommit(false);
	connectionAnagrafica->setSchema("anagraficaDB");
	cout << "connessione a anagraficaDB" << endl;

}

void DataManager::connectionCloseUrnaAnagrafica() {
	connectionUrna->close();
	connectionAnagrafica->close();
}
