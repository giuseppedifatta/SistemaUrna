#include "sslserver.h"

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <mutex>
#include <vector>
#include <thread>
#include <queue>
#include <cstdlib>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include "cryptopp/osrng.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/hmac.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"
#include "cryptopp/secblock.h"


using namespace CryptoPP;


# define LOCALHOST "localhost"

#define PORT "4433"

using namespace std;

SSLServer::SSLServer(UrnaVirtuale * uv) {
	this->uv = uv;
	this->stopServer = false;
	//seggioChiamante->mutex_stdout.lock();
	cout << "ServerUrna: Costruttore!" << endl;
	//seggioChiamante->mutex_stdout.unlock();

	this->init_openssl_library();

	this->createServerContext();

	char certFile[] =
			"/home/giuseppe/myCA/intermediate/certs/localhost.cert.pem";
	char keyFile[] =
			"/home/giuseppe/myCA/intermediate/private/localhost.key.pem";
	char chainFile[] =
			"/home/giuseppe/myCA/intermediate/certs/ca-chain.cert.pem";

	configure_context(certFile, keyFile, chainFile);

	//seggioChiamante->mutex_stdout.lock();
	cout << "ServerUrna: Context configured" << endl;
	//seggioChiamante->mutex_stdout.unlock();
	this->openListener(atoi(PORT));
	this->outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

}

SSLServer::~SSLServer() {
	//nel distruttore
	cout << "ServerUrna: Distruttore!" << endl;
	if (close(this->listen_sock) != 0)
		cerr << "ServerUrna: errore di chiusura listen socket" << endl;

	BIO_free_all(this->outbio);
	SSL_CTX_free(this->ctx);

	//pericolosa, cancella gli algoritmi e non funziona più nulla
	this->cleanup_openssl();

}

void SSLServer::startListen() {

	//inizializza una socket per il client
	struct sockaddr_in client_addr;
	uint len = sizeof(client_addr);

	//seggioChiamante->mutex_stdout.lock();
	cout << "ServerUrna: in ascolto sulla porta " << PORT
			<< ", attesa connessione da un client...\n";
	//seggioChiamante->mutex_stdout.unlock();

	// accept restituisce un valore negativo in caso di insuccesso
	int client_sock = accept(this->listen_sock, (struct sockaddr*) &client_addr,
			&len);

	if (client_sock < 0) {
		perror("Unable to accept");
		exit(EXIT_FAILURE);
	} else {
		//seggioChiamante->mutex_stdout.lock();
		cout
		<< "ServerUrna: Un client ha iniziato la connessione su una socket con fd:"
		<< client_sock << endl;
		cout << "ServerUrna: Client's Port assegnata: "
				<< ntohs(client_addr.sin_port) << endl;
		//seggioChiamante->mutex_stdout.unlock();

	}

	if (!(this->stopServer)) {

		//se non è stata settata l'interruzione del server, lancia il thread per servire la richiesta
		thread t(&SSLServer::Servlet, this, client_sock);
		t.detach();
		//seggioChiamante->mutex_stdout.lock();
		cout << "ServerUrna: start a thread..." << endl;
		//seggioChiamante->mutex_stdout.unlock();
	} else {
		//termina l'ascolto
		//seggioChiamante->mutex_stdout.lock();
		cout << "ServerUrna: interruzione del server in corso..." << endl;
		//seggioChiamante->mutex_stdout.unlock();
		int ab = close(client_sock);
		if (ab == 0) {
			cout << "ServerUrna: successo chiusura socket per il client"
					<< endl;
		}
		//        ab = close(this->listen_sock);
		//        if(ab ==0){
		//            cout << "ServerUrna: successo chiusura socket del listener" << endl;
		//        }
		return;
	}

}

void SSLServer::Servlet(int client_sock_fd) {/* threadable */
	//seggioChiamante->mutex_stdout.lock();
	cout << "ServizioUrnaThread: Servlet: inizio servlet" << endl;
	//seggioChiamante->mutex_stdout.unlock();

	SSL * ssl = SSL_new(ctx);
	if (!ssl)
		exit(1);

	//configurara ssl per collegarsi sulla socket indicata
	SSL_set_fd(ssl, client_sock_fd);

	int ret = SSL_accept(ssl);
	if (ret <= 0) {/* do SSL-protocol handshake */
		cout << "ServizioUrnaThread: error in handshake" << endl;
		ERR_print_errors_fp(stderr);

	}
	else {
		//seggioChiamante->mutex_stdout.lock();
		cout << "ServizioUrnaThread: handshake ok!" << endl;
		//seggioChiamante->mutex_stdout.unlock();
		this->ShowCerts(ssl);
		this->verify_ClientCert(ssl);

		//pvChiamante->mutex_stdout.lock();
		cout << "ServizioUrnaThread: ricevo l'identificativo del servizio richiesto..."
				<< endl;
		//pvChiamante->mutex_stdout.unlock();

		//ricezione codice del servizio richiesto
		int servizio;
		char cod_servizio[128];
		memset(cod_servizio, '\0', sizeof(cod_servizio));
		int bytes = SSL_read(ssl, cod_servizio, sizeof(cod_servizio));
		if (bytes > 0) {
			cod_servizio[bytes] = 0;
			servizio = atoi(cod_servizio);

			switch (servizio) {

			case servizi::attivazionePV:
				this->serviceAttivazionePV(ssl);
				break;
			case servizi::attivazioneSeggio:
				this->serviceAttivazioneSeggio(ssl);
				break;
				//			case servizi::infoProcedura:
				//				this->serviceInfoProcedura(ssl);
				//				break;
				//			case servizi::infoSessione:
				//				this->serviceInfoSessione(ssl);
				//				break;
			case servizi::risultatiVoto:
				this->serviceRisultatiVoto(ssl);
				break;
			case servizi::storeSchedaCompilata:
				this->serviceStoreSchedaCompilata(ssl);
				break;
			case servizi::scrutinio:
				this->serviceScrutinio(ssl);
				break;
			case servizi::autenticazioneRP:
				this->serviceAutenticazioneRP(ssl);
				break;
			case servizi::tryVoteElettore:
				this->serviceTryVoteElettore(ssl);
				break;
			case servizi::infoMatricola:
				this->serviceInfoMatricola(ssl);
				break;
			case servizi::setMatricolaVoted:
				this->serviceSetMatricolaVoted(ssl);
				break;
			case servizi::checkConnection:
				this->serviceCheckConnection(ssl);
				break;
			case servizi::resetMatricolaStatoVoto:
				this->serviceResetMatricolaStatoVoto(ssl);
				break;
			default:
				cerr << "ServizioUrnaThread: Servizio non disponibile" << endl;
			}

		}
		else{
			cerr << "errore durante la ricezione del codice del servizio" << endl;
		}
	}


	//chiusura connessione
	SSL_shutdown(ssl);
	SSL_free(ssl);

	if (close(client_sock_fd) != 0) {
		cerr << "ClientSeggio: errore chiusura socket del client" << endl;
	}
	//seggioChiamante->mutex_stdout.lock();
	cout << "ServizioUrnaThread: fine servlet" << endl;
	//seggioChiamante->mutex_stdout.unlock();
}
void SSLServer::serviceStoreSchedaCompilata(SSL * ssl){
	//seggioChiamante->mutex_stdout.lock();
	cout << "ServizioUrnaThread: service started: "
			<< servizi::storeSchedaCompilata << endl;
	//seggioChiamante->mutex_stdout.unlock();
	//ricevo scheda cifrata
	string schedaCifrata;
	char buffer[16];
	memset(buffer, '\0', sizeof(buffer));
	int bytes = SSL_read(ssl, buffer, sizeof(buffer));
	if (bytes > 0) {
		buffer[bytes] = 0;
		//lunghezza fileScheda da ricevere
		uint length = atoi(buffer);
		char fileScheda[length + 1];
		memset(fileScheda, '\0', sizeof(fileScheda));
		bytes = SSL_read(ssl, fileScheda, sizeof(fileScheda));
		if (bytes > 0) {
			fileScheda[bytes] = 0;
			schedaCifrata = fileScheda;
			cout << "scheda cifrata: " << schedaCifrata << endl;
		}
	}
	//ricevo kc
	string kc;
	memset(buffer, '\0', sizeof(buffer));
	bytes = SSL_read(ssl, buffer, sizeof(buffer));
	if (bytes > 0) {
		buffer[bytes] = 0;
		//lunghezza kc da ricevere
		uint length = atoi(buffer);
		char buffer1[length + 1];
		memset(buffer1, '\0', sizeof(buffer1));
		bytes = SSL_read(ssl, buffer1, sizeof(buffer1));
		if (bytes > 0) {
			buffer1[bytes] = 0;
			kc = buffer1;
			cout << "chiave cifrata: " << kc << endl;
		}
	}
	//ricevo ivc
	string ivc;
	memset(buffer, '\0', sizeof(buffer));
	bytes = SSL_read(ssl, buffer, sizeof(buffer));
	if (bytes > 0) {
		buffer[bytes] = 0;
		//lunghezza ivc da ricevere
		uint length = atoi(buffer);
		char buffer1[length + 1];
		memset(buffer1, '\0', sizeof(buffer1));
		bytes = SSL_read(ssl, buffer1, sizeof(buffer1));
		if (bytes > 0) {
			buffer1[bytes] = 0;
			ivc = buffer1;
			cout << "initial value cifrato: " << ivc << endl;
		}
	}
	//ricevo nonce
	uint nonce;
	memset(buffer, '\0', sizeof(buffer));
	bytes = SSL_read(ssl, buffer, sizeof(buffer));
	if (bytes > 0) {
		buffer[bytes] = 0;
		//lunghezza nonce da ricevere
		uint length = atoi(buffer);
		char buffer1[length + 1];
		memset(buffer1, '\0', sizeof(buffer1));
		bytes = SSL_read(ssl, buffer1, sizeof(buffer1));
		if (bytes > 0) {
			buffer1[bytes] = 0;
			nonce = atoi(buffer1);
			cout << "Nonce:  " << nonce << endl;
		}
	}
	//ricevo mac
	string macPacchettoVoto;
	memset(buffer, '\0', sizeof(buffer));
	bytes = SSL_read(ssl, buffer, sizeof(buffer));
	if (bytes > 0) {
		buffer[bytes] = 0;
		//lunghezza mac da ricevere
		uint length = atoi(buffer);
		char buffer1[length + 1];
		memset(buffer1, '\0', sizeof(buffer1));
		bytes = SSL_read(ssl, buffer1, sizeof(buffer1));
		if (bytes > 0) {
			buffer1[bytes] = 0;
			macPacchettoVoto = buffer1;
			cout << "Mac del pacchetto di voto ricevuto: "
					<< macPacchettoVoto << endl;
		}
	}
	//verifica del MAC
	//TODO 1. ricavare sessionKey per la postazione con cui si sta comunicando
	string encodedSessionKey = "11A47EC4465DD95FCD393075E7D3C4EB";
	cout << "Session key: " << encodedSessionKey << endl;
	string plain = schedaCifrata + kc + ivc + std::to_string(nonce);
	//2. verifica dell'hmac
	int success = uv->verifyMAC(encodedSessionKey, plain, macPacchettoVoto);
	cout << "ServizioUrnaThread: esito verifica del MAC: " << success
			<< endl;
	//3. tentativo di memorizzazione del voto sul database
	if (success == 0) {
		const char* storedVoto;
		int stored = 1; //non memorizzato
		//controllo che il mac sia adeguato come identificativo del pacchetto di voto sul database
		if (uv->checkMACasUniqueID(macPacchettoVoto)) {
			string idSchedaCompilata = macPacchettoVoto;
			if(uv->storePacchettoVoto(idSchedaCompilata, schedaCifrata, kc, ivc, nonce)){
				stored = 0;
			}
		} else {
			//mac non univoco per il DB, voto non memorizzato
			stored = 1;
		}
		storedVoto = std::to_string(stored).c_str();
		//storedVoto = 0 -> stored
		//storedVoto = 1 -> unable to store
		cout << "Esito operazione di storing del pacchetto di voto: " << storedVoto << endl;
		//invio valore di successo o insuccesso della memorizzazione del voto
		SSL_write(ssl, storedVoto, strlen(storedVoto));
	} else {
		cerr << "pacchetto di voto rifiutato, perchè corrotto" << endl;
	}
	return;

}
void SSLServer::serviceAttivazionePV(SSL * ssl) {
	//seggioChiamante->mutex_stdout.lock();
	cout << "ServizioUrnaThread: service started: " << servizi::attivazionePV << endl;
	//seggioChiamante->mutex_stdout.unlock();

	//invio idProcedura alla Postazione di voto
	//contattare il DB e ricavare l'id della Procedura di voto in corso
	uint idProceduraCorrente = uv->getIdProceduraCorrente();
	stringstream ssIdProcedura;
	ssIdProcedura << idProceduraCorrente;
	string strIdProcedura = ssIdProcedura.str();
	const char * charIdProcedura = strIdProcedura.c_str();
	//uvChiamante->mutex_stdout.lock();
	cout << "ServizioUrnaThread: invio idProcedura: " << charIdProcedura << endl;
	//uvChiamante->mutex_stdout.unlock();
	SSL_write(ssl,charIdProcedura,strlen(charIdProcedura));

	if(idProceduraCorrente == 0){
		cout << "nessuna procedura in corso!" << endl;
		return;
	}


	//1. ricezione hmac dell'idProcedura generato con la chiave di sessione relativo alla postazione che ha richiesto attivazione

	string macReceived;
	char mac_buffer[512];
	memset(mac_buffer, '\0', sizeof(mac_buffer));
	int bytes = SSL_read(ssl, mac_buffer, sizeof(mac_buffer));
	if (bytes > 0) {
		mac_buffer[bytes] = 0;
		macReceived = string(mac_buffer);
		cout << "HMAC ricevuto: " << macReceived << endl;
	}
	else{
		cerr << "ServizioUrnaThread: lunghezza MAC errata" << endl;
	}

	//chiave di sessione condivisa tra la postazione da attivare e l'urna

	//TODO 2. ricavare sessionKey per la postazione con cui si sta comunicando

	string encodedSessionKey = "11A47EC4465DD95FCD393075E7D3C4EB";
	cout << "Session key: " << encodedSessionKey << endl;

	string plain;
	plain = strIdProcedura;


	//3. verifica dell'hmac


	const char * successValue;

	int success = uv->verifyMAC(encodedSessionKey,plain,macReceived);

	string str1 = std::to_string(success);
	successValue = str1.c_str();
	cout << "ServizioUrnaThread: esito verifica del MAC: " << successValue << endl;

	//4. comunica esito della verifica del mac
	SSL_write(ssl,successValue,strlen(successValue));


	//invio delle schede alla postazione di voto
	if(success == 0){
		//inviare schede di voto per la procedura corrente
		//1.comunicare il numero di schede da inviare
		uint numSchede = uv->getNumeroSchede(idProceduraCorrente);

		stringstream ssNumSchede;
		ssNumSchede << numSchede;
		string strNumSchede = ssNumSchede.str();
		const char * charNumSchede = strNumSchede.c_str();
		//uvChiamante->mutex_stdout.lock();
		cout << "ServizioUrnaThread: invio numSchede: " << charNumSchede << endl;
		//uvChiamante->mutex_stdout.unlock();
		SSL_write(ssl,charNumSchede,strlen(charNumSchede));

		//ottenere dal db le schede di voto per la procedura in corso
		vector <string> schede = uv->getSchede();
		//2.invio del numero di schede precedentemente comunicato

		for(unsigned int i = 0; i< schede.size(); i++){
			//myssl_fwrite(ssl,"scheda_voto_1.xml");


			const char *file_xml = schede.at(i).c_str();
			int length = strlen(file_xml);
			stringstream strs;
			strs << length;
			string temp_str = strs.str();
			const char *num_bytes = temp_str.c_str();

			cout << "ServizioUrnaThread: bytes to send:" << num_bytes << endl;
			SSL_write(ssl, num_bytes, strlen(num_bytes));
			SSL_write(ssl, file_xml, length);
			//manca calcolo e invio del mac delle schede di voto

		}


		//ottengo chiave pubblica di RP per la procedura corrente
		string publicKeyRP;
		publicKeyRP = uv->getPublicKeyRP(idProceduraCorrente);

		//invio chiave pubblica di RP alla postazione voto
		int length = strlen(publicKeyRP.c_str());
		stringstream strs;
		strs << length;
		string temp_str = strs.str();
		const char *num_bytes = temp_str.c_str();
		SSL_write(ssl, num_bytes, strlen(num_bytes));
		SSL_write(ssl, publicKeyRP.c_str(), length);

	}

	return;

}

void SSLServer::serviceAttivazioneSeggio(SSL * ssl) {
	//seggioChiamante->mutex_stdout.lock();
	cout << "ServizioUrnaThread: service started: " << servizi::attivazioneSeggio << endl;
	//seggioChiamante->mutex_stdout.unlock();



	//invio idProcedura alla Postazione Seggio
	//contattare il DB e ricavare l'id della Procedura di voto in corso
	uint idProceduraCorrente = uv->getIdProceduraCorrente();
	stringstream ssIdProcedura;
	ssIdProcedura << idProceduraCorrente;
	string strIdProcedura = ssIdProcedura.str();
	const char * charIdProcedura = strIdProcedura.c_str();
	//uvChiamante->mutex_stdout.lock();
	cout << "ServizioUrnaThread: invio idProcedura: " << charIdProcedura << endl;
	//uvChiamante->mutex_stdout.unlock();
	SSL_write(ssl,charIdProcedura,strlen(charIdProcedura));

	if(idProceduraCorrente == 0){
		cout << "nessuna procedura in corso!" << endl;
		return;
	}


	//1. ricezione hmac dell'idProcedura generato con la chiave di sessione relativo alla postazione che ha richiesto attivazione

	string macReceived;
	char mac_buffer[512];
	memset(mac_buffer, '\0', sizeof(mac_buffer));
	int bytes = SSL_read(ssl, mac_buffer, sizeof(mac_buffer));
	if (bytes > 0) {
		mac_buffer[bytes] = 0;
		macReceived = string(mac_buffer);
		cout << "HMAC ricevuto: " << macReceived << endl;
	}
	else{
		cerr << "ServizioUrnaThread: lunghezza MAC errata" << endl;
	}

	//chiave di sessione condivisa tra la postazione seggio da attivare e l'urna

	//TODO 2. ricavare sessionKey per la postazione seggio con cui si sta comunicando

	string encodedSessionKey = "11A47EC4465DD95FCD393075E7D3C4EB";
	cout << "Session key: " << encodedSessionKey << endl;

	string plain;
	plain = strIdProcedura;


	//3. verifica dell'hmac
	const char * successValue;

	int success = uv->verifyMAC(encodedSessionKey,plain,macReceived);

	string str1 = std::to_string(success);
	successValue = str1.c_str();
	cout << "ServizioUrnaThread: esito verifica del MAC: " << successValue << endl;

	//4. comunica esito della verifica del mac
	SSL_write(ssl,successValue,strlen(successValue));

	//se la postazione seggio è stata attivata con successo inviamo i dati:
	// - info procedura(descrizione, dataInizio, dataTermine, stato),
	// - infoSessione(idSessione, data,oraApertura, oraChiusura),
	// - info token associati al seggio (id HT, username per l'autenticazione relativi agli HT)
	if(success == 0){
		//----infoProcedura
		//invio descrizione Procedura
		string descrizione = uv->getProceduraCorrente().getDescrizione();
		sendString_SSL(ssl,descrizione);

		//invio dtInizio
		string dtInizio = uv->getProceduraCorrente().getData_ora_inizio();
		sendString_SSL(ssl,dtInizio);

		//invio dtFine
		string dtTermine = uv->getProceduraCorrente().getData_ora_termine();
		sendString_SSL(ssl,dtTermine);
		//invio stato
		uint statoProcedura = uv->getProceduraCorrente().getStato();
		sendString_SSL(ssl,std::to_string(statoProcedura));
		//----infoProcedura
		cout << "inviate informazioni procedura ."<< endl;
		//----infoSessione
		uint idSessioneCorrenteSuccessiva = uv->getIdSessioneCorrenteSuccessiva();
		//invio idSessioneCorrente o successiva
		sendString_SSL(ssl,std::to_string(idSessioneCorrenteSuccessiva));

		//se idSessioneCorrente o successiva != 0
		//invia data Sessione
		string dataSessione = uv->getSessioneCorrenteSuccessiva().getData();
		sendString_SSL(ssl,dataSessione);
		//invio oraApertura
		string oraApertura = uv->getSessioneCorrenteSuccessiva().getOraApertura();
		sendString_SSL(ssl,oraApertura);
		//invio oraChiusura
		string oraChiusura = uv->getSessioneCorrenteSuccessiva().getOraChiusura();
		sendString_SSL(ssl,oraChiusura);
		//----infoSessione
		cout << "inviate informazioni sessione" << endl;
		//----info HTs

		//invio dei 5 idHT

		//invio delle 5 username associate agli HT


	}


	return;

}

//void SSLServer::serviceInfoProcedura(SSL * ssl) {
//	//seggioChiamante->mutex_stdout.lock();
//	cout << "ServizioUrnaThread: service started: " << servizi::infoProcedura << endl;
//	//seggioChiamante->mutex_stdout.unlock();
//
//
//	return;
//
//}
//
//void SSLServer::serviceInfoSessione(SSL *ssl){
//	//seggioChiamante->mutex_stdout.lock();
//	cout << "ServizioUrnaThread: service started: " << servizi::infoSessione << endl;
//	//seggioChiamante->mutex_stdout.unlock();
//
//
//	return;
//
//}

void SSLServer::serviceRisultatiVoto(SSL *ssl) {
	//seggioChiamante->mutex_stdout.lock();
	cout << "ServizioUrnaThread: service started: " << servizi::risultatiVoto << endl;
	//seggioChiamante->mutex_stdout.unlock();


	return;

}

void SSLServer::serviceScrutinio(SSL * ssl) {
	//seggioChiamante->mutex_stdout.lock();
	cout << "ServizioUrnaThread: service started: " << servizi::scrutinio << endl;
	//seggioChiamante->mutex_stdout.unlock();


	return;

}

void SSLServer::serviceTryVoteElettore(SSL * ssl) {
	//seggioChiamante->mutex_stdout.lock();
	cout << "ServizioUrnaThread: service started: " << servizi::tryVoteElettore << endl;
	//seggioChiamante->mutex_stdout.unlock();

	//ricevi matricola elettore attivo
	string matr;
	receiveString_SSL(ssl,matr);

	uint matricola = atoi(matr.c_str());
	//prova a bloccare l'elettore per permettere la votazione esclusiva e univoca
	uint ruolo;
	uint esito = uv->tryVote(matricola,ruolo);

	//restituisci alla postazione seggio l'esito dell'operazione
	sendString_SSL(ssl,std::to_string(esito));

	//se l'esito è positivo invia il ruolo della matricola che ha richiesto di votare
	if(esito == uv->esitoLock::locked){
		sendString_SSL(ssl,std::to_string(ruolo));
	}
	return;

}



void SSLServer::serviceInfoMatricola(SSL* ssl) {
	//seggioChiamante->mutex_stdout.lock();
	cout << "ServizioUrnaThread: service started: " << servizi::infoMatricola << endl;
	//seggioChiamante->mutex_stdout.unlock();

	//ricevi matricola elettore attivo
	string matr;
	receiveString_SSL(ssl,matr);
	uint matricola = atoi(matr.c_str());
	string nome, cognome;
	uint statoVoto;
	bool matricolaPresente;
	matricolaPresente = uv->getInfoMatricola(matricola, nome, cognome,statoVoto);





	if(matricolaPresente){
		//comunica se la matricola è presente o no in anagrafica
		cout << "Matricola presente, invio i dati" << endl;
		sendString_SSL(ssl, std::to_string(uv->matricolaExist::si));

		//invio stato di voto della matricola
		sendString_SSL(ssl,std::to_string(statoVoto));

		//invia nome matricola
		sendString_SSL(ssl,nome);

		//invia cognome matricola
		sendString_SSL(ssl,cognome);

	}
	else{
		sendString_SSL(ssl, std::to_string(uv->matricolaExist::no));
		cout << "Matricola non presente" << endl;
	}


}
void SSLServer::serviceSetMatricolaVoted(SSL* ssl) {

	//ricevi matricola
	string matr;
	receiveString_SSL(ssl,matr);
	uint matricola = atoi(matr.c_str());

	//aggiorna lo stato della matricola sul database
	bool setted = uv->updateVoted(matricola);

	if(setted){
		//invio esito positivo
		sendString_SSL(ssl,to_string(0));
	}
	else{
		//invio esito negativo
		sendString_SSL(ssl,to_string(1));
	}
}

void SSLServer::serviceCheckConnection(SSL* ssl) {
	//seggioChiamante->mutex_stdout.lock();
	cout << "ServizioUrnaThread: service started: " << servizi::checkConnection << endl;
	//seggioChiamante->mutex_stdout.unlock();
}
void SSLServer::serviceResetMatricolaStatoVoto(SSL* ssl) {
	//seggioChiamante->mutex_stdout.lock();
	cout << "ServizioUrnaThread: service started: " << servizi::resetMatricolaStatoVoto << endl;
	//seggioChiamante->mutex_stdout.unlock();

	//ricevi matricola da resettare
	string matr;
	receiveString_SSL(ssl,matr);
	uint matricola = atoi(matr.c_str());


	//richiedi all'urna di eseguire l'operazione
	bool resetted = uv->resetMatricola(matricola);

	//invia esito operazione
	if(resetted){
		//invio esito positivo
		sendString_SSL(ssl,to_string(0));
	}
	else{
		//invio esito negativo
		sendString_SSL(ssl,to_string(1));
	}
}
int SSLServer::receiveString_SSL(SSL* ssl, string &s){

	char dim_string[16];
	memset(dim_string, '\0', sizeof(dim_string));
	int bytes = SSL_read(ssl, dim_string, sizeof(dim_string));
	if (bytes > 0) {
		dim_string[bytes] = 0;
		//lunghezza fileScheda da ricevere
		uint length = atoi(dim_string);
		char buffer[length + 1];
		memset(buffer, '\0', sizeof(buffer));
		bytes = SSL_read(ssl, buffer, sizeof(buffer));
		if (bytes > 0) {
			buffer[bytes] = 0;
			s = buffer;
		}
	}
	return bytes; //bytes read for the string received
}
void SSLServer::sendString_SSL(SSL* ssl, string s) {
	int length = strlen(s.c_str());
	string length_str = std::to_string(length);
	const char *num_bytes = length_str.c_str();
	SSL_write(ssl, num_bytes, strlen(num_bytes));
	SSL_write(ssl, s.c_str(), length);
}

void SSLServer::serviceAutenticazioneRP(SSL * ssl) {
	//seggioChiamante->mutex_stdout.lock();
	cout << "ServizioUrnaThread: service started: " << servizi::autenticazioneRP << endl;
	//seggioChiamante->mutex_stdout.unlock();

	//ricevi username rp


	//ricevi password rp

	//controllo credenziali sul database

	//se credenziali errate, termina


	//se credenziali corrette, prosegui
	//richiesta dati procedure di cui l'RP che si è loggato è responsabile

	//invio dati procedure trovate

	return;

}

void SSLServer::openListener(int s_port) {

	// non è specifico per openssl, crea una socket in ascolto su una porta passata come argomento
	int r;

	struct sockaddr_in sa_serv;
	this->listen_sock = socket(PF_INET, SOCK_STREAM, 0);

	//allow reuse of port without dealy for TIME_WAIT
	int iSetOption = 1;
	setsockopt(this->listen_sock, SOL_SOCKET, SO_REUSEADDR, (char*)&iSetOption,
			sizeof(iSetOption));

	if (this->listen_sock <= 0) {
		perror("Unable to create socket");
		abort();
	}

	memset(&sa_serv, 0, sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(s_port); /* Server Port number */
	cout<< "ServerUrna: Server's Port: "<< ntohs(sa_serv.sin_port)<<endl;

	r = bind(this->listen_sock, (struct sockaddr*) &sa_serv, sizeof(sa_serv));
	if (r < 0) {
		perror("Unable to bind");
		exit(EXIT_FAILURE);
	}

	// Receive a TCP connection.
	r = listen(this->listen_sock, 10);

	if (r < 0) {
		perror("Unable to listen");
		exit(EXIT_FAILURE);
	}
	//return this->listen_sock;
}

void SSLServer::createServerContext() {
	const SSL_METHOD *method;
	method = TLSv1_2_server_method();

	this->ctx = SSL_CTX_new(method);
	if (!this->ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	const long flags = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
	/*long old_opts = */SSL_CTX_set_options(this->ctx, flags);
	//    //seggioChiamante->mutex_stdout.lock();
	//    cout << "ServerUrna: bitmask options: " << old_opts << endl;
	//    //seggioChiamante->mutex_stdout.unlock();

}

void SSLServer::configure_context(char* CertFile, char* KeyFile, char* ChainFile) {
	SSL_CTX_set_ecdh_auto(this->ctx, 1);

	SSL_CTX_load_verify_locations(this->ctx, ChainFile, ChainFile);
	//SSL_CTX_use_certificate_chain_file(ctx,"/home/giuseppe/myCA/intermediate/certs/ca-chain.cert.pem");

	/*The final step of configuring the context is to specify the certificate and private key to use.*/
	/* Set the key and cert */
	if (SSL_CTX_use_certificate_file(this->ctx, CertFile, SSL_FILETYPE_PEM) < 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(this->ctx, KeyFile, SSL_FILETYPE_PEM) < 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	//SSL_CTX_set_default_passwd_cb(ctx,"password"); // cercare funzionamento con reference

	if (!SSL_CTX_check_private_key(this->ctx)) {
		fprintf(stderr, "ServerUrna: Private key does not match the public certificate\n");
		abort();
	}
	//substitute NULL with the name of the specific verify_callback
	SSL_CTX_set_verify(this->ctx, SSL_VERIFY_PEER, NULL);

}

void SSLServer::init_openssl_library() {
	SSL_library_init();

	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

	/* OpenSSL_config may or may not be called internally, based on */
	/*  some #defines and internal gyrations. Explicitly call it    */
	/*  *IF* you need something from openssl.cfg, such as a         */
	/*  dynamically configured ENGINE.                              */
	//OPENSSL_config(NULL);
}

void SSLServer::print_cn_name(const char* label, X509_NAME* const name) {
	int idx = -1, success = 0;
	unsigned char *utf8 = NULL;

	do {
		if (!name)
			break; /* failed */

		idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
		if (!(idx > -1))
			break; /* failed */

		X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
		if (!entry)
			break; /* failed */

		ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
		if (!data)
			break; /* failed */

		int length = ASN1_STRING_to_UTF8(&utf8, data);
		if (!utf8 || !(length > 0))
			break; /* failed */

		cout << "ServizioUrnaThread:   " << label << ": " << utf8 << endl;
		success = 1;

	}while (0);

	if (utf8)
		OPENSSL_free(utf8);
	//seggioChiamante->mutex_stdout.lock();
	if (!success) {

		cout << "ServizioUrnaThread:   " << label << ": <not available>" << endl;
	}
	//seggioChiamante->mutex_stdout.unlock();
}

void SSLServer::print_san_name(const char* label, X509* const cert) {
	int success = 0;
	GENERAL_NAMES* names = NULL;
	unsigned char* utf8 = NULL;

	do {
		if (!cert)
			break; // failed

		names = (GENERAL_NAMES*) X509_get_ext_d2i(cert, NID_subject_alt_name, 0,
				0);
		if (!names)
			break;

		int i = 0, count = sk_GENERAL_NAME_num(names);
		if (!count)
			break;// failed

		for (i = 0; i < count; ++i) {
			GENERAL_NAME* entry = sk_GENERAL_NAME_value(names, i);
			if (!entry)
				continue;

			if (GEN_DNS == entry->type) {
				int len1 = 0, len2 = -1;
				//ASN1_STRING_to_UTF8 restiruisce la lunghezza del buffer di out o un valore negativo
				len1 = ASN1_STRING_to_UTF8(&utf8, entry->d.dNSName);
				if (utf8) {
					len2 = (int) strlen((const char*) utf8);
				}

				if (len1 != len2) {
					cerr
					<< "ServizioUrnaThread:  Strlen and ASN1_STRING size do not match (embedded null?): "
					<< len2 << " vs " << len1 << endl;
				}

				// If there's a problem with string lengths, then
				// we skip the candidate and move on to the next.
				// Another policy would be to fails since it probably
				// indicates the client is under attack.
				if (utf8 && len1 && len2 && (len1 == len2)) {
					//lock_guard<std::mutex> guard(seggioChiamante->mutex_stdout);
					cout << "ServizioUrnaThread:   " << label << ": " << utf8 << endl;
					success = 1;
				}

				if (utf8) {
					OPENSSL_free(utf8), utf8 = NULL;
				}
			} else {
				cerr << "ServizioUrnaThread:  Unknown GENERAL_NAME type: " << entry->type << endl;
			}
		}

	}while (0);

	if (names)
		GENERAL_NAMES_free(names);

	if (utf8)
		OPENSSL_free(utf8);

	if (!success) {
		//seggioChiamante->mutex_stdout.lock();
		cout << "ServizioUrnaThread:   " << label << ": <not available>\n" << endl;
		//seggioChiamante->mutex_stdout.unlock();
	}
}

int SSLServer::verify_callback(int preverify, X509_STORE_CTX* x509_ctx) {

	/*cout << "ServizioUrnaThread: preverify value: " << preverify <<endl;*/
	int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
	int err = X509_STORE_CTX_get_error(x509_ctx);

	X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
	X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;

	//seggioChiamante->mutex_stdout.lock();
	cout << "ServizioUrnaThread: verify_callback (depth=" << depth << ")(preverify=" << preverify
			<< ")" << endl;

	/* Issuer is the authority we trust that warrants nothing useful */
	print_cn_name("Issuer (cn)", iname);

	/* Subject is who the certificate is issued to by the authority  */
	print_cn_name("Subject (cn)", sname);

	if (depth == 0) {
		/* If depth is 0, its the server's certificate. Print the SANs */
		print_san_name("Subject (san)", cert);
	}

	if (preverify == 0) {
		if (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) {

			cout << "ServizioUrnaThread:   Error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY\n";
		}
		else if (err == X509_V_ERR_CERT_UNTRUSTED) {

			cout << "ServizioUrnaThread:   Error = X509_V_ERR_CERT_UNTRUSTED\n";
		}
		else if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) {

			cout << "ServizioUrnaThread:   Error = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN\n";}
		else if (err == X509_V_ERR_CERT_NOT_YET_VALID) {

			cout << "ServizioUrnaThread:   Error = X509_V_ERR_CERT_NOT_YET_VALID\n";
		}
		else if (err == X509_V_ERR_CERT_HAS_EXPIRED) {

			cout << "ServizioUrnaThread:   Error = X509_V_ERR_CERT_HAS_EXPIRED\n";
		}
		else if (err == X509_V_OK) {

			cout << "ServizioUrnaThread:   Error = X509_V_OK\n";
		}
		else {

			cout << "ServizioUrnaThread:   Error = " << err << "\n";
		}
	}
	//seggioChiamante->mutex_stdout.unlock();

	return 1;
}

void SSLServer::print_error_string(unsigned long err, const char* const label) {
	const char* const str = ERR_reason_error_string(err);
	if (str)
		fprintf(stderr, "ServizioUrnaThread: %s\n", str);
	else
		fprintf(stderr, "ServizioUrnaThread: %s failed: %lu (0x%lx)\n", label, err, err);
}

void SSLServer::cleanup_openssl() {
	EVP_cleanup();
}

void SSLServer::ShowCerts(SSL *ssl) {

	X509 *cert = NULL;
	char *line = NULL;
	cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */

	//seggioChiamante->mutex_stdout.lock();
	ERR_print_errors_fp(stderr);
	if (cert != NULL) {
		BIO_printf(this->outbio,"Client certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		BIO_printf(this->outbio,"Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		BIO_printf(this->outbio,"Issuer: %s\n", line);
		free(line);

	} else
		BIO_printf(this->outbio,"No certificates.\n");
	//seggioChiamante->mutex_stdout.unlock();
	X509_free(cert);

}

void SSLServer::verify_ClientCert(SSL *ssl) {

	/* ---------------------------------------------------------- *
	 * Declare X509 structure                                     *
	 * ---------------------------------------------------------- */
	X509 *error_cert = NULL;
	X509 *cert = NULL;
	X509_NAME *certsubject = NULL;
	X509_STORE *store = NULL;
	X509_STORE_CTX *vrfy_ctx = NULL;
	//BIO *certbio = NULL;
	//X509_NAME *certname = NULL;
	//certbio = BIO_new(BIO_s_file());

	/* ---------------------------------------------------------- *
	 * Get the remote certificate into the X509 structure         *
	 * ---------------------------------------------------------- */
	cert = SSL_get_peer_certificate(ssl);
	//seggioChiamante->mutex_stdout.lock();
	if (cert == NULL) {

		BIO_printf(this->outbio, "ServizioUrnaThread: Error: Could not get a certificate \n"
		/*,hostname*/);
	}
	else {

		BIO_printf(this->outbio, "ServizioUrnaThread: Retrieved the client's certificate \n"
		/*,hostname*/);
	}
	//seggioChiamante->mutex_stdout.unlock();
	/* ---------------------------------------------------------- *
	 * extract various certificate information                    *
	 * -----------------------------------------------------------*/
	//certname = X509_NAME_new();
	//certname = X509_get_subject_name(cert);
	/* ---------------------------------------------------------- *
	 * display the cert subject here                              *
	 * -----------------------------------------------------------*/
	//    //seggioChiamante->mutex_stdout.lock();
	//    BIO_printf(this->outbio, "ServizioUrnaThread: Displaying the certificate subject data:\n");
	//    //seggioChiamante->mutex_stdout.unlock();
	//X509_NAME_print_ex(this->outbio, certname, 0, 0);
	//    //seggioChiamante->mutex_stdout.lock();
	//    BIO_printf(this->outbio, "\n");
	//    //seggioChiamante->mutex_stdout.unlock();
	/* ---------------------------------------------------------- *
	 * Initialize the global certificate validation store object. *
	 * ---------------------------------------------------------- */
	if (!(store = X509_STORE_new())) {
		//seggioChiamante->mutex_stdout.lock();
		BIO_printf(this->outbio, "ServizioUrnaThread: Error creating X509_STORE_CTX object\n");
		//seggioChiamante->mutex_stdout.unlock();
	}

	/* ---------------------------------------------------------- *
	 * Create the context structure for the validation operation. *
	 * ---------------------------------------------------------- */
	vrfy_ctx = X509_STORE_CTX_new();

	/* ---------------------------------------------------------- *
	 * Load the certificate and cacert chain from file (PEM).     *
	 * ---------------------------------------------------------- */
	int ret;
	/*
	 ret = BIO_read_filename(certbio, certFile);
	 if (!(cert = PEM_read_bio_X509(certbio, NULL, 0, NULL)))
	 BIO_printf(this->outbio, "ServizioUrnaThread: Error loading cert into memory\n");
	 */
	char chainFile[] =
			"/home/giuseppe/myCA/intermediate/certs/ca-chain.cert.pem";

	ret = X509_STORE_load_locations(store, chainFile, NULL);
	if (ret != 1) {
		BIO_printf(this->outbio, "ServizioUrnaThread: Error loading CA cert or chain file\n");
	}
	/* ---------------------------------------------------------- *
	 * Initialize the ctx structure for a verification operation: *
	 * Set the trusted cert store, the unvalidated cert, and any  *
	 * potential certs that could be needed (here we set it NULL) *
	 * ---------------------------------------------------------- */
	X509_STORE_CTX_init(vrfy_ctx, store, cert, NULL);

	/* ---------------------------------------------------------- *
	 * Check the complete cert chain can be build and validated.  *
	 * Returns 1 on success, 0 on verification failures, and -1   *
	 * for trouble with the ctx object (i.e. missing certificate) *
	 * ---------------------------------------------------------- */
	ret = X509_verify_cert(vrfy_ctx);
	//lock_guard<std::mutex> guard7(seggioChiamante->mutex_stdout);
	BIO_printf(this->outbio, "ServizioUrnaThread: Verification return code: %d\n", ret);

	if (ret == 0 || ret == 1) {
		//lock_guard<std::mutex> guard8(seggioChiamante->mutex_stdout);
		BIO_printf(this->outbio, "ServizioUrnaThread: Verification result text: %s\n",
				X509_verify_cert_error_string(vrfy_ctx->error));
	}
	/* ---------------------------------------------------------- *
	 * The error handling below shows how to get failure details  *
	 * from the offending certificate.                            *
	 * ---------------------------------------------------------- */
	if (ret == 0) {
		/*  get the offending certificate causing the failure */
		error_cert = X509_STORE_CTX_get_current_cert(vrfy_ctx);
		certsubject = X509_NAME_new();
		certsubject = X509_get_subject_name(error_cert);
		BIO_printf(this->outbio, "ServizioUrnaThread: Verification failed cert:\n");
		X509_NAME_print_ex(this->outbio, certsubject, 0, XN_FLAG_MULTILINE);
		BIO_printf(this->outbio, "\n");
	}

	/* ---------------------------------------------------------- *
	 * Free the structures we don't need anymore                  *
	 * -----------------------------------------------------------*/
	X509_STORE_CTX_free(vrfy_ctx);
	X509_STORE_free(store);
	X509_free(cert);

	//BIO_free_all(certbio);

	//seggioChiamante->mutex_stdout.lock();
	cout << "ServizioUrnaThread: Fine --Verify Client Cert --" << endl;
	//seggioChiamante->mutex_stdout.unlock();
}

int SSLServer::myssl_fwrite(SSL *ssl, const char * infile) {
	/* legge in modalità binaria il file e lo strasmette sulla socket aperta
	 * una SSL_write per comunicare la lunghezza dello stream da inviare
	 * una SSL_write per trasmettere il file binario della lunghezza calcolata
	 * */
	ifstream is(infile, std::ifstream::binary);
	if (is) {
		// get length of file:
		is.seekg(0, is.end);
		int length = is.tellg();
		is.seekg(0, is.beg);

		char * buffer = new char[length];

		//lock_guard<std::mutex> guard1(seggioChiamante->mutex_stdout);
		cout << "ServizioUrnaThread: Reading " << length << " characters... ";
		// read data as a block:
		is.read(buffer, length);

		if (is) {
			//lock_guard<std::mutex> guard2(seggioChiamante->mutex_stdout);
			cout << "ServizioUrnaThread: all characters read successfully." << endl;
		}
		else {
			// lock_guard<std::mutex> guard3(seggioChiamante->mutex_stdout);
			cout << "ServizioUrnaThread: error: only " << is.gcount() << " could be read";
		}
		is.close();

		// ...buffer contains the entire file...
		stringstream strs;
		strs << length;
		string temp_str = strs.str();
		const char *num_bytes = temp_str.c_str();
		cout << "ServizioUrnaThread: bytes to send:" << num_bytes << endl;
		SSL_write(ssl, num_bytes, strlen(num_bytes));
		SSL_write(ssl, buffer, length);

		delete[] buffer;
		return 1;
	}
	else {
		//lock_guard<std::mutex> guard4(seggioChiamante->mutex_stdout);
		cout << "ServizioUrnaThread: file unreadable" << endl;
	}
	return 0;
}

void SSLServer::setStopServer(bool b) {

	//proteggere con un mutex
	this->stopServer=b;

}


