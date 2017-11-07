#ifndef SSLSERVER_H
#define SSLSERVER_H

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>
#include <openssl/x509v3.h>
#include <openssl/opensslconf.h>

#include <vector>
#include <mutex>
#include <thread>
#include "sessionevoto.h"


#include "urnavirtuale.h"
#include "pacchettoVoto.h"
#include "conf.h"

class UrnaVirtuale;

using namespace std;


class SSLServer
{
public:

	SSLServer(UrnaVirtuale * uv);
	~SSLServer();

	void setStopServer(bool b);

	enum servizi { //richiedente del servizio nei commenti
		attivazionePV = 0, //postazionevoto
		attivazioneSeggio = 1, //seggio
		//infoProcedura, //seggio
		nextSessione = 3, //seggio
		risultatiVoto = 4, //seggio
		storeSchedeCompilate = 5, //postazionevoto
		scrutinio = 6, //responsabile procedimento
		autenticazioneRP = 7,//responsabile procedimento
		tryVoteElettore = 8, //seggio
		infoMatricola = 9, //seggio
		//setMatricolaVoted = 10,
		checkConnection = 11, //postazione voto
		resetMatricolaStatoVoto = 12 //seggio
	};

	//funzione che mette il server in ascolto delle richieste
	void startListen();
private:
	UrnaVirtuale *uv;
	//std::thread test_thread;
	BIO* outbio;
	SSL_CTX * ctx;
	int listen_sock;

	bool stopServer;

	void openListener(int s_port);
	void init_openssl_library();
	void cleanup_openssl();

	void createServerContext();
	void configure_context(const char* CertFile, const char* KeyFile, const char* ChainFile);
	void ShowCerts(SSL * ssl);
	void verify_ClientCert(SSL *ssl);


	int myssl_fwrite(SSL* ssl,const char * infile);
	void sendString_SSL(SSL * ssl, string s);
	int receiveString_SSL(SSL *ssl, string &s);


	void print_error_string(unsigned long err, const char* const label);
	int verify_callback(int preverify, X509_STORE_CTX* x509_ctx);
	void print_san_name(const char* label, X509* const cert);
	void print_cn_name(const char* label, X509_NAME* const name);

	//riceve l'id del servizio da avviare
	void Servlet(int client_sock/*,string ipClient*/);

	//servizi richiamati dalla funzione Servlet
	void serviceAttivazionePV(SSL *ssl, string ipClient);
	void serviceAttivazioneSeggio(SSL *ssl, string ipClient);
	//void serviceInfoProcedura(SSL * ssl, string ipClient);
	void serviceNextSessione(SSL * ssl);
	void serviceRisultatiVoto(SSL *ssl);
	void serviceStoreSchedeCompilate(SSL* ssl, string ipClient);
	void serviceScrutinio(SSL *ssl);
	void serviceAutenticazioneRP(SSL *ssl);
	void serviceTryVoteElettore(SSL * ssl, string ipClient);
	void serviceInfoMatricola(SSL * ssl, string ipClient);

	void serviceCheckConnection(SSL *ssl, string ipClient);
	void serviceResetMatricolaStatoVoto(SSL * ssl, string ipClient);
};

#endif // SSLSERVER_H
