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


#include "urnavirtuale.h"

class UrnaVirtuale;

using namespace std;


class SSLServer
{
public:

    SSLServer(UrnaVirtuale * uv);
    ~SSLServer();

    void setStopServer(bool b);

    enum servizi { //richiedente del servizio nei commenti
        attivazionePV, //postazionevoto
        attivazioneSeggio, //seggio
        infoProcedura, //seggio
        infoSessione, //seggio
        risultatiVoto, //seggio
        invioSchedaCompilata, //postazionevoto
        scrutinio, //responsabile procedimento
        autenticazioneTecnico, //sistema tecnico
        autenticazioneRP, //responsabile procedimento

    };

    //mutex per l'accesso al vettore
    //mutex mtx_vector;
    //vector <AggiornamentoStatoPV*> aggiornamentiVector;
    //queue<thread> threads_q;

    int getListenSocketFD();
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
    void configure_context(char* CertFile, char* KeyFile, char* ChainFile);
    void ShowCerts(SSL * ssl);
    void verify_ClientCert(SSL *ssl);


    int myssl_fwrite(SSL* ssl,const char * infile);


    void print_error_string(unsigned long err, const char* const label);
    int verify_callback(int preverify, X509_STORE_CTX* x509_ctx);
    void print_san_name(const char* label, X509* const cert);
    void print_cn_name(const char* label, X509_NAME* const name);

    //riceve l'id del servizio da avviare
    void Servlet(int client_sock);

    //servizi richiamati dalla funzione Servlet
	void serviceAttivazionePV(SSL *ssl);
	void serviceAttivazioneSeggio(SSL *ssl);
	void serviceInfoProcedura(SSL * ssl);
	void serviceInfoSessione(SSL *ssl);
	void serviceRisultatiVoto(SSL *ssl);
	void serviceInvioSchedaCompilata(SSL* ssl);

	void serviceScrutinio(SSL *ssl);
	void serviceAutenticazioneTecnico(SSL *ssl);
	void serviceAutenticazioneRP(SSL *ssl);
};

#endif // SSLSERVER_H
