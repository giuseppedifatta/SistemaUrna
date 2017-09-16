/*
 * urnavirtuale.cpp
 *
 *  Created on: 03/ago/2017
 *      Author: giuseppe
 */

#include "urnavirtuale.h"
#include "RSA-PSS_utils.h"

UrnaVirtuale::UrnaVirtuale() {
	// TODO Auto-generated constructor stub
	model = new DataManager();
	modelPacchetti = new DataManager();
}

UrnaVirtuale::~UrnaVirtuale() {
	// TODO Auto-generated destructor stub
}

uint UrnaVirtuale::getIdProceduraCorrente(){
	//contattare il db e ottenere l'id della procedura corrente
	proceduraCorrente = model->getProceduraCorrente();

	return proceduraCorrente.getIdProceduraVoto();
}

uint UrnaVirtuale::getIdSessioneCorrenteSuccessiva(){
	sessioneCorrenteSuccessiva = model->getSessioneCorrenteSuccessiva(proceduraCorrente.getIdProceduraVoto());

	return sessioneCorrenteSuccessiva.getIdSessione();
}

uint UrnaVirtuale::getNumeroSchede(uint idProceduraCorrente){
	//contattare il db per ottenere il numero di schede abbinate alla procedura

	uint numSchede = proceduraCorrente.getNumSchedeVoto();
	return numSchede;
}

vector<string> UrnaVirtuale::getSchede() {
	uint idProcedura = proceduraCorrente.getIdProceduraVoto();
	//cout << "richiedo al model le schede per la procedura: " << idProcedura << endl;
	return model->getSchedeVoto(idProcedura);
}

string UrnaVirtuale::getPublicKeyRP(uint idProceduraCorrente){
	return model->getPublicKeyRP(idProceduraCorrente);
}



bool UrnaVirtuale::checkMACasUniqueID(string macPacchettoVoto) {
	return model->uniqueIDSchedaCompilata(macPacchettoVoto);
}

//bool UrnaVirtuale::storePacchettoVoto(string idSchedaCompilata,
//		string schedaCifrata, string kc, string ivc, uint nonce) {
//	uint idProcedura = this->getIdProceduraCorrente();
//	string dataToStore = idSchedaCompilata + schedaCifrata + kc + ivc + std::to_string(nonce) + std::to_string(idProcedura);
//	//TODO firmare pacchetto di voto
//	cout << idSchedaCompilata << endl;
//	cout << schedaCifrata << endl;
//	cout << kc << endl;
//	cout << ivc << endl;
//
//	string encodedSignature = signString_U(dataToStore);
//
//	//chiedere al model di memorizzare il pacchetto di voto sul database
//	return model->storeVotoFirmato_U(idSchedaCompilata,schedaCifrata,kc,ivc,nonce, encodedSignature, idProcedura);
//}

string UrnaVirtuale::signString_U(string data) {

	const char * filePrivateKey = "/home/giuseppe/myCA/intermediate/private/localhost.key.pem";
	RSA::PrivateKey privateKey = this->extractPrivatePemKey(filePrivateKey);
	ByteQueue queue;
	privateKey.Save(queue);
	HexEncoder encoder;
	queue.CopyTo(encoder);
	encoder.MessageEnd();

	string s;
	StringSink ss(s);
	encoder.CopyTo(ss);
	ss.MessageEnd();
	cout << "PrivateKey:" << s << endl;

	cout << "Data to sign: " << data << endl;

	string signature;
	string encodedSignature;
	////////////////////////////////////////////////
	try{
		// Sign and Encode
		RSASS<PSS, SHA256>::Signer signer(privateKey);

		AutoSeededRandomPool rng;

		StringSource(data, true,
				new SignerFilter(rng, signer, new StringSink(signature)) // SignerFilter
		);// StringSource
		cout << " Signature: " << signature << endl;

		StringSource(signature,true,
				new HexEncoder(
						new StringSink(encodedSignature)
				)//HexEncoder
		);//StringSource
		cout << "Signature encoded: " << encodedSignature << endl;

		//------ verifica signature
		FileSource certin(
				"/home/giuseppe/myCA/intermediate/certs/localhost.cert.der", true,
				NULL, true);
		FileSink keyout("localhost-public.key", true);

		getPublicKeyFromCert(certin, keyout);

		//non dimenticare di chiudere il buffer!!!!!!!
		keyout.MessageEnd();

		RSA::PublicKey publicKey;
		LoadPublicKey("localhost-public.key", publicKey);


		ByteQueue queue;
		publicKey.Save(queue);
		HexEncoder encoder;
		queue.CopyTo(encoder);
		encoder.MessageEnd();

		string s;
		StringSink ss(s);
		encoder.CopyTo(ss);
		ss.MessageEnd();
		cout << "PublicKey: " << s << endl;
		////////////////////////////////////////////////
		// Verify and Recover
		RSASS<PSS, SHA256>::Verifier verifier(publicKey);
		cout << data + signature << endl;
		StringSource(data + signature, true,
				new SignatureVerificationFilter(verifier, NULL,
						SignatureVerificationFilter::THROW_EXCEPTION) // SignatureVerificationFilter
		);// StringSource

		cout << "Verified signature on message" << endl;

	} // try

	catch (CryptoPP::Exception& e) {
		cerr << "Error: " << e.what() << endl;
	}

	return encodedSignature;
}

int UrnaVirtuale::verifySignString_U(string data, string encodedSignature) {
	int success = 1; //non verificato
	string signature;
	StringSource(encodedSignature,true,
			new HexDecoder(
					new StringSink(signature)
			)//HexDecoder
	);//StringSource
	cout << "Signature encoded: " << encodedSignature << endl;
	cout << "Signature decoded: " << signature << endl;

	try{
		////------ verifica signature
		FileSource certin(
				"/home/giuseppe/myCA/intermediate/certs/localhost.cert.der", true,
				NULL, true);
		FileSink keyout("localhost-public.key", true);

		getPublicKeyFromCert(certin, keyout);

		//non dimenticare di chiudere il buffer!!!!!!!
		keyout.MessageEnd();

		RSA::PublicKey publicKey;
		LoadPublicKey("localhost-public.key", publicKey);


		ByteQueue queue;
		publicKey.Save(queue);
		HexEncoder encoder;
		queue.CopyTo(encoder);
		encoder.MessageEnd();

		string s;
		StringSink ss(s);
		encoder.CopyTo(ss);
		ss.MessageEnd();
		cout << "PublicKey encoded: " << s << endl;
		////////////////////////////////////////////////
		// Verify and Recover
		RSASS<PSS, SHA256>::Verifier verifier(publicKey);
		cout << "Data to sign|signature: " << data + signature << endl;
		StringSource(data + signature, true,
				new SignatureVerificationFilter(verifier, NULL,
						SignatureVerificationFilter::THROW_EXCEPTION) // SignatureVerificationFilter
		);// StringSource

		cout << "Verified signature on message" << endl;
		success = 0; //verificato
	} // try

	catch (CryptoPP::Exception& e) {
		cerr << "Error: " << e.what() << endl;
		success = 1;
	}
	return success;
}


string UrnaVirtuale::generaDigestSHA256(string data) {
	byte const* pbData = (byte*) data.data();
	unsigned int nDataLen = data.size();

	byte abDigest[CryptoPP::SHA256::DIGESTSIZE];

	CryptoPP::SHA256().CalculateDigest(abDigest, pbData, nDataLen);

	CryptoPP::HexEncoder encoder;
	std::string output;
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(abDigest, sizeof(abDigest));
	encoder.MessageEnd();

	return output;
}

bool UrnaVirtuale::checkDigestSHA256(string digest, string dataToCheck) {
	byte const* pbData = (byte*) dataToCheck.data();
	unsigned int nDataLen = dataToCheck.size();

	byte abDigest[CryptoPP::SHA256::DIGESTSIZE];

	CryptoPP::SHA256().CalculateDigest(abDigest, pbData, nDataLen);

	CryptoPP::HexEncoder encoder;
	std::string newDigest;
	encoder.Attach(new CryptoPP::StringSink(newDigest));
	encoder.Put(abDigest, sizeof(abDigest));
	encoder.MessageEnd();

	return (newDigest == digest);

}


CryptoPP::RSA::PrivateKey UrnaVirtuale::extractPrivatePemKey(const char * key_pem_filePath) {
	/*	string RSA_PRIV_KEY = "-----BEGIN RSA PRIVATE KEY-----\n"
	 "MIIBOgIBAAJBAK8Q+ToR4tWGshaKYRHKJ3ZmMUF6jjwCS/u1A8v1tFbQiVpBlxYB\n"
	 "paNcT2ENEXBGdmWqr8VwSl0NBIKyq4p0rhsCAQMCQHS1+3wL7I5ZzA8G62Exb6RE\n"
	 "INZRtCgBh/0jV91OeDnfQUc07SE6vs31J8m7qw/rxeB3E9h6oGi9IVRebVO+9zsC\n"
	 "IQDWb//KAzrSOo0P0yktnY57UF9Q3Y26rulWI6LqpsxZDwIhAND/cmlg7rUz34Pf\n"
	 "SmM61lJEmMEjKp8RB/xgghzmCeI1AiEAjvVVMVd8jCcItTdwyRO0UjWU4JOz0cnw\n"
	 "5BfB8cSIO18CIQCLVPbw60nOIpUClNxCJzmMLbsrbMcUtgVS6wFomVvsIwIhAK+A\n"
	 "YqT6WwsMW2On5l9di+RPzhDT1QdGyTI5eFNS+GxY\n"
	 "-----END RSA PRIVATE KEY-----";
	 */
	static string HEADER = "-----BEGIN RSA PRIVATE KEY-----";
	static string FOOTER = "-----END RSA PRIVATE KEY-----";
	//

	std::ifstream ifs(key_pem_filePath);
	std::string content((std::istreambuf_iterator<char>(ifs)),
			(std::istreambuf_iterator<char>()));

	//cout << content << endl;
	size_t pos1, pos2;
	pos1 = content.find(HEADER);
	if (pos1 == string::npos)
		throw runtime_error("PEM header not found");

	pos2 = content.find(FOOTER, pos1 + 1);
	if (pos2 == string::npos)
		throw runtime_error("PEM footer not found");

	// Start position and length
	pos1 = pos1 + HEADER.length();
	pos2 = pos2 - pos1;
	string keystr = content.substr(pos1, pos2);

	// Base64 decode, place in a ByteQueue
	ByteQueue queue;
	Base64Decoder decoder;

	decoder.Attach(new Redirector(queue));
	decoder.Put((const byte*) keystr.data(), keystr.length());
	decoder.MessageEnd();

	// Write to file for inspection
	FileSink fs("decoded-key.der");
	queue.CopyTo(fs);
	fs.MessageEnd();

	CryptoPP::RSA::PrivateKey rsaPrivate;
	try {

		rsaPrivate.BERDecodePrivateKey(queue, false /*paramsPresent*/,
				queue.MaxRetrievable());

		// BERDecodePrivateKey is a void function. Here's the only check
		// we have regarding the DER bytes consumed.
		if (!queue.IsEmpty()) {
			cerr << "errore: DER bytes not proper consumed" << endl;
			exit(1);
		}

		AutoSeededRandomPool prng;
		bool valid = rsaPrivate.Validate(prng, 3);
		if (!valid){
			cerr << "RSA private key is not valid" << endl;
		}
		cout << "RSA private key is valid" << endl;
		cout << "N:" << rsaPrivate.GetModulus() << endl;
		cout << "E:" << rsaPrivate.GetPublicExponent() << endl;
		cout << "D:" << rsaPrivate.GetPrivateExponent() << endl;

	} catch (const Exception& ex) {
		cerr << ex.what() << endl;
		exit(1);
	}
	return rsaPrivate;
}


string UrnaVirtuale::calcolaMAC(string encodedSessionKey, string plain){


	//"11A47EC4465DD95FCD393075E7D3C4EB";
	cout << "Session key: " << encodedSessionKey << endl;
	string decodedKey;
	StringSource (encodedSessionKey,true,
			new HexDecoder(
					new StringSink(decodedKey)
			) // HexDecoder
	); // StringSource

	SecByteBlock key(reinterpret_cast<const byte*>(decodedKey.data()), decodedKey.size());


	string macCalculated, encoded;

	/*********************************\
    \*********************************/

	// Pretty print key
	encoded.clear();
	StringSource(key, key.size(), true,
			new HexEncoder(
					new StringSink(encoded)
			) // HexEncoder
	); // StringSource
	cout << "key encoded: " << encoded << endl;

	cout << "plain text: " << plain << endl;

	/*********************************\
    \*********************************/

	try
	{
		CryptoPP::HMAC< CryptoPP::SHA256 > hmac(key, key.size());

		StringSource(plain, true,
				new HashFilter(hmac,
						new StringSink(macCalculated)
				) // HashFilter
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << "Caught exception :" << e.what() << endl;
	}

	/*********************************\
    \*********************************/

	//	// Pretty print MAC
	string macEncoded;
	StringSource(macCalculated, true,
			new HexEncoder(
					new StringSink(macEncoded)
			) // HexEncoder
	); // StringSource
	cout << "hmac encoded: " << macEncoded << endl;

	return macEncoded;
}

int UrnaVirtuale::verifyMAC(string encodedSessionKey,string data, string macEncoded){
	//restituisce 0 in caso di verifica positiva
	//restituisce 1 in caso di verifica negativa
	string decodedKey;
	int success = 1;
	cout << "Session key: " << encodedSessionKey << endl;

	StringSource (encodedSessionKey,true,
			new HexDecoder(
					new StringSink(decodedKey)
			) // HexDecoder
	); // StringSource

	SecByteBlock key(reinterpret_cast<const byte*>(decodedKey.data()), decodedKey.size());

	string macDecoded;
	StringSource(macEncoded, true,
			new HexDecoder(
					new StringSink(macDecoded)
			) // HexEncoder
	); // StringSource
	cout << "hmac decoded: " << macDecoded << endl;

	try
	{
		CryptoPP::HMAC< CryptoPP::SHA256 > hmac(key, key.size());
		const int flags = HashVerificationFilter::THROW_EXCEPTION | HashVerificationFilter::HASH_AT_END;


		StringSource(data + macDecoded, true,
				new HashVerificationFilter(hmac, NULL, flags)
		); // StringSource
		success = 0;
		cout << "Verified message" << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << "Caught exception :" << e.what() << endl;
	}
	return success;
}
bool UrnaVirtuale::checkScrutinioEseguito(uint idProcedura) {
	return model->isScrutinioEseguito(idProcedura);
}

bool UrnaVirtuale::getInfoMatricola(uint matricola, string& nome,
		string& cognome, uint& statoVoto) {
	return model->infoVotanteByMatricola(matricola,nome, cognome, statoVoto);
}

//bool UrnaVirtuale::updateVoted(uint matricola) {
//	return model->setVoted(matricola);
//}

bool UrnaVirtuale::resetMatricola(uint matricola) {
	return model->setNotVoted(matricola);
}

string UrnaVirtuale::getStringProcedure_formattedXML_byUsernameRP(
		string usernameRP) {


	uint idRP = model->getIdRPByUsername(usernameRP);
	if(idRP == 0){
		return "";
	}

	vector <ProceduraVoto> procedureRP;
	procedureRP = model->getProcedureRP(idRP);

	return procedureVotoRPtoXML(procedureRP);
}

string UrnaVirtuale::procedureVotoRPtoXML(
		vector<ProceduraVoto> pvs) {
	XMLDocument xmlDoc;
	XMLNode * pRoot = xmlDoc.NewElement("procedureVotoRP");
	xmlDoc.InsertFirstChild(pRoot);

	//per ogni procedura creiamo un nuovo elemento figlio di root e vi memorizziamo i dati al suo interno
	for (uint i = 0; i < pvs.size(); i++){
		//creiamo un nuovo elemento figlio di root
		XMLElement * pProcedura = xmlDoc.NewElement("procedura");
		pRoot->InsertEndChild(pProcedura);

		XMLElement * pElement;

		//aggiungiamo ad ogni nodo procedura i suoi dati dentro suoi elementi figli

		uint idProcedura = pvs.at(i).getIdProceduraVoto();
		pElement = xmlDoc.NewElement("id");
		pElement->SetText(idProcedura);
		pProcedura->InsertEndChild(pElement);

		string descrizione = pvs.at(i).getDescrizione();
		pElement = xmlDoc.NewElement("descrizione");
		pElement->SetText(descrizione.c_str());
		pProcedura->InsertEndChild(pElement);

		string dtInizio = pvs.at(i).getData_ora_inizio();
		pElement = xmlDoc.NewElement("inizio");
		pElement->SetText(dtInizio.c_str());
		pProcedura->InsertEndChild(pElement);

		string dtTermine = pvs.at(i).getData_ora_termine();
		pElement = xmlDoc.NewElement("fine");
		pElement->SetText(dtTermine.c_str());
		pProcedura->InsertEndChild(pElement);

		uint stato = pvs.at(i).getStato();
		pElement = xmlDoc.NewElement("stato");
		pElement->SetText(stato);
		pProcedura->InsertEndChild(pElement);
	}



	XMLPrinter printer;
	xmlDoc.Print( &printer );
	string xmlStringProcedureRP = printer.CStr();
	return xmlStringProcedureRP;
}

uint UrnaVirtuale::idRPByUsername(string username) {
	return model->getIdRPByUsername(username);
}

bool UrnaVirtuale::doScrutinio(uint idProcedura, string derivedKey) {
	uint idRP = model->getIdRPByProcedura(idProcedura);

	//ottengo la chiave privata di RP dal database (codificata esadecimale), la quale
	//è cifrata con la chiave simmetrica derivata dalla password di RP
	string encryptedPrivateKeyRP = model->getEncryptedPR_RP(idRP);
	cout << "chiave privata RP cifrata: " << encryptedPrivateKeyRP << endl;

	//iv di decifratura, uguale all'iv di cifratura sul sistema Tecnico!!
	byte iv[AES::BLOCKSIZE];
	memset(iv, 0x01,AES::BLOCKSIZE);
	std::string s_iv( reinterpret_cast< char const* >(iv) ) ;

	//derivedKey ricevuta dall'RP che ha richiesto lo scrutinio
	string decodedDerivedKey;
	StringSource(derivedKey,true,
			new HexDecoder(
					new StringSink(decodedDerivedKey)
			)
	);
	//mettiamola nella struttura SecByteBlock
	SecByteBlock key(reinterpret_cast<const byte*>(decodedDerivedKey.data()),decodedDerivedKey.size());

	string decodedPrivateKeyRP = AESdecryptStdString(encryptedPrivateKeyRP,key,iv);
	cout << "chiave privata RP decifrata: " << decodedPrivateKeyRP<< endl;

	;

	StringSource ss(decodedPrivateKeyRP,true /*pumpAll*/);
	RSA::PrivateKey privateKeyRP;
	privateKeyRP.Load(ss);

	//ottenere i pacchetti voto per la procedura
	vector <PacchettoVoto> pacchetti = model->getPacchettiVoto(idProcedura);
	cout << "Ottenuti dal DB i pacchetti per la procedura con id: " << idProcedura << endl;

	//per ogni pacchetto
	int pacchettiVerificati = 0;
	int pacchettiRifiutati = 0;
	int pacchettiEstratti = pacchetti.size();

	for(uint i=0; i< pacchetti.size();i++){
		//1.verificare la firma, quindi accettare o rifiutare un pacchetto
		string idSchedaCompilata ,schedaCifrata, kc, ivc, encodedSignature;
		uint nonce;
		uint idProcedura = pacchetti.at(i).getIdProcedura();

		idSchedaCompilata = pacchetti.at(i).getMacId();
		schedaCifrata = pacchetti.at(i).getSchedaCifrata();
		kc = pacchetti.at(i).getKc();
		ivc = pacchetti.at(i).getIvc();
		nonce = pacchetti.at(i).getNonce();
		encodedSignature = pacchetti.at(i).getEncodedSign();


		string dataToVerify = idSchedaCompilata + schedaCifrata + kc + ivc + std::to_string(nonce) + std::to_string(idProcedura);
		// visualizzazione dati di cui verificare la firma
		cout << "macId: " << idSchedaCompilata << endl;
		cout << "schedaCompilata: " << schedaCifrata << endl;
		cout << "kc: " <<kc << endl;
		cout << "ivc: " <<ivc << endl;
		cout << "nonce: " << nonce << endl;
		cout << "idProcedura: " << idProcedura << endl;

		//calcolo la firma
		int success = verifySignString_U(dataToVerify, encodedSignature);

		//se non è stato rifiutato
		if(success == 0){
			pacchettiVerificati++;
			//2. decifrare chiave simmetrica e iv del pacchetto di voto con la chiave privata di RP, RSA
			SecByteBlock k = RSADecrypt(kc, privateKeyRP);

			SecByteBlock iv = RSADecrypt(ivc, privateKeyRP);


			SchedaCompilata sc;
			//3. parsing della scheda di voto, viene decifrata e accetta se nonce decifrato è
			//uguale a quello presente in chiaro nel pacchetto di voto
			bool accepted = parseDecryptSchedaCifrata(schedaCifrata,k,iv,nonce,&sc);

			if(accepted){

				//4. conteggiare le preferenze


			}
		}
		else{
			//TODO verificare la presenza del pacchetto di voto con questo macID  sul database replicato e provare a verificare la firma
			pacchettiRifiutati++;
			cerr << "pacchetto "<< i+1 << " non verificato" << endl;
		}
	}

	if(pacchettiVerificati != pacchettiEstratti){
		cerr << "alcuni pacchetti non hanno superato la verifica della firma dell'urna" << endl;
		return false;
	}
	else{
		cout << pacchettiVerificati << " pacchetti verificati!" << endl;
	}
	//7. tutte le schede sono state scrutinate, creare un file xml in cui conservare queste informazioni
	//preferenze divise per seggio, per idScheda, per lista, per candidato
	//totale dei voti non distinti per seggio?


	//8. salvare file xml sul database e aggiornare lo stato della procedura su scrutinata

	return true;
}


void UrnaVirtuale::getPublicKeyFromCert(CryptoPP::BufferedTransformation & certin,
		CryptoPP::BufferedTransformation & keyout) {
	/**
	 * Reads an X.509 v3 certificate from certin, extracts the subjectPublicKeyInfo structure
	 * (which is one way PK_Verifiers can get their key material) and writes it to keyout
	 *
	 * @throws CryptoPP::BERDecodeError
	 */
	BERSequenceDecoder x509Cert(certin);
	BERSequenceDecoder tbsCert(x509Cert);

	// ASN.1 from RFC 3280
	// TBSCertificate  ::=  SEQUENCE  {
	// version         [0]  EXPLICIT Version DEFAULT v1,

	// consume the context tag on the version
	BERGeneralDecoder context(tbsCert, 0xa0);
	word32 ver;

	// only want a v3 cert
	BERDecodeUnsigned<word32>(context, ver, INTEGER, 2, 2);

	// serialNumber         CertificateSerialNumber,
	Integer serial;
	serial.BERDecode(tbsCert);

	// signature            AlgorithmIdentifier,
	BERSequenceDecoder signature(tbsCert);
	signature.SkipAll();

	// issuer               Name,
	BERSequenceDecoder issuerName(tbsCert);
	issuerName.SkipAll();

	// validity             Validity,
	BERSequenceDecoder validity(tbsCert);
	validity.SkipAll();

	// subject              Name,
	BERSequenceDecoder subjectName(tbsCert);
	subjectName.SkipAll();

	// subjectPublicKeyInfo SubjectPublicKeyInfo,
	BERSequenceDecoder spki(tbsCert);
	DERSequenceEncoder spkiEncoder(keyout);

	spki.CopyTo(spkiEncoder);
	spkiEncoder.MessageEnd();

	spki.SkipAll();
	tbsCert.SkipAll();
	x509Cert.SkipAll();
}

uint UrnaVirtuale::tryVote(uint matricola, uint &ruolo) {

	return model->tryLockAnagrafica(matricola,ruolo);
}



bool UrnaVirtuale::authenticateRP(string userid, string password){
	//ottengo dal database salt e hash della password del tecnico
	string storedSalt;
	string storedHashedPassword;
	model->userSaltAndPassword(userid, storedSalt,storedHashedPassword);


	string calculatedHashedPassword = hashPassword(password,storedSalt);

	if(calculatedHashedPassword==storedHashedPassword){
		return true;
	}
	else {
		return false;
	}
}

string UrnaVirtuale::hashPassword( string plainPass, string salt){

	//100 iterazioni
	uint iterations = 100;
	SecByteBlock result(32);
	string hexResult;

	PKCS5_PBKDF2_HMAC<SHA256> pbkdf;

	pbkdf.DeriveKey(result, result.size(),0x00,(byte *) plainPass.data(), plainPass.size(),(byte *) salt.data(), salt.size(),iterations);

	//ArraySource resultEncoder(result,result.size(), true, new HexEncoder(new StringSink(hexResult)));

	HexEncoder hex(new StringSink(hexResult));
	hex.Put(result.data(), result.size());
	hex.MessageEnd();

	return hexResult;

}



uint UrnaVirtuale::numSchedeCompilate(uint idProcedura) {
	return model->getNumberSchedeCompilate(idProcedura);
}



void UrnaVirtuale::setVoted(uint matricola) {
	modelPacchetti->votedNotCommit(matricola);
}

void UrnaVirtuale::storePacchettiVoto(vector<PacchettoVoto> pacchetti) {
	for (uint i = 0; i< pacchetti.size(); i++){
		string idSchedaCompilata ,schedaCifrata, kc, ivc;
		uint nonce;
		uint idProcedura = this->getIdProceduraCorrente();

		idSchedaCompilata = pacchetti.at(i).getMacId();
		schedaCifrata = pacchetti.at(i).getSchedaCifrata();
		kc = pacchetti.at(i).getKc();
		ivc = pacchetti.at(i).getIvc();
		nonce = pacchetti.at(i).getNonce();


		string dataToStore = idSchedaCompilata + schedaCifrata + kc + ivc + std::to_string(nonce) + std::to_string(idProcedura);
		// visualizzazione dati da firmare
		cout << "macId: " << idSchedaCompilata << endl;
		cout << "schedaCompilata" << schedaCifrata << endl;
		cout << "kc: " <<kc << endl;
		cout << "ivc: " <<ivc << endl;
		cout << "nonce: " << nonce << endl;
		cout << "idProcedura: " << idProcedura << endl;

		//calcolo la firma
		string encodedSignature = signString_U(dataToStore);

		//setto i valori mancanti al pacchetto di voto corrente
		pacchetti.at(i).setIdProcedura(idProcedura);
		pacchetti.at(i).setEncodedSign(encodedSignature);

	}
	modelPacchetti->storePacchettiSignedNoCommit(pacchetti);

}

void UrnaVirtuale::savePacchetti()
{
	modelPacchetti->myCommit();

}

void UrnaVirtuale::discardPacchetti()
{
	modelPacchetti->myRollback();
}

SecByteBlock UrnaVirtuale::RSADecrypt(string encodedCipher,CryptoPP::RSA::PrivateKey privateKey) {
	//funzione per decifrare chiave e iv che servono per decifrare le componenti del pacchetto di voto
	////////////////////////////////////////////////

	string decodedCipher;
	StringSource(encodedCipher,true,
			new HexDecoder(
					new StringSink(decodedCipher)
			)//HexDecoder
	);//StringSource

	cout << "decodedCipher:" << decodedCipher << endl;

	AutoSeededRandomPool rng;
	string recovered;
	try{
		// Decryption
		RSAES_OAEP_SHA_Decryptor rsaDecryptor( privateKey );

		StringSource( decodedCipher, true,
				new PK_DecryptorFilter( rng, rsaDecryptor,
						new StringSink( recovered )
				) // PK_EncryptorFilter
		); // StringSource
		cout << "Recovered: " << recovered << endl;


	}
	catch( CryptoPP::Exception& e )
	{
		cerr << "Caught Exception..." << endl;
		cerr << e.what() << endl;
	}
	SecByteBlock recoveredKey(reinterpret_cast<const byte*>(recovered.data()), recovered.size());

	string encoded;
	StringSource (recovered,true,
			new HexEncoder(
					new StringSink(encoded)
			)
	);
	cout << "recovered:" << encoded;

	return recoveredKey;
}

string UrnaVirtuale::AESdecryptStdString(string encodedCipher, SecByteBlock key, byte* iv){
	string encoded,recovered;
	encoded.clear();
	StringSource(key, key.size(), true,
			new HexEncoder(
					new StringSink(encoded)
			) // HexEncoder
	); // StringSource
	cout << "key: " << encoded << endl;

	// Pretty print iv
	encoded.clear();
	std::string s_iv( reinterpret_cast< char const* >(iv) ) ;
	StringSource(s_iv, true,
			new HexEncoder(
					new StringSink(encoded)
			) // HexEncoder
	); // StringSource
	cout << "iv: " << encoded << endl;

	//decodifichiamo il testo cifrato
	string decodedCipher;
	StringSource(encodedCipher,true,
			new HexDecoder(new StringSink(decodedCipher)
			)//HexDecoder
	);//StringSource

	try
	{

		CBC_Mode< AES >::Decryption aesDecryptor;
		aesDecryptor.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource (decodedCipher, true,
				new StreamTransformationFilter(aesDecryptor,
						new StringSink(recovered)
				) // StreamTransformationFilter
		); // StringSource

		cout << "recovered text: " << recovered << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << "Caught exception :" << e.what() << endl;
	}
	return recovered;
}

string UrnaVirtuale::AESdecryptStdString(string encodedCipher, SecByteBlock key, SecByteBlock iv){
	string encoded,recovered;
	encoded.clear();
	StringSource(key, key.size(), true,
			new HexEncoder(
					new StringSink(encoded)
			) // HexEncoder
	); // StringSource
	cout << "key: " << encoded << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv,iv.size(),true,
			new HexEncoder(
					new StringSink(encoded)
			) // HexEncoder
	); // StringSource
	cout << "iv: " << encoded << endl;

	//decodifichiamo il testo cifrato
	string decodedCipher;
	StringSource(encodedCipher,true,
			new HexDecoder(new StringSink(decodedCipher)
			)//HexDecoder
	);//StringSource

	try{

		CBC_Mode< AES >::Decryption aesDecryptor;
		aesDecryptor.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource (decodedCipher, true,
				new StreamTransformationFilter(aesDecryptor,
						new StringSink(recovered)
				) // StreamTransformationFilter
		); // StringSource

		cout << "recovered text: " << recovered << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << "Caught exception :" << e.what() << endl;
	}
	return recovered;
}

bool UrnaVirtuale::parseDecryptSchedaCifrata(string schedaCifrata,
		SecByteBlock k, SecByteBlock iv, uint nonce, SchedaCompilata *sc) {

	//3. usare chiave simmetrica e iv per decifrare l'nonce cifrato presente sulla scheda,
	//se l'nonce è uguale all'nonce in chiaro del pacchetto, questo viene accettato
	//si decifrano i campi matricolaPreferenza della scheda cifrata, così da riottenere i campi in chiaro
	//anche le altre informazioni in chiaro vengono salvate sulla scheda compilata
	XMLDocument xmlDoc;
	xmlDoc.Parse(schedaCifrata.c_str());
	XMLNode *rootNode = xmlDoc.FirstChild();

	XMLText * textNodeNonce = rootNode->FirstChildElement("nonce")->FirstChild()->ToText();
	string encodedCryptedNonce = textNodeNonce->Value();
	string nonceDecryptedStr = this->AESdecryptStdString(encodedCryptedNonce,k,iv);
	uint nonceDecrypted = atoi(nonceDecryptedStr.c_str());

	//se l'noncein chiaro non corrisponde con quello decifrato, si tratta di un pacchetto di voto
	//soggetto ad attacco di replay, il pacchetto va rifiutato
	if(nonce != nonceDecrypted){
		return false;
	}
	else{
		sc->setNonce(nonceDecrypted);



		XMLText * textNodeIdScheda = rootNode->FirstChildElement("idScheda")->FirstChild()->ToText();
		uint idScheda = atoi(textNodeIdScheda->Value());
		sc->setIdScheda(idScheda);

		//XMLText * textNodeIdSeggio = rootNode->FirstChildElement("idSeggio")->FirstChild()->ToText();
		//uint idSeggio = atoi(textNodeIdSeggio->Value());
		sc->setIdSeggio(1);

		XMLText * textNodeIdProcedura = rootNode->FirstChildElement("idProcedura")->FirstChild()->ToText();
		uint idProcedura = atoi(textNodeIdProcedura->Value());
		sc->setIdProcedura(idProcedura);

		XMLText * textNodeNumeroPreferenze = rootNode->FirstChildElement("numeroPreferenze")->FirstChild()->ToText();
		uint numeroPreferenze = atoi(textNodeNumeroPreferenze->Value());
		sc->setNumPreferenze(numeroPreferenze);

		XMLText * textNodeTipologiaElezione = rootNode->FirstChildElement("tipologiaElezione")->FirstChild()->ToText();
		uint tipologiaElezione = atoi(textNodeTipologiaElezione->Value());
		sc->setTipologiaElezione(tipologiaElezione);

		XMLNode* preferenzeNode = rootNode->FirstChildElement("preferenze");
		//primo e ultimo elemento procedura
		XMLElement * firstMatricolaElement = preferenzeNode->FirstChildElement("matricolaCandidato");
		XMLElement * lastMatricolaElement = preferenzeNode->LastChildElement("matricolaCandidato");

		XMLElement *matricolaElement = firstMatricolaElement;
		bool lastMatricola = false;
		do{
			XMLText * textNodeMatricola = matricolaElement->FirstChild()->ToText();
			string encryptedMatricola = textNodeMatricola->Value();
			string matricolaPreferenza = this->AESdecryptStdString(encryptedMatricola,k,iv);
			sc->addMatricolaPreferenza(matricolaPreferenza);

			if(matricolaElement == lastMatricolaElement){
				lastMatricola = true;
			}
			else{
				//accediamo alla successiva procedura
				matricolaElement = matricolaElement->NextSiblingElement("matricolaCandidato");
				cout << "ottengo il puntatore alla successiva matricola" << endl;
			}
		}while(!lastMatricola);
		cout << "non ci sono altre matricole preferenza da estrarre" << endl;

	}
	return true;
}
