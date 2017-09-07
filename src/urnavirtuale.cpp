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
	cout << "richiedo al model le schede per la procedura: " << idProcedura << endl;
	return model->getSchedeVoto(idProcedura);
}

string UrnaVirtuale::getPublicKeyRP(uint idProceduraCorrente){
	return model->getPublicKeyRP(idProceduraCorrente);
}


int UrnaVirtuale::verifyMAC(string encodedSessionKey,string data, string macEncoded){
	//chiamata all'interno del thread che sta offrendo il servizio
	int success = 0;
	cout << "Dati da verificare: " << data << endl;
	cout << "mac da verificare: " << macEncoded << endl;

	string decodedKey;
	cout << "Session key: " << encodedSessionKey << endl;

	StringSource (encodedSessionKey,true,
			new HexDecoder(
					new StringSink(decodedKey)
			) // HexDecoder
	); // StringSource

	SecByteBlock key2(reinterpret_cast<const byte*>(decodedKey.data()), decodedKey.size());

	string macDecoded;
	StringSource(macEncoded, true,
			new HexDecoder(
					new StringSink(macDecoded)
			) // HexDecoder
	); // StringSource
	cout << "hmac decoded: " << macDecoded << endl;

	try
	{
		HMAC< SHA256 > hmac(key2, key2.size());
		const int flags = HashVerificationFilter::THROW_EXCEPTION | HashVerificationFilter::HASH_AT_END;

		StringSource(data + macDecoded, true,
				new HashVerificationFilter(hmac, NULL, flags)
		); // StringSource

		cout << "Verified message" << endl;
		success = 0;
	}
	catch(const CryptoPP::Exception& e)
	{
		success = 1;
		cerr << e.what() << endl;
	}
	return success;
}

bool UrnaVirtuale::checkMACasUniqueID(string macPacchettoVoto) {
	return model->uniqueIDSchedaCompilata(macPacchettoVoto);
}

bool UrnaVirtuale::storePacchettoVoto(string idSchedaCompilata,
		string schedaCifrata, string kc, string ivc, uint nonce) {
	uint idProcedura = this->getIdProceduraCorrente();
	string dataToStore = idSchedaCompilata + schedaCifrata + kc + ivc + std::to_string(nonce) + std::to_string(idProcedura);
	//TODO firmare pacchetto di voto

	string encodedSignature = signString_U(dataToStore);

	//chiedere al model di memorizzare il pacchetto di voto sul database
	return model->storeVotoFirmato_U(idSchedaCompilata,schedaCifrata,kc,ivc,nonce, encodedSignature, idProcedura);
}

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
	int success = 1;
	string signature;
	StringSource(signature,true,
			new HexEncoder(
					new StringSink(encodedSignature)
			)//HexEncoder
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
		success = 0;
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


CryptoPP::RSA::PrivateKey UrnaVirtuale::extractPrivatePemKey(const char * key_pem) {
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

	std::ifstream ifs(key_pem);
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
		if (!valid)
			cerr << "RSA private key is not valid" << endl;

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

string UrnaVirtuale::calcolaMAC(string encodedSessionKey, string plainText) {
	//chiamata all'interno del thread che sta offrendo il servizio

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

	cout << "plain text: " << plainText << endl;

	/*********************************\
	    \*********************************/

	try
	{
		CryptoPP::HMAC< CryptoPP::SHA256 > hmac(key, key.size());

		StringSource(plainText, true,
				new HashFilter(hmac,
						new StringSink(macCalculated)
				) // HashFilter
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;

	}

	/*********************************\
	    \*********************************/

	// Pretty print MAC
	string macEncoded;
	StringSource(macCalculated, true,
			new HexEncoder(
					new StringSink(macEncoded)
			) // HexEncoder
	); // StringSource
	cout << "hmac encoded: " << macEncoded << endl;

	verifyMAC(encodedSessionKey,plainText, macEncoded);

	return macEncoded;
}

bool UrnaVirtuale::checkScrutinioEseguito(uint idProcedura) {
	return model->isScrutinioEseguito(idProcedura);
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


