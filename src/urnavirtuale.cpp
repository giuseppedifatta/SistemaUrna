/*
 * urnavirtuale.cpp
 *
 *  Created on: 03/ago/2017
 *      Author: giuseppe
 */

#include "urnavirtuale.h"

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
			) // HexEncoder
	); // StringSource
	cout << "hmac encoded: " << macDecoded << endl;

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
		exit(1);
	}
	return success;
}
