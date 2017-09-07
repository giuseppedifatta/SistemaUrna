/*
 * RSA-PSS_utils.h
 *
 *  Created on: 10/mag/2017
 *      Author: giuseppe
 */

#ifndef RSA_PSS_UTILS_H_
#define RSA_PSS_UTILS_H_
#include "cryptopp/rsa.h"
#include "cryptopp/pssr.h"
#include "cryptopp/sha.h"
#include "cryptopp/files.h"
#include "cryptopp/filters.h"
#include "cryptopp/osrng.h"
#include "cryptopp/secblock.h"
#include "cryptopp/hex.h"
#include "cryptopp/base64.h"
using namespace CryptoPP;



#include <string>
#include <stdexcept>
#include <iostream>
#include <fstream>

using namespace std;

void SavePrivateKey(const string& filename, const PrivateKey& key);
void SavePublicKey(const string& filename, const PublicKey& key);

void SaveBase64PrivateKey(const string& filename, const PrivateKey& key);
void SaveBase64PublicKey(const string& filename, const PublicKey& key);

void SaveBase64(const string& filename, const BufferedTransformation& bt);
void Save(const string& filename, const BufferedTransformation& bt);

void SaveHexPrivateKey(const string& filename, const PrivateKey& key);
void SaveHexPublicKey(const string& filename, const PublicKey& key);
void SaveHex(const string& filename, const BufferedTransformation& bt);

void LoadHexPrivateKey(const string& filename, const PrivateKey& key);
void LoadHexPublicKey(const string& filename, const PublicKey& key);
void LoadHex(const string& filename, const BufferedTransformation& bt);

void LoadPrivateKey(const string& filename, PrivateKey& key);
void LoadPublicKey(const string& filename, PublicKey& key);

void LoadBase64PrivateKey(const string& filename, PrivateKey& key);
void LoadBase64PublicKey(const string& filename, PublicKey& key);

void LoadBase64(const string& filename, BufferedTransformation& bt);
void Load(const string& filename, BufferedTransformation& bt);


void SavePrivateKey(const string& filename, const PrivateKey& key) {
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void SavePublicKey(const string& filename, const PublicKey& key) {
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void Save(const string& filename, const BufferedTransformation& bt) {
	// http://www.cryptopp.com/docs/ref/class_file_sink.html
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}

void SaveBase64PrivateKey(const string& filename, const PrivateKey& key) {
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	SaveBase64(filename, queue);
}

void SaveBase64PublicKey(const string& filename, const PublicKey& key) {
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	SaveBase64(filename, queue);
}

void SaveBase64(const string& filename, const BufferedTransformation& bt) {
	// http://www.cryptopp.com/docs/ref/class_base64_encoder.html
	Base64Encoder encoder;

	bt.CopyTo(encoder);
	encoder.MessageEnd();

	Save(filename, encoder);
}
//Finally, the hex encoded implementations would be as follows.
void SaveHexPrivateKey(const string& filename, const PrivateKey& key) {
	ByteQueue queue;
	key.Save(queue);

	SaveHex(filename, queue);
}

void SaveHexPublicKey(const string& filename, const PublicKey& key) {
	ByteQueue queue;
	key.Save(queue);

	SaveHex(filename, queue);
}

void SaveHex(const string& filename, const BufferedTransformation& bt) {
	HexEncoder encoder;

	bt.CopyTo(encoder);
	encoder.MessageEnd();

	Save(filename, encoder);
}

void LoadPrivateKey(const string& filename, PrivateKey& key) {
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);
}

void LoadPublicKey(const string& filename, PublicKey& key) {
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);
}

void Load(const string& filename, BufferedTransformation& bt) {
	// http://www.cryptopp.com/docs/ref/class_file_source.html
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}

void LoadBase64PrivateKey(const string& filename, PrivateKey& key) {
	ByteQueue queue;

	LoadBase64(filename, queue);
	key.Load(queue);
}

void LoadBase64PublicKey(const string& filename, PublicKey& key) {
	ByteQueue queue;

	LoadBase64(filename, queue);
	key.Load(queue);
}

void LoadBase64(const string& filename, BufferedTransformation& bt) {
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}

void LoadHex(const string& filename, BufferedTransformation& bt) {
	//trasferisce i dati del file in ingresso su un buffer trasformation
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();

}

void LoadHexPrivateKey(const string& filename, PrivateKey& key) {
	//crea un buffer di supporto
	ByteQueue queue;
	//riempie il buffer con il file indicato
	LoadHex(filename,queue);

	//carica il contenuto del buffer sulla struttura key
	key.Load(queue);

}
void LoadHexPublicKey(const string& filename, PublicKey& key) {
	ByteQueue queue;

	LoadHex(filename,queue);
	key.Load(queue);

}


#endif /* RSA_PSS_UTILS_H_ */
