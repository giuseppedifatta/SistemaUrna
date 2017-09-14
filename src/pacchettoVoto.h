/*
 * pacchettoVoto.h
 *
 *  Created on: 14/set/2017
 *      Author: giuseppe
 */

#ifndef PACCHETTOVOTO_H_
#define PACCHETTOVOTO_H_
#include <string>

using namespace std;

class PacchettoVoto {
public:
	PacchettoVoto();
	virtual ~PacchettoVoto();
	const string& getIvc() const;
	void setIvc(const string& ivc);
	const string& getKc() const;
	void setKc(const string& kc);
	const string& getMacId() const;
	void setMacId(const string& macId);
	uint getNonce() const;
	void setNonce(uint nonce);
	const string& getSchedaCifrata() const;
	void setSchedaCifrata(const string& schedaCifrata);

	uint getIdProcedura() const;
	void setIdProcedura(uint idProcedura);
	const string& getEncodedSign() const;
	void setEncodedSign(const string& encodedSign);

private:
	string schedaCifrata;
	string KC;
	string IVC;
	uint nonce;
	string macID;
	string encodedSign;
	uint idProcedura;
};

#endif /* PACCHETTOVOTO_H_ */
