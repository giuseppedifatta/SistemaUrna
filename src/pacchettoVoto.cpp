/*
 * pacchettoVoto.cpp
 *
 *  Created on: 14/set/2017
 *      Author: giuseppe
 */

#include "pacchettoVoto.h"

PacchettoVoto::PacchettoVoto() {
	// TODO Auto-generated constructor stub

	nonce = 0;
	idProcedura = 0;


}

PacchettoVoto::~PacchettoVoto() {
	// TODO Auto-generated destructor stub
}

const string& PacchettoVoto::getEncodedSign() const {
	return encodedSign;
}

void PacchettoVoto::setEncodedSign(const string& encodedSign) {
	this->encodedSign = encodedSign;
}

uint PacchettoVoto::getIdProcedura() const {
	return idProcedura;
}

void PacchettoVoto::setIdProcedura(uint idProcedura) {
	this->idProcedura = idProcedura;
}

const string& PacchettoVoto::getIvc() const {
	return IVC;
}

void PacchettoVoto::setIvc(const string& ivc) {
	IVC = ivc;
}

const string& PacchettoVoto::getKc() const {
	return KC;
}

void PacchettoVoto::setKc(const string& kc) {
	KC = kc;
}

const string& PacchettoVoto::getMacId() const {
	return macID;
}

void PacchettoVoto::setMacId(const string& macId) {
	macID = macId;
}

uint PacchettoVoto::getNonce() const {
	return nonce;
}

void PacchettoVoto::setNonce(uint nonce) {
	this->nonce = nonce;
}

const string& PacchettoVoto::getSchedaCifrata() const {
	return schedaCifrata;
}

void PacchettoVoto::setSchedaCifrata(const string& schedaCifrata) {
	this->schedaCifrata = schedaCifrata;
}
