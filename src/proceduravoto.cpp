#include "proceduravoto.h"
#include <iostream>
using namespace std;

ProceduraVoto::ProceduraVoto()
{
	this->data_ora_inizio = "";
	this->data_ora_termine = "";
	this->idRP = 0;
	this->idProceduraVoto = 0;
	this->descrizione = "";
	this->numSchedeVoto = 0;
	this->schedeInserite = 0;
	this->stato = ProceduraVoto::statiProcedura::undefined;
}

uint ProceduraVoto::getNumSchedeVoto() const
{
	return numSchedeVoto;
}

void ProceduraVoto::setNumSchedeVoto(const uint &value)
{
	numSchedeVoto = value;
}

uint ProceduraVoto::getIdRP() const
{
	return idRP;
}

void ProceduraVoto::setIdRP(const uint &value)
{
	idRP = value;
}



void ProceduraVoto::addSessione(SessioneVoto *sessione)
{
	sessioni.push_back(*sessione);
}

vector<SessioneVoto> ProceduraVoto::getSessioni() const
{
	return sessioni;
}

void ProceduraVoto::resetSessioni()
{
	sessioni.clear();
}

void ProceduraVoto::removeSessioneByIndex(int index)
{
	this->sessioni.erase(sessioni.begin()+index);
}

uint ProceduraVoto::getIdProceduraVoto() const
{
	return idProceduraVoto;
}

void ProceduraVoto::setIdProceduraVoto(const uint &value)
{
	idProceduraVoto = value;
}

uint ProceduraVoto::getSchedeInserite() const
{
	return schedeInserite;
}

void ProceduraVoto::setSchedeInserite(const uint &value)
{
	schedeInserite = value;
}

ProceduraVoto::statiProcedura ProceduraVoto::getStato() const
{
	return stato;
}

void ProceduraVoto::setStato(const statiProcedura &value)
{
	stato = value;
}


string ProceduraVoto::getStatoAsString(ProceduraVoto::statiProcedura stato)
{
	string statoAsString;
	switch(stato){
	case creazione:
		statoAsString = "creazione";
		break;
	case programmata:
		statoAsString = "programmata";
		break;
	case in_corso:
		statoAsString = "in corso";
		break;
	case conclusa:
		statoAsString = "conclusa";
		break;
	case scrutinata:
		statoAsString = "scrutinata";
		break;
	case da_eliminare:
		statoAsString = "da eliminare";
		break;
	case undefined:
		statoAsString = "undefined";
		break;
	}

	return statoAsString;
}


ProceduraVoto::statiProcedura ProceduraVoto::getStatoFromString(string stato)
{
	if(stato == "creazione"){
		return statiProcedura::creazione;
	}
	if(stato == "programmata"){
		return statiProcedura::programmata;
	}
	if(stato == "in corso"){
		return statiProcedura::in_corso;
	}
	if(stato == "conclusa"){
		return statiProcedura::conclusa;
	}
	if(stato == "scrutinata"){
		return statiProcedura::scrutinata;
	}
	else{
		return statiProcedura::undefined;
	}
}

void ProceduraVoto::setStato(const uint &stato){

	switch(stato){
	case ProceduraVoto::statiProcedura::creazione:
		this->stato =  ProceduraVoto::statiProcedura::creazione;
		break;
	case ProceduraVoto::statiProcedura::programmata:
		this->stato =  ProceduraVoto::statiProcedura::programmata;
		break;
	case ProceduraVoto::statiProcedura::in_corso:
		this->stato =  ProceduraVoto::statiProcedura::in_corso;
		break;
	case ProceduraVoto::statiProcedura::conclusa:
		this->stato =  ProceduraVoto::statiProcedura::conclusa;
		break;
	case ProceduraVoto::statiProcedura::scrutinata:
		this->stato =  ProceduraVoto::statiProcedura::scrutinata;
		break;
	case ProceduraVoto::statiProcedura::da_eliminare:
		this->stato =  ProceduraVoto::statiProcedura::da_eliminare;
		break;

	default:
		this->stato =  ProceduraVoto::statiProcedura::undefined;
		break;


	}

}

const string& ProceduraVoto::getDataOraInizio() const {
	return data_ora_inizio;
}

void ProceduraVoto::setDataOraInizio(const string& dataOraInizio) {
	data_ora_inizio = dataOraInizio;
}

const string& ProceduraVoto::getDataOraTermine() const {
	return data_ora_termine;
}

void ProceduraVoto::setDataOraTermine(const string& dataOraTermine) {
	data_ora_termine = dataOraTermine;
}

uint ProceduraVoto::getIdRp() const {
	return idRP;
}

void ProceduraVoto::setIdRp(uint idRp) {
	idRP = idRp;
}

const string& ProceduraVoto::getDescrizione() const {
	return descrizione;
}

void ProceduraVoto::setDescrizione(const string& descrizione) {
	this->descrizione = descrizione;
}
