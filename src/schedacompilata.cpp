#include "schedacompilata.h"

SchedaCompilata::SchedaCompilata()
{
    idProcedura = 0;
    idScheda = 0;
    idSeggio  = 0;
    nonce = 0;
    numPreferenze = 0;

}

uint SchedaCompilata::getNonce() const
{
    return nonce;
}

void SchedaCompilata::setNonce(const uint &value)
{
    nonce = value;
}

uint SchedaCompilata::getIdProcedura() const
{
    return idProcedura;
}

void SchedaCompilata::setIdProcedura(const uint &value)
{
    idProcedura = value;
}

uint SchedaCompilata::getNumPreferenze() const
{
    return numPreferenze;
}

void SchedaCompilata::setNumPreferenze(const uint &value)
{
    numPreferenze = value;
}

void SchedaCompilata::addMatricolaPreferenza(string matricolaPreferenza)
{	//uint matricola = atoi(matricolaPreferenza.c_str());
    matricolePreferenze.push_back(matricolaPreferenza);
}

vector<string> SchedaCompilata::getMatricolePreferenze() const
{
    return matricolePreferenze;
}

uint SchedaCompilata::getIdScheda() const
{
    return idScheda;
}

uint SchedaCompilata::getIdSeggio() const {
	return idSeggio;
}

const string& SchedaCompilata::getDescrizioneElezione() const {
	return descrizioneElezione;
}

void SchedaCompilata::setDescrizioneElezione(
		const string& descrizioneElezione) {
	this->descrizioneElezione = descrizioneElezione;
}

void SchedaCompilata::setMatricolePreferenze(
		const vector<string>& matricolePreferenze) {
	this->matricolePreferenze = matricolePreferenze;
}

void SchedaCompilata::setIdSeggio(uint idSeggio) {
	this->idSeggio = idSeggio;
}


void SchedaCompilata::setIdScheda(const uint &value)
{
    idScheda = value;
}


