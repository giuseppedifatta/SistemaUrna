#include "proceduravoto.h"
#include <iostream>
using namespace std;

ProceduraVoto::ProceduraVoto()
{
    this->data_ora_inizio = "";
    this->data_ora_termine = "";
}

string ProceduraVoto::getDescrizione() const
{
    return descrizione;
}

void ProceduraVoto::setDescrizione(const string &value)
{
    descrizione = value;
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

string ProceduraVoto::getData_ora_inizio() const
{
    return data_ora_inizio;
}

void ProceduraVoto::setData_ora_inizio(const string &value)
{
    data_ora_inizio = value;
}

string ProceduraVoto::getData_ora_termine() const
{
    return data_ora_termine;
}

void ProceduraVoto::setData_ora_termine(const string &value)
{
    data_ora_termine = value;
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

string ProceduraVoto::getInfoRP(uint idRP)
{   string infoRP;
    if(rps.empty()){
        return "";
    }
    else{
        for(unsigned int i = 0; i< rps.size(); i++){
            string nome,cognome,data,luogo;
            if(rps.at(i).getIdRP() == idRP){
                nome = rps.at(i).getNome();
                cognome = rps.at(i).getCognome();
                data = rps.at(i).getDataNascita();
                luogo = rps.at(i).getLuogoNascita();
                infoRP =  nome + " " + cognome + ", " + luogo + ", " + data;
                break;
            }
        }
    }
    return infoRP;
}

vector<ResponsabileProcedimento> ProceduraVoto::getRps() const
{
    return rps;
}

void ProceduraVoto::setRps(const vector<ResponsabileProcedimento> &value)
{
    rps = value;
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


