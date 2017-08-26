#ifndef PROCEDURAVOTO_H
#define PROCEDURAVOTO_H
#include <string>
#include <vector>
#include "sessionevoto.h"
#include "responsabileprocedimento.h"
#include <QtCore>

using namespace std;
class ProceduraVoto
{
public:
    ProceduraVoto();

    string getDescrizione() const;
    void setDescrizione(const string &value);

    uint getNumSchedeVoto() const;
    void setNumSchedeVoto(const uint &value);

    uint getIdRP() const;
    void setIdRP(const uint &value);

    string getData_ora_inizio() const;
    void setData_ora_inizio(const string &value);

    string getData_ora_termine() const;
    void setData_ora_termine(const string &value);

    void addSessione(SessioneVoto *sessione);
    vector<SessioneVoto> getSessioni() const;
    void resetSessioni();
    void removeSessioneByIndex(int index);
    string getInfoRP(uint idRP);
    vector<ResponsabileProcedimento> getRps() const;
    void setRps(const vector<ResponsabileProcedimento> &value);

    uint getIdProceduraVoto() const;
    void setIdProceduraVoto(const uint &value);

    uint getSchedeInserite() const;
    void setSchedeInserite(const uint &value);

    enum statiProcedura{
        creazione,
        programmata,
        in_corso,
        conclusa,
        scrutinata,
        undefined
    };

    statiProcedura getStato() const;
    void setStato(const statiProcedura &value);
    static string getStatoAsString(statiProcedura stato);
    static statiProcedura getStatoFromString(string stato);

private:
    string descrizione;
    uint numSchedeVoto;
    uint schedeInserite;
    statiProcedura stato;
    uint idRP;
    string data_ora_inizio;
    string data_ora_termine;
    vector <SessioneVoto> sessioni;
    vector <ResponsabileProcedimento> rps;
    uint idProceduraVoto;


};
Q_DECLARE_METATYPE(ProceduraVoto)
#endif // PROCEDURAVOTO_H
