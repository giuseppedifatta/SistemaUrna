#ifndef SCHEDACOMPILATA_H
#define SCHEDACOMPILATA_H
#include <string>
#include <vector>
using namespace std;
class SchedaCompilata
{
private:
    uint nonce;
    vector <uint> matricolePreferenze;
    uint idProcedura;
    uint numPreferenze;
    uint idScheda;
    uint tipologiaElezione;
    uint idSeggio;

public:
    SchedaCompilata();
    uint getNonce() const;
    void setNonce(const uint &value);
    uint getIdProcedura() const;
    void setIdProcedura(const uint &value);
    uint getNumPreferenze() const;
    void setNumPreferenze(const uint &value);
    uint getTipologiaElezione() const;
    void setTipologiaElezione(const uint &value);
    void addMatricolaPreferenza(string matricolaPreferenza);
    vector<uint> getMatricolePreferenze() const;
    uint getIdScheda() const;
    void setIdScheda(const uint &value);
	uint getIdSeggio() const;
	void setIdSeggio(uint idSeggio);

};

#endif // SCHEDACOMPILATA_H
