#ifndef SESSIONEVOTO_H
#define SESSIONEVOTO_H
#include <string>
using namespace std;
class SessioneVoto
{
public:
    SessioneVoto();


    string getOraApertura() const;
    void setOraApertura(const string &value);

    string getOraChiusura() const;
    void setOraChiusura(const string &value);

    string getData() const;
    void setData(const string &value);

    uint getIdSessione() const;
    void setIdSessione(const uint &value);

private:
    string oraApertura;
    string oraChiusura;
    string data;
    uint idSessione;
};

#endif // SESSIONEVOTO_H
