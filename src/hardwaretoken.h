/*
 * hardwaretoken.h
 *
 *  Created on: 01/ott/2017
 *      Author: giuseppe
 */

#ifndef HARDWARETOKEN_H
#define HARDWARETOKEN_H
#include <string>
using namespace std;
class HardwareToken
{
public:
    HardwareToken();
	const string& getPassword() const;
	void setPassword(const string& password);
	const string& getSn() const;
	void setSn(const string& sn);
	const string& getUsername() const;
	void setUsername(const string& username);

private:
    string SN;
    string username;
    string password;


};

#endif // HARDWARETOKEN_H
