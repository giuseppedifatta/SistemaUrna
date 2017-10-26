/*
 * hardwaretoke.cpp
 *
 *  Created on: 01/ott/2017
 *      Author: giuseppe
 */

#include "hardwaretoken.h"

HardwareToken::HardwareToken()
{

}

const string& HardwareToken::getPassword() const {
	return password;
}

void HardwareToken::setPassword(const string& password) {
	this->password = password;
}

const string& HardwareToken::getSn() const {
	return SN;
}

void HardwareToken::setSn(const string& sn) {
	SN = sn;
}

const string& HardwareToken::getUsername() const {
	return username;
}

void HardwareToken::setUsername(const string& username) {
	this->username = username;
}
