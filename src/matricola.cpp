/*
 * matricola.cpp
 *
 *  Created on: 17/set/2017
 *      Author: giuseppe
 */

#include "matricola.h"

Matricola::Matricola() {
	// TODO Auto-generated constructor stub
	id = 0;
	numVoti = 0;
}

Matricola::~Matricola() {
	// TODO Auto-generated destructor stub
}

unsigned int Matricola::getId() const {
	return id;
}

void Matricola::setId(unsigned int id) {
	this->id = id;
}

Matricola::Matricola(unsigned int id) {
	this->id = id;
	numVoti = 0;
}

unsigned int Matricola::getNumVoti() const {
	return numVoti;
}

void Matricola::incVoti() {
	numVoti++;
}
