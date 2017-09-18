/*
 * matricola.h
 *
 *  Created on: 17/set/2017
 *      Author: giuseppe
 */

#ifndef MATRICOLA_H_
#define MATRICOLA_H_

class Matricola {
public:
	Matricola();
	Matricola(unsigned int id);
	virtual ~Matricola();
	unsigned int getId() const;
	void setId(unsigned int id);
	unsigned int getNumVoti() const;
	void incVoti();
private:
	unsigned int id;
	unsigned int numVoti;
};

#endif /* MATRICOLA_H_ */
