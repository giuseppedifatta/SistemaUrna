/*
 * urnavirtuale.h
 *
 *  Created on: 03/ago/2017
 *      Author: giuseppe
 */

#ifndef URNAVIRTUALE_H_
#define URNAVIRTUALE_H_
#include <string>
#include <cstdlib>
#include "tinyxml2.h"
#include

class UrnaVirtuale {
public:
	UrnaVirtuale();
	virtual ~UrnaVirtuale();
	uint getIdProceduraCorrente();
	uint getNumeroSchede(uint idProcedura);


};

#endif /* URNAVIRTUALE_H_ */
