/*
 * urnavirtuale.h
 *
 *  Created on: 03/ago/2017
 *      Author: giuseppe
 */

#ifndef URNAVIRTUALE_H_
#define URNAVIRTUALE_H_
//#include <string>
#include <cstdlib>
class UrnaVirtuale {
public:
	UrnaVirtuale();
	virtual ~UrnaVirtuale();
	uint getIdProceduraCorrente();
	uint getNumeroSchede(uint idProcedura);

};

#endif /* URNAVIRTUALE_H_ */
