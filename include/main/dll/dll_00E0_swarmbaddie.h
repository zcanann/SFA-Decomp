#ifndef MAIN_DLL_DLL_00E0_SWARMBADDIE_H_
#define MAIN_DLL_DLL_00E0_SWARMBADDIE_H_

#include "types.h"
#include "main/dll/swarmbaddiestate_struct.h"

void fn_8014EE8C(int obj, SwarmBaddieState* state);
int SwarmBaddie_getExtraSize(void);
int SwarmBaddie_getObjectTypeId(void);
void SwarmBaddie_free(int obj);
void SwarmBaddie_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void SwarmBaddie_hitDetect(void);
void SwarmBaddie_update(int obj);
void SwarmBaddie_init(int obj, int data, int skip_alloc);
void SwarmBaddie_release(void);
void SwarmBaddie_initialise(void);

#endif /* MAIN_DLL_DLL_00E0_SWARMBADDIE_H_ */
