#ifndef MAIN_DLL_DLL_00CF_CANNONCLAW_H_
#define MAIN_DLL_DLL_00CF_CANNONCLAW_H_

#include "types.h"

void grimble_initialiseStateHandlerTables(void);
int cannonclaw_getExtraSize(void);
int cannonclaw_getObjectTypeId(void);
void cannonclaw_free(void);
void cannonclaw_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void cannonclaw_hitDetect(void);
void cannonclaw_update(u8* obj);
void cannonclaw_init(s16* dst, void* src);
void cannonclaw_release(void);
void cannonclaw_initialise(void);

#endif /* MAIN_DLL_DLL_00CF_CANNONCLAW_H_ */
