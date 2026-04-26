#ifndef MAIN_DLL_FIRE_H_
#define MAIN_DLL_FIRE_H_

#include "ghidra_import.h"

typedef struct FireObject FireObject;

struct FireObject {
    u8 pad00[0xAC];
    s8 mapId;
    u8 padAD[0xB0 - 0xAD];
    u16 flags;
    u8 padB2[0xBC - 0xB2];
    undefined4 (*stateCallback)(FireObject *obj, undefined4 param_2, u8 *stateList);
};

undefined4 fire_updateState(FireObject *obj,undefined4 param_2,u8 *stateList);
int fireObj_getExtraSize(void);
int fireObj_func08(void);
void fireObj_free(void);
void fireObj_render(void);
void fireObj_hitDetect(void);
void fireObj_update(FireObject *obj);
void fireObj_init(FireObject *obj);
void fireObj_release(void);
void fireObj_initialise(void);

#endif /* MAIN_DLL_FIRE_H_ */
