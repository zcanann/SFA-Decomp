#ifndef MAIN_DLL_DLL_02B9_MCSTAFFEFFE_H
#define MAIN_DLL_DLL_02B9_MCSTAFFEFFE_H

#include "main/dll/mcstaffeffe_state.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

extern ObjectDescriptor gMCStaffEffeObjDescriptor;

int mcstaffeffe_SeqFn(McStaffEffectObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void mcstaffeffe_render(McStaffEffectObject* obj);
void mcstaffeffe_update(void);
void mcstaffeffe_init(McStaffEffectObject* obj, McStaffEffectSetup* setup);

#endif
