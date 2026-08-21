#ifndef MAIN_DLL_DLL_0219_H_
#define MAIN_DLL_DLL_0219_H_

#include "global.h"
#include "game/objects/object.h"
#include "dlls/object_descriptor.h"
#include "game/objects/object_setup.h"

typedef struct Dll219State
{
    s16 gameBit;
} Dll219State;

typedef struct Dll219Setup
{
    ObjPlacement placement;
    s8 rotX; /* 0x18 */
    u8 pad19[0x1e - 0x19];
    s16 gameBit; /* 0x1e */
} Dll219Setup;

int dll_219_getExtraSize_ret_4(void);
int dll_219_getObjectTypeId(void);
void dll_219_free(GameObject* obj);
void dll_219_render_nop(void);
void dll_219_hitDetect_nop(void);
void dll_219_update(GameObject* obj);
void dll_219_init(GameObject* obj, Dll219Setup* placement);
void dll_219_release_nop(void);
void dll_219_initialise_nop(void);

extern ObjectDescriptor gDll219ObjDescriptor;

#endif /* MAIN_DLL_DLL_0219_H_ */
