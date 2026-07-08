#ifndef MAIN_DLL_DLL_0219_H_
#define MAIN_DLL_DLL_0219_H_

#include "global.h"
#include "main/obj_placement.h"

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

typedef struct Dll219Object
{
    u8 pad00[0xc];
    f32 x; /* 0x0c: current world X */
    u8 pad10[0x46 - 0x10];
    s16 objectId; /* 0x46 */
    u8 pad48[0x4c - 0x48];
    ObjPlacement* setup; /* 0x4c */
    u8 pad50[0xb8 - 0x50];
    Dll219State* state; /* 0xb8 */
} Dll219Object;

int dll_219_getExtraSize_ret_4(void);
int dll_219_getObjectTypeId(void);
void dll_219_free(int obj);
void dll_219_render_nop(void);
void dll_219_hitDetect_nop(void);
void dll_219_update(Dll219Object* obj);
void dll_219_init(int* obj, Dll219Setup* placement);
void dll_219_release_nop(void);
void dll_219_initialise_nop(void);

#endif /* MAIN_DLL_DLL_0219_H_ */
