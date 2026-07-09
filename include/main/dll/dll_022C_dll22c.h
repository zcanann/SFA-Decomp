#ifndef MAIN_DLL_DLL_022C_DLL22C_H_
#define MAIN_DLL_DLL_022C_DLL22C_H_

#include "main/game_object.h"
#include "global.h"
#include "main/obj_placement.h"

typedef struct Dll22CMapData
{
    ObjPlacement base;
    s8 rotXByte;     /* 0x18: rotX in 1/256 turns */
    s8 unk19;        /* 0x19 */
    s16 raiseHeight; /* 0x1A */
    s16 raiseMode;   /* 0x1C: -> state raiseMode */
    s16 gameBit2;    /* 0x1E */
    s16 gameBit;     /* 0x20 */
} Dll22CMapData;

STATIC_ASSERT(offsetof(Dll22CMapData, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(Dll22CMapData, raiseHeight) == 0x1A);
STATIC_ASSERT(offsetof(Dll22CMapData, raiseMode) == 0x1C);
STATIC_ASSERT(offsetof(Dll22CMapData, gameBit2) == 0x1E);
STATIC_ASSERT(offsetof(Dll22CMapData, gameBit) == 0x20);

int dll_22C_SeqFn(void);
int dll_22C_getExtraSize_ret_16(void);
int dll_22C_getObjectTypeId(void);
void dll_22C_free(int p1);
void dll_22C_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_22C_hitDetect_nop(void);
void dll_22C_update(int obj);
void dll_22C_init(GameObject* obj, char* p);
void dll_22C_release_nop(void);
void dll_22C_initialise_nop(void);

#endif /* MAIN_DLL_DLL_022C_DLL22C_H_ */
