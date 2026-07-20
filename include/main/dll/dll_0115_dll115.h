#ifndef MAIN_DLL_DLL_0115_DLL115_H_
#define MAIN_DLL_DLL_0115_DLL115_H_

#include "types.h"
#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/obj_placement.h"

typedef struct Dll115Placement
{
    ObjPlacement base; /* 0x00 */
    s16 setGameBits[8];
    s16 gateGameBits[8];
    u8 rotByte;        /* 0x38: rotX in 1/256 turns */
    u8 flags;          /* 0x39: DLL115_PLACEMENT_FINISH_FLAG */
    u8 finishSeqId;    /* 0x3A: step-9 trigger sequence id */
    u8 finishSeqParam; /* 0x3B */
    s16 preemptArg;    /* 0x3C */
    u8 pad3E[0x40 - 0x3E];
    s8 triggerSeqIds[8];
} Dll115Placement;

typedef struct Dll115State
{
    u8 step;
    u8 flags;
} Dll115State;

int dll_115_seqFn(GameObject* obj, int p2, ObjAnimUpdateState* animUpdate);
int dll_115_getExtraSize_ret_2(void);
int dll_115_getObjectTypeId(void);
void dll_115_free(GameObject* obj);
void dll_115_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dll_115_hitDetect_nop(void);
void dll_115_update(GameObject* obj);
void dll_115_init(GameObject* obj, Dll115Placement* placement);
void dll_115_release_nop(void);
void dll_115_initialise_nop(void);

#endif /* MAIN_DLL_DLL_0115_DLL115_H_ */
