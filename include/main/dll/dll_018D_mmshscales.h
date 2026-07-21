#ifndef MAIN_DLL_DLL_018D_MMSHSCALES_H_
#define MAIN_DLL_DLL_018D_MMSHSCALES_H_

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objseq.h"

typedef struct MmshScalesState
{
    ObjSeqState sequence;
    u8 pad138[0x140 - 0x138];
} MmshScalesState;

typedef struct MmshScalesPlacement
{
    ObjPlacement base;
    s16 animationBank;
    s16 sequenceGameBit;
    u8 pad1C[0x24 - 0x1C];
    u8 positionDamping;
} MmshScalesPlacement;

/* 0x24-byte spawn descriptor handed to Obj_SetupObject for the child
 * object. ObjPlacement-style head (color block + position). */
typedef struct MmshScalesSpawnSetup
{
    ObjPlacement base;
    u8 pad18[0x24 - 0x18];
} MmshScalesSpawnSetup;

STATIC_ASSERT(offsetof(MmshScalesState, sequence) == 0x0);
STATIC_ASSERT(sizeof(MmshScalesState) == 0x140);
STATIC_ASSERT(offsetof(MmshScalesPlacement, animationBank) == 0x18);
STATIC_ASSERT(offsetof(MmshScalesPlacement, sequenceGameBit) == 0x1A);
STATIC_ASSERT(offsetof(MmshScalesPlacement, positionDamping) == 0x24);
STATIC_ASSERT(sizeof(MmshScalesSpawnSetup) == 0x24);

extern ObjectDescriptor gMMSH_ScalesObjDescriptor;

int MMSH_Scales_getExtraSize(void);
int MMSH_Scales_getObjectTypeId(void);
void MMSH_Scales_free(GameObject* obj, int keepChild);
void MMSH_Scales_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void MMSH_Scales_hitDetect(void);
void MMSH_Scales_update(GameObject* obj);
void MMSH_Scales_init(GameObject* obj, MmshScalesPlacement* placement);
void MMSH_Scales_release(void);
void MMSH_Scales_initialise(void);

#endif /* MAIN_DLL_DLL_018D_MMSHSCALES_H_ */
