#ifndef MAIN_DLL_VF_DLL_0217_VFPOBJCREATOR_H_
#define MAIN_DLL_VF_DLL_0217_VFPOBJCREATOR_H_

#include "ghidra_import.h"
#include "global.h"
#include "main/obj_placement.h"

typedef struct VfpObjCreatorState
{
    s16 gameBit;       /* 0x00: spawn gate bit (-1 = always spawn) */
    s16 spawnInterval; /* 0x02: frames between spawns */
    s16 spawnTimer;    /* 0x04: countdown to the next spawn */
    s16 spawnParam;    /* 0x06 */
    s16 spawnRadius;   /* 0x08: random XZ scatter radius (falling mode) */
} VfpObjCreatorState;

typedef struct VfpObjCreatorPlacement
{
    ObjPlacement base;
    s16 gameBit;       /* 0x18 */
    s16 spawnMode;     /* 0x1A */
    s16 spawnInterval; /* 0x1C */
    s8 rotXByte;       /* 0x1E: packed into anim.rotX (<<8) */
    s8 spawnParam;     /* 0x1F */
    u8 spawnRadius;    /* 0x20 */
    u8 pad21[3];
} VfpObjCreatorPlacement;

STATIC_ASSERT(sizeof(VfpObjCreatorState) == 0xa);
STATIC_ASSERT(offsetof(VfpObjCreatorPlacement, gameBit) == 0x18);
STATIC_ASSERT(offsetof(VfpObjCreatorPlacement, spawnMode) == 0x1A);
STATIC_ASSERT(offsetof(VfpObjCreatorPlacement, spawnInterval) == 0x1C);
STATIC_ASSERT(offsetof(VfpObjCreatorPlacement, rotXByte) == 0x1E);
STATIC_ASSERT(offsetof(VfpObjCreatorPlacement, spawnParam) == 0x1F);
STATIC_ASSERT(offsetof(VfpObjCreatorPlacement, spawnRadius) == 0x20);
STATIC_ASSERT(sizeof(VfpObjCreatorPlacement) == 0x24);

/* Obj_AllocObjectSetup buffer filled in for each spawn. Head is the
 * common ObjPlacement; tail (0x18..0x27) is the per-spawn payload whose
 * fields are interpreted by the spawned object's own init. */
typedef struct VfpObjCreatorSetup
{
    ObjPlacement base; /* 0x00..0x17 (posX@0x8, unk04@0x4) */
    s16 unk18;         /* 0x18 */
    s16 unk1A;         /* 0x1A */
    s16 unk1C;         /* 0x1C */
    s16 unk1E;         /* 0x1E */
    s16 unk20;         /* 0x20 */
    s16 unk22;         /* 0x22 */
    u8 unk24;          /* 0x24 */
    u8 pad25[3];       /* 0x25 */
} VfpObjCreatorSetup;

STATIC_ASSERT(offsetof(VfpObjCreatorSetup, unk18) == 0x18);
STATIC_ASSERT(offsetof(VfpObjCreatorSetup, unk24) == 0x24);
STATIC_ASSERT(sizeof(VfpObjCreatorSetup) == 0x28);

int VFP_ObjCreator_getExtraSize(void);
int VFP_ObjCreator_getObjectTypeId(void);
void VFP_ObjCreator_free(void);
void VFP_ObjCreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void VFP_ObjCreator_hitDetect(void);
void VFP_ObjCreator_update(int* obj);
void VFP_ObjCreator_init(int* obj, u8* init);
void VFP_ObjCreator_release(void);
void VFP_ObjCreator_initialise(void);

#endif /* MAIN_DLL_VF_DLL_0217_VFPOBJCREATOR_H_ */
