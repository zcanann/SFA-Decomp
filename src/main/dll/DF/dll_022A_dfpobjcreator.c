/*
 * DragonRock Palace object creator (DLL 0x22A; "DFP_ObjCreator") - a
 * spawner object that periodically creates child objects from a stored
 * placement template, gated by a gamebit and a spawn-period timer.
 */
#include "main/dll/dfpobjcreatorstate_struct.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/dll/dll_80220608_shared.h"

STATIC_ASSERT(sizeof(DfpObjCreatorState) == 0x1C);

typedef struct DfpobjcreatorObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 gameBit;
    u8 pad1A[0x1C - 0x1A];
    s16 spawnPeriod;
    u8 pad1E[0x24 - 0x1E];
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} DfpobjcreatorObjectDef;

typedef struct DfpobjcreatorPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 colorR; /* 0x4 -> spawn setup base.color[0] */
    u8 colorG; /* 0x5 -> spawn setup base.color[1] */
    u8 colorB; /* 0x6 -> spawn setup base.color[2] */
    u8 colorA; /* 0x7 -> spawn setup base.color[3] */
    f32 posX;
    f32 posY;
    f32 posZ;
    s32 unk14;
    u8 pad18[0x19 - 0x18];
    u8 unk19;
    s16 behaviorMode; /* 0x1A switch selector (case 7 spawns the periodic object) */
    s16 spawnPeriod; /* 0x1C */
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    u8 pad2C[0x2E - 0x2C];
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DfpobjcreatorPlacement;

/* Obj_AllocObjectSetup(0x24,...) spawn buffer composed in
 * dbstealerworm_stateHandlerA00. Head is the common ObjPlacement (the
 * 0x04..0x07 bytes live in ObjPlacement.color); tail (0x18..0x23) is
 * file-local. */
typedef struct DfpobjcreatorSetup
{
    ObjPlacement base; /* 0x00..0x17 */
    u8 pad18[0x1A - 0x18];
    s16 objDefId;      /* 0x1A: spawned object/effect def id (0xdc) */
    u8 pad1C[0x1E - 0x1C];
    s16 gameBit;       /* 0x1E: GameBit slot (-1 = none) */
    s16 gameBit2;      /* 0x20: GameBit slot (-1 = none) */
    u8 pad22[0x24 - 0x22];
} DfpobjcreatorSetup;

STATIC_ASSERT(offsetof(DfpobjcreatorSetup, objDefId) == 0x1A);
STATIC_ASSERT(offsetof(DfpobjcreatorSetup, gameBit) == 0x1E);
STATIC_ASSERT(offsetof(DfpobjcreatorSetup, gameBit2) == 0x20);
STATIC_ASSERT(sizeof(DfpobjcreatorSetup) == 0x24);

extern int dbstealerworm_stateHandlerA02();

void dfpobjcreator_hitDetect(void)
{
}

void dfpobjcreator_release(void)
{
}

void dfpobjcreator_initialise(void)
{
}

int dfpobjcreator_getExtraSize(void) { return 0x1c; }
int dfpobjcreator_getObjectTypeId(void) { return 0x0; }

void dfpobjcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

void dfpobjcreator_free(int obj, int flag)
{
    DfpObjCreatorState* state = ((GameObject*)obj)->extra;
    if (flag == 0)
    {
        if (*(void**)&state->spawnedObj != NULL)
        {
            Obj_FreeObject(state->spawnedObj);
            state->spawnedObj = 0;
        }
    }
}

void dfpobjcreator_init(int obj, s8* def)
{
    DfpObjCreatorState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)def[0x1E] << 8);
    state->gameBit = ((DfpobjcreatorObjectDef*)def)->gameBit;
    state->spawnPeriod = ((DfpobjcreatorObjectDef*)def)->spawnPeriod;
    state->spawnTimer = state->spawnPeriod;
    state->unk12 = (s16)(s32)
    def[0x1F];
    state->unk14 = (s16)((s32)(u8)def[0x20] << 1);
    state->unk16 = 100;
}

#pragma dont_inline on

void dfpobjcreator_update(int obj)
{

    extern void* Obj_AllocObjectSetup(int size, int b);
    extern u8*Obj_SetupObject(u8*, int, int, int, int);
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    DfpObjCreatorState* state = ((GameObject*)obj)->extra;
    u8* setup;
    u8* newObj;

    if (Obj_IsLoadingLocked() != 0)
    {
        switch (((DfpobjcreatorPlacement*)data)->behaviorMode)
        {
        case 7:
            state->spawnTimer -= (s16)timeDelta;
            if (state->spawnTimer <= 0 && GameBit_Get(state->gameBit) != 0)
            {
                state->spawnTimer = state->spawnPeriod;
                setup = Obj_AllocObjectSetup(0x24, 0x71b);
                ((DfpobjcreatorSetup*)setup)->base.posX = ((DfpobjcreatorPlacement*)data)->posX;
                ((DfpobjcreatorSetup*)setup)->base.posY = ((DfpobjcreatorPlacement*)data)->posY;
                ((DfpobjcreatorSetup*)setup)->base.posZ = ((DfpobjcreatorPlacement*)data)->posZ;
                ((DfpobjcreatorSetup*)setup)->base.color[0] = ((DfpobjcreatorPlacement*)data)->colorR;
                ((DfpobjcreatorSetup*)setup)->base.color[1] = ((DfpobjcreatorPlacement*)data)->colorG;
                ((DfpobjcreatorSetup*)setup)->base.color[2] = ((DfpobjcreatorPlacement*)data)->colorB;
                ((DfpobjcreatorSetup*)setup)->base.color[3] = ((DfpobjcreatorPlacement*)data)->colorA;
                ((DfpobjcreatorSetup*)setup)->gameBit = -1;
                ((DfpobjcreatorSetup*)setup)->gameBit2 = -1;
                ((DfpobjcreatorSetup*)setup)->objDefId = 0xdc;
                newObj = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                         *(int*)&((GameObject*)obj)->anim.parent);
                ((GameObject*)newObj)->unkF4 = *(s8*)(data + 0x1e);
            }
            break;
        }
    }
}
#pragma dont_inline reset

int dbstealerworm_stateHandlerA02(int obj, int p2);
