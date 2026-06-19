/*
 * DragonRock Palace object creator (DLL 0x22A; "DFP_ObjCreator") - a
 * spawner object that periodically creates child objects from a stored
 * placement template, gated by a gamebit and a spawn-period timer.
 */
#include "main/dll/dfpobjcreatorstate_struct.h"
#include "main/obj_placement.h"
#include "main/game_object.h"

extern u32 GameBit_Get(int eventId);

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
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    f32 posX;
    f32 posY;
    f32 posZ;
    s32 unk14;
    u8 pad18[0x19 - 0x18];
    u8 unk19;
    s16 unk1A;
    s16 unk1C;
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
 * 0x04..0x07 bytes live in ObjPlacement.unk04); tail (0x18..0x23) is
 * file-local. */
typedef struct DfpobjcreatorSetup
{
    ObjPlacement base; /* 0x00..0x17 */
    u8 pad18[0x1A - 0x18];
    s16 unk1A;         /* 0x1A */
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;         /* 0x1E */
    s16 unk20;         /* 0x20 */
    u8 pad22[0x24 - 0x22];
} DfpobjcreatorSetup;

STATIC_ASSERT(offsetof(DfpobjcreatorSetup, unk1A) == 0x1A);
STATIC_ASSERT(offsetof(DfpobjcreatorSetup, unk1E) == 0x1E);
STATIC_ASSERT(offsetof(DfpobjcreatorSetup, unk20) == 0x20);
STATIC_ASSERT(sizeof(DfpobjcreatorSetup) == 0x24);

extern void Obj_FreeObject(int obj);
extern f32 timeDelta;

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
    extern u8 Obj_IsLoadingLocked(void);
    extern u32 GameBit_Get(int);
    extern u8*Obj_AllocObjectSetup(int, int);
    extern u8*Obj_SetupObject(u8*, int, int, int, int);
    extern f32 timeDelta;
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    DfpObjCreatorState* state = ((GameObject*)obj)->extra;
    u8* setup;
    u8* newObj;

    if (Obj_IsLoadingLocked() != 0)
    {
        switch (((DfpobjcreatorPlacement*)data)->unk1A)
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
                ((DfpobjcreatorSetup*)setup)->base.unk04[0] = ((DfpobjcreatorPlacement*)data)->unk4;
                ((DfpobjcreatorSetup*)setup)->base.unk04[1] = ((DfpobjcreatorPlacement*)data)->unk5;
                ((DfpobjcreatorSetup*)setup)->base.unk04[2] = ((DfpobjcreatorPlacement*)data)->unk6;
                ((DfpobjcreatorSetup*)setup)->base.unk04[3] = ((DfpobjcreatorPlacement*)data)->unk7;
                ((DfpobjcreatorSetup*)setup)->unk1E = -1;
                ((DfpobjcreatorSetup*)setup)->unk20 = -1;
                ((DfpobjcreatorSetup*)setup)->unk1A = 0xdc;
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

