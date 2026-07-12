/*
 * DragonRock Palace object creator (DLL 0x22A; "DFP_ObjCreator") - a
 * spawner object that periodically creates child objects from a stored
 * placement template, gated by a gamebit and a spawn-period timer.
 */
#include "main/dll/dfpobjcreatorstate_struct.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "main/object.h"
#include "main/object_api.h"

typedef struct DfpobjcreatorObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 gameBit;
    u8 pad1A[0x1C - 0x1A];
    s16 spawnPeriod;
    s8 rotXByte;
    s8 unk1F;
    u8 unk20;
    u8 pad21[0x24 - 0x21];
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} DfpobjcreatorObjectDef;

typedef struct DfpobjcreatorPlacement
{
    ObjPlacement base;
    u8 pad18[0x19 - 0x18];
    u8 unk19;
    s16 behaviorMode; /* 0x1A switch selector (case 7 spawns the periodic object) */
    s16 spawnPeriod;  /* 0x1C */
    s8 spawnedObjUnkF4;
    u8 pad1F;
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
    s16 objDefId; /* 0x1A: spawned object/effect def id (0xdc) */
    u8 pad1C[0x1E - 0x1C];
    s16 gameBit;  /* 0x1E: GameBit slot (-1 = none) */
    s16 gameBit2; /* 0x20: GameBit slot (-1 = none) */
    u8 pad22[0x24 - 0x22];
} DfpobjcreatorSetup;

STATIC_ASSERT(offsetof(DfpobjcreatorSetup, objDefId) == 0x1A);
STATIC_ASSERT(offsetof(DfpobjcreatorSetup, gameBit) == 0x1E);
STATIC_ASSERT(offsetof(DfpobjcreatorSetup, gameBit2) == 0x20);
STATIC_ASSERT(sizeof(DfpobjcreatorSetup) == 0x24);
STATIC_ASSERT(sizeof(DfpObjCreatorState) == 0x1C);

/* Object periodically spawned by DFP_ObjCreator (case 7) from the placement
 * template; the spawner's whole purpose. */
#define DFPOBJCREATOR_CHILD_OBJ 0x71b

int DFP_ObjCreator_getExtraSize(void)
{
    return 0x1c;
}
int DFP_ObjCreator_getObjectTypeId(void)
{
    return 0x0;
}

void DFP_ObjCreator_free(GameObject* obj, int flag)
{
    DfpObjCreatorState* state = obj->extra;
    if (flag == 0)
    {
        if (state->spawnedObj != NULL)
        {
            Obj_FreeObject(state->spawnedObj);
            state->spawnedObj = NULL;
        }
    }
}

void DFP_ObjCreator_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible == 0)
        return;
}

void DFP_ObjCreator_hitDetect(void)
{
}

void DFP_ObjCreator_update(GameObject* obj)
{

    DfpobjcreatorPlacement* data = (DfpobjcreatorPlacement*)obj->anim.placementData;
    DfpObjCreatorState* state = obj->extra;
    DfpobjcreatorSetup* setup;
    GameObject* newObj;

    if (Obj_IsLoadingLocked() != 0)
    {
        switch (data->behaviorMode)
        {
        case 7:
            state->spawnTimer -= (s16)timeDelta;
            if (state->spawnTimer <= 0 && mainGetBit(state->gameBit) != 0)
            {
                state->spawnTimer = state->spawnPeriod;
                setup = (DfpobjcreatorSetup*)Obj_AllocObjectSetup(0x24, DFPOBJCREATOR_CHILD_OBJ);
                setup->base.posX = data->base.posX;
                setup->base.posY = data->base.posY;
                setup->base.posZ = data->base.posZ;
                setup->base.color[0] = data->base.color[0];
                setup->base.color[1] = data->base.color[1];
                setup->base.color[2] = data->base.color[2];
                setup->base.color[3] = data->base.color[3];
                setup->gameBit = -1;
                setup->gameBit2 = -1;
                setup->objDefId = 0xdc;
                newObj = Obj_SetupObject(&setup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                newObj->unkF4 = data->spawnedObjUnkF4;
            }
            break;
        }
    }
}

void DFP_ObjCreator_init(GameObject* obj, DfpobjcreatorObjectDef* def)
{
    DfpObjCreatorState* state = obj->extra;
    obj->anim.rotX = (s16)((s32)def->rotXByte << 8);
    state->gameBit = def->gameBit;
    state->spawnPeriod = def->spawnPeriod;
    state->spawnTimer = state->spawnPeriod;
    state->unk12 = (s16)(s32)def->unk1F;
    state->unk14 = (s16)((s32)def->unk20 << 1);
    state->unk16 = 100;
}

void DFP_ObjCreator_release(void)
{
}

void DFP_ObjCreator_initialise(void)
{
}
