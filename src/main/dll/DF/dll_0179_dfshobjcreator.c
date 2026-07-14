/*
 * DragonRock Shrine object creator (DLL 0x179; "DFSH_ObjCreator") - a
 * spawner that, once its gamebit arms, builds a SpiritPrize object setup
 * (object id 0x11) from its placement template and periodically spawns it
 * while loading is locked, playing the gem-run sfx.
 */
#include "main/obj_placement.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/resource.h"
#include "main/object.h"
#include "main/frame_timing.h"
#include "main/object_render_legacy.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/object_descriptor.h"

/* Obj_AllocObjectSetup(0x38,...) buffer composed in DFSH_ObjCreator_update.
 * Head is the common ObjPlacement; tail (0x18..0x37) is file-local. */
typedef struct DfshObjCreatorSetup
{
    ObjPlacement base; /* 0x00..0x17 */
    s16 unk18;         /* 0x18 */
    s16 unk1A;         /* 0x1A */
    s16 unk1C;         /* 0x1C */
    u8 pad1E[0x22 - 0x1E];
    s16 unk22; /* 0x22 */
    u8 pad24[0x27 - 0x24];
    u8 unk27;   /* 0x27 */
    u8 pad28;   /* 0x28 */
    u8 unk29;   /* 0x29 */
    s8 rotByte; /* 0x2A: object yaw byte (anim.rotX >> 8) */
    u8 unk2B;   /* 0x2B */
    u8 pad2C[0x2E - 0x2C];
    s8 unk2E;  /* 0x2E */
    u8 pad2F;  /* 0x2F */
    s16 unk30; /* 0x30 */
    u8 pad32[0x34 - 0x32];
    u16 unk34; /* 0x34 */
    u8 pad36[0x38 - 0x36];
} DfshObjCreatorSetup;

typedef struct DfshObjCreatorState
{
    s16 spawnTimer;
    s16 spawnTimerStep;
} DfshObjCreatorState;

STATIC_ASSERT(offsetof(DfshObjCreatorSetup, unk18) == 0x18);
STATIC_ASSERT(offsetof(DfshObjCreatorSetup, unk22) == 0x22);
STATIC_ASSERT(offsetof(DfshObjCreatorSetup, unk27) == 0x27);
STATIC_ASSERT(offsetof(DfshObjCreatorSetup, unk29) == 0x29);
STATIC_ASSERT(offsetof(DfshObjCreatorSetup, rotByte) == 0x2A);
STATIC_ASSERT(offsetof(DfshObjCreatorSetup, unk2E) == 0x2E);
STATIC_ASSERT(offsetof(DfshObjCreatorSetup, unk30) == 0x30);
STATIC_ASSERT(offsetof(DfshObjCreatorSetup, unk34) == 0x34);
STATIC_ASSERT(sizeof(DfshObjCreatorSetup) == 0x38);

/* Object id of the SpiritPrize object this creator spawns (docblock:
 * "builds a SpiritPrize object setup (object id 0x11)"). */
#define DFSHOBJCREATOR_SPIRITPRIZE_OBJ_ID 0x11

extern f32 lbl_803E4EB8;

int DFSH_ObjCreator_getExtraSize(void)
{
    return 0x4;
}
int DFSH_ObjCreator_getObjectTypeId(void)
{
    return 0x0;
}

void DFSH_ObjCreator_free(void)
{
}

void DFSH_ObjCreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E4EB8);
}

void DFSH_ObjCreator_hitDetect(void)
{
}

void DFSH_ObjCreator_update(GameObject* obj)
{

    u8* setup = *(u8**)&(obj)->anim.placementData;
    DfshObjCreatorState* state = (obj)->extra;
    void* resource;
    DfshObjCreatorSetup* spawnSetup;

    if (mainGetBit(0x589) != 0)
    {
        (obj)->unkF8 = 0;
        return;
    }

    if ((obj)->unkF8 == 0 && mainGetBit((s8)setup[0x1f] + 0xf6) != 0)
    {
        resource = Resource_Acquire(0x82, 1);
        (*(void (**)(int, int, int, int, int, int))(*(int*)resource + 4))((int)obj, 0, 0, 1, -1, 0);
        (*(void (**)(int, int, int, int, int, int))(*(int*)resource + 4))((int)obj, 1, 0, 1, -1, 0);
        Sfx_PlayFromObject((int)obj, SFXTRIG_hitpos_6);
        Resource_Release(resource);
        state->spawnTimerStep = 1;
        (obj)->unkF8 = 1;
    }

    if (state->spawnTimerStep != 0)
    {
        state->spawnTimer = (s16)(state->spawnTimer - state->spawnTimerStep * (int)timeDelta);
    }

    if (Obj_IsLoadingLocked() != 0 && state->spawnTimer <= 0)
    {
        spawnSetup = (DfshObjCreatorSetup*)Obj_AllocObjectSetup(0x38, DFSHOBJCREATOR_SPIRITPRIZE_OBJ_ID);
        spawnSetup->base.posX = ((ObjPlacement*)setup)->posX;
        spawnSetup->base.posY = ((ObjPlacement*)setup)->posY;
        spawnSetup->base.posZ = ((ObjPlacement*)setup)->posZ;
        spawnSetup->base.mapId = ((ObjPlacement*)setup)->mapId;
        spawnSetup->base.color[0] = setup[0x04];
        spawnSetup->base.color[1] = setup[0x05];
        spawnSetup->base.color[2] = setup[0x06];
        spawnSetup->base.color[3] = setup[0x07];
        ((DfshObjCreatorSetup*)spawnSetup)->unk27 = 3;
        ((DfshObjCreatorSetup*)spawnSetup)->unk18 = 0x1e7;
        ((DfshObjCreatorSetup*)spawnSetup)->unk30 = -1;
        ((DfshObjCreatorSetup*)spawnSetup)->unk1A = -1;
        ((DfshObjCreatorSetup*)spawnSetup)->unk1C = -1;
        ((DfshObjCreatorSetup*)spawnSetup)->rotByte = (s8)((obj)->anim.rotX >> 8);
        ((DfshObjCreatorSetup*)spawnSetup)->unk2B = 2;
        if (mainGetBit(0xfc) != 0)
        {
            ((DfshObjCreatorSetup*)spawnSetup)->unk22 = 0x49;
        }
        else
        {
            ((DfshObjCreatorSetup*)spawnSetup)->unk22 = -1;
        }
        ((DfshObjCreatorSetup*)spawnSetup)->unk29 = 0xff;
        ((DfshObjCreatorSetup*)spawnSetup)->unk2E = -1;
        ((DfshObjCreatorSetup*)spawnSetup)->unk34 = 0xffff;
        Obj_SetupObject(&spawnSetup->base, 5, (obj)->anim.mapEventSlot, -1, (obj)->anim.parent);
        state->spawnTimer = 100;
        state->spawnTimerStep = 0;
    }
}

void DFSH_ObjCreator_init(GameObject* obj, s8* def)
{
    DfshObjCreatorState* state = (obj)->extra;
    (obj)->anim.rotX = (s16)((s32)def[0x1E] << 8);
    (obj)->unkF8 = 0;
    state->spawnTimer = 100;
    state->spawnTimerStep = 0;
    *(u8*)((char*)obj + 0x37) = 0xFF;
    (obj)->anim.alpha = 0xFF;
}

void DFSH_ObjCreator_release(void)
{
}

void DFSH_ObjCreator_initialise(void)
{
}

ObjectDescriptor gDFSH_ObjCreatorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DFSH_ObjCreator_initialise,
    (ObjectDescriptorCallback)DFSH_ObjCreator_release,
    0,
    (ObjectDescriptorCallback)DFSH_ObjCreator_init,
    (ObjectDescriptorCallback)DFSH_ObjCreator_update,
    (ObjectDescriptorCallback)DFSH_ObjCreator_hitDetect,
    (ObjectDescriptorCallback)DFSH_ObjCreator_render,
    (ObjectDescriptorCallback)DFSH_ObjCreator_free,
    (ObjectDescriptorCallback)DFSH_ObjCreator_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)DFSH_ObjCreator_getExtraSize,
};
