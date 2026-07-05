/*
 * DragonRock Shrine object creator (DLL 0x179; "DFSH_ObjCreator") - a
 * spawner that, once its gamebit arms, builds a SpiritPrize object setup
 * (object id 0x11) from its placement template and periodically spawns it
 * while loading is locked, playing the gem-run sfx.
 */
#include "main/obj_placement.h"
#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/resource.h"
#include "main/dll/VF/vf_shared.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"

extern f32 lbl_803E4EB8;
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern void* Obj_SetupObject(void* setup, int mode, int mapLayer, int objIndex, int parent);

/* Obj_AllocObjectSetup(0x38,...) buffer composed in dfsh_objcreator_update.
 * Head is the common ObjPlacement; tail (0x18..0x37) is file-local. */
typedef struct DfshObjCreatorSetup
{
    ObjPlacement base; /* 0x00..0x17 */
    s16 unk18;         /* 0x18 */
    s16 unk1A;         /* 0x1A */
    s16 unk1C;         /* 0x1C */
    u8 pad1E[0x22 - 0x1E];
    s16 unk22;         /* 0x22 */
    u8 pad24[0x27 - 0x24];
    u8 unk27;          /* 0x27 */
    u8 pad28;          /* 0x28 */
    u8 unk29;          /* 0x29 */
    s8 rotByte;        /* 0x2A: object yaw byte (anim.rotX >> 8) */
    u8 unk2B;          /* 0x2B */
    u8 pad2C[0x2E - 0x2C];
    s8 unk2E;          /* 0x2E */
    u8 pad2F;          /* 0x2F */
    s16 unk30;         /* 0x30 */
    u8 pad32[0x34 - 0x32];
    u16 unk34;         /* 0x34 */
    u8 pad36[0x38 - 0x36];
} DfshObjCreatorSetup;

STATIC_ASSERT(offsetof(DfshObjCreatorSetup, unk18) == 0x18);
STATIC_ASSERT(offsetof(DfshObjCreatorSetup, unk22) == 0x22);
STATIC_ASSERT(offsetof(DfshObjCreatorSetup, unk27) == 0x27);
STATIC_ASSERT(offsetof(DfshObjCreatorSetup, unk29) == 0x29);
STATIC_ASSERT(offsetof(DfshObjCreatorSetup, rotByte) == 0x2A);
STATIC_ASSERT(offsetof(DfshObjCreatorSetup, unk2E) == 0x2E);
STATIC_ASSERT(offsetof(DfshObjCreatorSetup, unk30) == 0x30);
STATIC_ASSERT(offsetof(DfshObjCreatorSetup, unk34) == 0x34);
STATIC_ASSERT(sizeof(DfshObjCreatorSetup) == 0x38);

void dfsh_objcreator_free(void)
{
}

void dfsh_objcreator_hitDetect(void)
{
}

int dfsh_objcreator_getExtraSize(void) { return 0x4; }
int dfsh_objcreator_getObjectTypeId(void) { return 0x0; }

void dfsh_objcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E4EB8);
}

typedef struct DfshObjCreatorState
{
    s16 spawnTimer;
    s16 spawnTimerStep;
} DfshObjCreatorState;

void dfsh_objcreator_update(int obj)
{

    u8* setup = *(u8**)&((GameObject*)obj)->anim.placementData;
    DfshObjCreatorState* state = ((GameObject*)obj)->extra;
    void* resource;
    u8* spawnSetup;

    if (GameBit_Get(0x589) != 0)
    {
        ((GameObject*)obj)->unkF8 = 0;
        return;
    }

    if (((GameObject*)obj)->unkF8 == 0 && GameBit_Get((s8)setup[0x1f] + 0xf6) != 0)
    {
        resource = Resource_Acquire(0x82, 1);
        (*(void (**)(int, int, int, int, int, int))(*(int*)resource + 4))(
            obj, 0, 0, 1, -1, 0);
        (*(void (**)(int, int, int, int, int, int))(*(int*)resource + 4))(
            obj, 1, 0, 1, -1, 0);
        Sfx_PlayFromObject(obj, SFXsc_gemrun1022);
        Resource_Release(resource);
        state->spawnTimerStep = 1;
        ((GameObject*)obj)->unkF8 = 1;
    }

    if (state->spawnTimerStep != 0)
    {
        state->spawnTimer =
            (s16)(state->spawnTimer - state->spawnTimerStep * (int)timeDelta);
    }

    if (Obj_IsLoadingLocked() != 0 && state->spawnTimer <= 0)
    {
        spawnSetup = Obj_AllocObjectSetup(0x38, 0x11);
        ((DfshObjCreatorSetup*)spawnSetup)->base.posX = ((ObjPlacement*)setup)->posX;
        ((DfshObjCreatorSetup*)spawnSetup)->base.posY = ((ObjPlacement*)setup)->posY;
        ((DfshObjCreatorSetup*)spawnSetup)->base.posZ = ((ObjPlacement*)setup)->posZ;
        ((DfshObjCreatorSetup*)spawnSetup)->base.mapId = ((ObjPlacement*)setup)->mapId;
        ((DfshObjCreatorSetup*)spawnSetup)->base.color[0] = setup[0x04];
        ((DfshObjCreatorSetup*)spawnSetup)->base.color[1] = setup[0x05];
        ((DfshObjCreatorSetup*)spawnSetup)->base.color[2] = setup[0x06];
        ((DfshObjCreatorSetup*)spawnSetup)->base.color[3] = setup[0x07];
        ((DfshObjCreatorSetup*)spawnSetup)->unk27 = 3;
        ((DfshObjCreatorSetup*)spawnSetup)->unk18 = 0x1e7;
        ((DfshObjCreatorSetup*)spawnSetup)->unk30 = -1;
        ((DfshObjCreatorSetup*)spawnSetup)->unk1A = -1;
        ((DfshObjCreatorSetup*)spawnSetup)->unk1C = -1;
        ((DfshObjCreatorSetup*)spawnSetup)->rotByte = (s8)(((GameObject*)obj)->anim.rotX >> 8);
        ((DfshObjCreatorSetup*)spawnSetup)->unk2B = 2;
        if (GameBit_Get(0xfc) != 0)
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
        Obj_SetupObject(spawnSetup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                        *(int*)&((GameObject*)obj)->anim.parent);
        state->spawnTimer = 100;
        state->spawnTimerStep = 0;
    }
}

void dfsh_objcreator_release(void)
{
}

void dfsh_objcreator_initialise(void)
{
}

void dfsh_objcreator_init(int obj, s8* def)
{
    DfshObjCreatorState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)def[0x1E] << 8);
    ((GameObject*)obj)->unkF8 = 0;
    state->spawnTimer = 100;
    state->spawnTimerStep = 0;
    *(u8*)((char*)obj + 0x37) = 0xFF;
    ((GameObject*)obj)->anim.alpha = 0xFF;
}
