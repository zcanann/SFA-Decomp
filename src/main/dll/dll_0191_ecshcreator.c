/*
 * DLL 0x0191 - ecshcreator (EarthWalker shrine spawner). TU 0x801C6E0C-0x801C70F0.
 *
 * A placement-spawned manager object: on init it stores a per-instance
 * EcshCreatorState (in obj->extra) with the countdown (=100) and the
 * trigger game bit read from the placement. update() waits until that
 * game bit is set, then acquires resource 0x82, runs its two setup
 * vtable slots, plays a sfx and starts
 * the countdown (decremented by framesThisStep each tick). Once object
 * loading is unlocked and the countdown reaches <= 0 it allocates a 0x38
 * byte spawn descriptor and creates the actual shrine child object
 * (object type 0x11) via Obj_SetupObject, then re-arms the countdown.
 */
#include "main/game_object.h"
#include "main/audio/sfx.h"
#include "main/object_api.h"
#include "main/object_render.h"
#include "main/obj_placement.h"
#include "main/resource.h"
#include "main/gamebits.h"
#include "main/mm.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/dll_0191_ecshcreator.h"

#define ECSH_SHRINE_RESOURCE 0x82 /* shrine setup resource (Resource_Acquire id) */
#define ECSH_SHRINE_OBJ_TYPE 0x11 /* object type id of the spawned shrine */
#define ECSH_COUNTDOWN_START 100

extern f32 lbl_803E4FF8;

typedef struct EcshCreatorPlacement
{
    ObjPlacement head;
    s16 gameBit;         /* 0x18 */
    u8 pad1a[0x1e - 0x1a];
    s8 rotByte;          /* 0x1e: object yaw seed (<<8 -> anim.rotX) */
    s8 gameBitOffset;    /* 0x1f: added to spawned child gameBit */
    u8 groupSlotOffset;  /* 0x20: added to base group slot */
} EcshCreatorPlacement;

extern int Obj_SetupObject(u8* def, int a, int b, int c, int d);

int ecsh_creator_getExtraSize(void)
{
    return 0xa;
}
int ecsh_creator_getObjectTypeId(void)
{
    return 0x0;
}

void ecsh_creator_free(void)
{
}

void ecsh_creator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes((GameObject*)p1, lbl_803E4FF8);
}

void ecsh_creator_hitDetect(void)
{
}

void ecsh_creator_update(GameObject* obj)
{
    u8* def;
    EcshCreatorState* state;
    void* res;
    EcshShrineSpawnSetup* p;
    int ret;

    def = (u8*)obj->anim.placementData;
    state = (EcshCreatorState*)obj->extra;
    if (obj->unkF8 == 0 && (u32)mainGetBit(state->gameBit) != 0)
    {
        res = Resource_Acquire(ECSH_SHRINE_RESOURCE, 1);
        (*(EcshSetupFn*)(*(int*)res + 4))((s16*)obj, 0, 0, 1, -1, 0);
        (*(EcshSetupFn*)(*(int*)res + 4))((s16*)obj, 1, 0, 1, -1, 0);
        Sfx_PlayFromObject((u32)obj, SFXTRIG_wp_hitpos_6);
        Resource_Release(res);
        state->active = 1;
        obj->unkF8 = 1;
    }
    if (state->active != 0)
    {
        state->countdown = state->countdown - state->active * framesThisStep;
    }
    if (Obj_IsLoadingLocked() != 0 && state->countdown <= 0)
    {
        p = mmAlloc(0x38, 0xe, 0);
        p->posX = ((ObjPlacement*)def)->posX;
        p->posY = ((ObjPlacement*)def)->posY;
        p->posZ = ((ObjPlacement*)def)->posZ;
        p->objType = ECSH_SHRINE_OBJ_TYPE;
        p->mapId = -1;
        p->color[0] = ((ObjPlacement*)def)->color[0];
        p->color[1] = ((ObjPlacement*)def)->color[1];
        p->color[2] = ((ObjPlacement*)def)->color[2];
        p->color[3] = ((ObjPlacement*)def)->color[3];
        p->unk27 = 3;
        p->unk28 = 0;
        p->gameBit = state->gameBit + ((EcshCreatorPlacement*)def)->gameBitOffset;
        p->unk30 = -1;
        p->rotByte = (s8)(obj->anim.rotX >> 8);
        p->unk2B = 2;
        p->unk20 = 0;
        p->unk1E = 0;
        p->unk22 = -1;
        p->unk29 = 0xff;
        p->unk2E = -1;
        p->unk24 = 0;
        p->unk2C = 0;
        p->unk34 = 0xFFFF;
        p->unk1A = 0;
        p->groupSlot = state->groupSlot;
        ret = Obj_SetupObject((u8*)p, 5, obj->anim.mapEventSlot, -1, *(int*)&obj->anim.parent);
        if ((u32)ret != 0)
        {
            *(u8*)(*(int*)&((GameObject*)ret)->extra + 0x404) = 0x20;
        }
        state->countdown = ECSH_COUNTDOWN_START;
        state->active = 0;
    }
}

void ecsh_creator_init(GameObject* obj, s8* defArg)
{
    EcshCreatorState* state = (EcshCreatorState*)obj->extra;
    EcshCreatorPlacement* def = (EcshCreatorPlacement*)defArg;
    obj->anim.rotX = (s16)((s32)def->rotByte << 8);
    obj->unkF8 = 0;
    state->countdown = ECSH_COUNTDOWN_START;
    state->active = 0;
    *(u8*)((char*)obj + 0x37) = 0xff; /* anim.pad37[0], adjacent to anim.alpha */
    obj->anim.alpha = 0xff;
    state->gameBit = def->gameBit;
    state->groupSlot = 2;
    state->groupSlot += def->groupSlotOffset;
}

void ecsh_creator_release(void)
{
}

void ecsh_creator_initialise(void)
{
}
