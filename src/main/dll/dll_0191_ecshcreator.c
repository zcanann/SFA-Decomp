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
#include "main/obj_placement.h"
#include "main/resource.h"

extern void Sfx_PlayFromObject(s16* obj, int sfxId);
extern int GameBit_Get(int bit);
extern f32 lbl_803E4FF8;
extern u8* mmAlloc(int size, int tag, int p);
extern int Obj_SetupObject(u8* def, int a, int b, int c, int d);
extern u8 Obj_IsLoadingLocked(void);
extern u8 framesThisStep;

#define ECSH_SHRINE_RESOURCE 0x82  /* shrine setup resource (Resource_Acquire id) */
#define ECSH_SHRINE_OBJ_TYPE 0x11  /* object type id of the spawned shrine */
#define ECSH_COUNTDOWN_START 100

typedef void (*EcshSetupFn)(s16*, int, int, int, int, int);

typedef struct EcshCreatorState {
    s16 countdown;
    s16 active;
    s16 gameBit;
    s16 pad06;
    s16 groupSlot;
} EcshCreatorState;

STATIC_ASSERT(offsetof(EcshCreatorState, countdown) == 0);
STATIC_ASSERT(offsetof(EcshCreatorState, active) == 2);
STATIC_ASSERT(offsetof(EcshCreatorState, gameBit) == 4);
STATIC_ASSERT(offsetof(EcshCreatorState, groupSlot) == 8);
STATIC_ASSERT(sizeof(EcshCreatorState) == 0xa);

void ecsh_creator_free(void)
{
}

void ecsh_creator_hitDetect(void)
{
}

void ecsh_creator_release(void)
{
}

void ecsh_creator_initialise(void)
{
}

int ecsh_creator_getExtraSize(void) { return 0xa; }
int ecsh_creator_getObjectTypeId(void) { return 0x0; }

#pragma scheduling off
#pragma peephole off
void ecsh_creator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderFn_8003b8f4(f32);
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4FF8);
}

void ecsh_creator_init(GameObject* obj, s8* def)
{
    EcshCreatorState* state = (EcshCreatorState*)obj->extra;
    obj->anim.rotX = (s16)((s32)def[0x1e] << 8);
    obj->unkF8 = 0;
    state->countdown = ECSH_COUNTDOWN_START;
    state->active = 0;
    *(u8*)((char*)obj + 0x37) = 0xff; /* anim.pad37[0], adjacent to anim.alpha */
    obj->anim.alpha = 0xff;
    state->gameBit = *(s16*)(def + 0x18);
    state->groupSlot = 2;
    state->groupSlot += (u8)def[0x20];
}

void ecsh_creator_update(GameObject* obj)
{
    u8* def;
    EcshCreatorState* state;
    void* res;
    u8* p;
    int ret;

    def = (u8*)obj->anim.placementData;
    state = (EcshCreatorState*)obj->extra;
    if (obj->unkF8 == 0 && (u32)GameBit_Get(state->gameBit) != 0)
    {
        res = Resource_Acquire(ECSH_SHRINE_RESOURCE, 1);
        (*(EcshSetupFn*)(*(int*)res + 4))((s16*)obj, 0, 0, 1, -1, 0);
        (*(EcshSetupFn*)(*(int*)res + 4))((s16*)obj, 1, 0, 1, -1, 0);
        Sfx_PlayFromObject((s16*)obj, 0x16d);
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
        *(f32*)(p + 8) = ((ObjPlacement*)def)->posX;
        *(f32*)(p + 0xc) = ((ObjPlacement*)def)->posY;
        *(f32*)(p + 0x10) = ((ObjPlacement*)def)->posZ;
        *(s16*)p = ECSH_SHRINE_OBJ_TYPE;
        *(int*)(p + 0x14) = -1;
        p[4] = def[4];
        p[5] = def[5];
        p[6] = def[6];
        p[7] = def[7];
        p[0x27] = 3;
        p[0x28] = 0;
        *(s16*)(p + 0x18) = state->gameBit + *(s8*)(def + 0x1f);
        *(s16*)(p + 0x30) = -1;
        *(s8*)(p + 0x2a) = (s8)(obj->anim.rotX >> 8);
        p[0x2b] = 2;
        *(s16*)(p + 0x20) = 0;
        *(s16*)(p + 0x1e) = 0;
        *(s16*)(p + 0x22) = -1;
        p[0x29] = 0xff;
        *(s8*)(p + 0x2e) = -1;
        *(s16*)(p + 0x24) = 0;
        *(s16*)(p + 0x2c) = 0;
        *(u16*)(p + 0x34) = 0xFFFF;
        *(s16*)(p + 0x1a) = 0;
        *(u8*)(p + 0x32) = state->groupSlot;
        ret = Obj_SetupObject(p, 5, obj->anim.mapEventSlot, -1, *(int*)&obj->anim.parent);
        if ((u32)ret != 0)
        {
            /* byte at +0x404 in the spawned shrine's extra state block */
            *(u8*)(*(int*)&((GameObject*)ret)->extra + 0x404) = 0x20;
        }
        state->countdown = ECSH_COUNTDOWN_START;
        state->active = 0;
    }
}
#pragma reset
#pragma reset
