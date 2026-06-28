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
#include "main/gamebits.h"
#include "main/mm.h"
extern void Sfx_PlayFromObject(s16* obj, int sfxId);
extern f32 lbl_803E4FF8;
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

/* 0x38-byte spawn descriptor handed to Obj_SetupObject for the shrine
 * child (object type 0x11). Head is the common ObjPlacement layout
 * (type id at 0, color block, position, mapId); the tail is the
 * EarthWalker-shrine class fields. */
typedef struct EcshShrineSpawnSetup {
    s16 objType;       /* 0x00 */
    s16 pad02;         /* 0x02 */
    u8 color[4];       /* 0x04 */
    f32 posX;          /* 0x08 */
    f32 posY;          /* 0x0c */
    f32 posZ;          /* 0x10 */
    s32 mapId;         /* 0x14 */
    s16 gameBit;       /* 0x18 */
    s16 unk1A;         /* 0x1a */
    u8 pad1C[2];       /* 0x1c */
    s16 unk1E;         /* 0x1e */
    s16 unk20;         /* 0x20 */
    s16 unk22;         /* 0x22 */
    s16 unk24;         /* 0x24 */
    u8 pad26;          /* 0x26 */
    u8 unk27;          /* 0x27 */
    u8 unk28;          /* 0x28 */
    u8 unk29;          /* 0x29 */
    s8 unk2A;          /* 0x2a */
    u8 unk2B;          /* 0x2b */
    s16 unk2C;         /* 0x2c */
    s8 unk2E;          /* 0x2e */
    u8 pad2F;          /* 0x2f */
    s16 unk30;         /* 0x30 */
    u8 unk32;          /* 0x32 */
    u8 pad33;          /* 0x33 */
    u16 unk34;         /* 0x34 */
    u8 pad36[2];       /* 0x36 */
} EcshShrineSpawnSetup;

STATIC_ASSERT(offsetof(EcshShrineSpawnSetup, posX) == 0x8);
STATIC_ASSERT(offsetof(EcshShrineSpawnSetup, mapId) == 0x14);
STATIC_ASSERT(offsetof(EcshShrineSpawnSetup, gameBit) == 0x18);
STATIC_ASSERT(offsetof(EcshShrineSpawnSetup, unk2A) == 0x2a);
STATIC_ASSERT(offsetof(EcshShrineSpawnSetup, unk34) == 0x34);
STATIC_ASSERT(sizeof(EcshShrineSpawnSetup) == 0x38);

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
    EcshShrineSpawnSetup* p;
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
        p->posX = ((ObjPlacement*)def)->posX;
        p->posY = ((ObjPlacement*)def)->posY;
        p->posZ = ((ObjPlacement*)def)->posZ;
        p->objType = ECSH_SHRINE_OBJ_TYPE;
        p->mapId = -1;
        p->color[0] = def[4];
        p->color[1] = def[5];
        p->color[2] = def[6];
        p->color[3] = def[7];
        p->unk27 = 3;
        p->unk28 = 0;
        p->gameBit = state->gameBit + *(s8*)(def + 0x1f);
        p->unk30 = -1;
        p->unk2A = (s8)(obj->anim.rotX >> 8);
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
        p->unk32 = state->groupSlot;
        ret = Obj_SetupObject((u8*)p, 5, obj->anim.mapEventSlot, -1, *(int*)&obj->anim.parent);
        if ((u32)ret != 0)
        {
            *(u8*)(*(int*)&((GameObject*)ret)->extra + 0x404) = 0x20;
        }
        state->countdown = ECSH_COUNTDOWN_START;
        state->active = 0;
    }
}
#pragma reset
#pragma reset
