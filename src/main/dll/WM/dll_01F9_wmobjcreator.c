/* DLL 0x1F9 - WMObjCreator [801EF360-801EF3A8) */
#include "main/dll_000A_expgfx.h"
#include "main/dll/WC/dll_01F9_wmobjcreator.h"
#include "main/effect_interfaces.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/resource.h"

extern uint GameBit_Get(int eventId);

extern EffectInterface** gPartfxInterface;

extern f32 lbl_803E5CC8;
extern f32 lbl_803E5C70;
extern u8 framesThisStep;
extern u32 randomGetRange(int min, int max);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int a, int b);
extern int Obj_SetupObject(int setup, int a, int b, int c, int d);
extern int lbl_803DDC68;
extern f32 lbl_803E5CCC;
extern f32 lbl_803E5CD0;
extern f32 lbl_803E5CD4;
extern const f32 lbl_803E5CD8;
extern f32 lbl_803E5CDC;

void WM_ObjCreator_free(void)
{
}

void WM_ObjCreator_hitDetect(void)
{
}

int fn_801EEDAC(void);
int WM_ObjCreator_getExtraSize(void) { return 0x8; }
int WM_ObjCreator_getObjectTypeId(void) { return 0x0; }

void WM_ObjCreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderFn_8003b8f4(f32); /* #57 */
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5CC8);
}

/* Path-follow steering update for the cloudrunner block (target 0x801EE668;
 * Ghidra split this body as FUN_801eeafc). */

/* SB_CloudRunner_HandlePriorityHit: when the laser hits an object whose
 * type isn't 281 and isn't currently in fade state, fade it red, rumble,
 * play SFX, gate further damage on a GameBit, then if the hit type is 154
 * emit 3 partfx of effect 168 followed by a 10-shot burst of effect 169. */

/* segment pragma-stack balance (re-split): */

/* WM_ObjCreator per-object extra state (four s16 slots). */
typedef struct WmObjCreatorState
{
    s16 gameBit; /* 0x00: spawn gate, -1 = always */
    s16 spawnPeriod; /* 0x02 */
    s16 spawnTimer; /* 0x04 */
    s16 spawnJitter; /* 0x06: randomGetRange(0, jitter) added per cycle */
} WmObjCreatorState;

STATIC_ASSERT(sizeof(WmObjCreatorState) == 0x8);

typedef struct WmObjCreatorPlacement
{
    ObjPlacement base;
    s16 gameBit;
    s16 spawnMode;
    s16 spawnPeriod;
    s8 yaw;
    s8 spawnJitter;
    u8 pad20[4];
} WmObjCreatorPlacement;

STATIC_ASSERT(offsetof(WmObjCreatorPlacement, gameBit) == 0x18);
STATIC_ASSERT(offsetof(WmObjCreatorPlacement, spawnMode) == 0x1A);
STATIC_ASSERT(offsetof(WmObjCreatorPlacement, spawnPeriod) == 0x1C);
STATIC_ASSERT(offsetof(WmObjCreatorPlacement, yaw) == 0x1E);
STATIC_ASSERT(offsetof(WmObjCreatorPlacement, spawnJitter) == 0x1F);
STATIC_ASSERT(sizeof(WmObjCreatorPlacement) == 0x24);

/* WM_Galleon_getExtraSize == 0x10. */
typedef struct WmGalleonState
{
    u8 pad00[0xC];
    u8 active; /* 0x0c: cleared on a non-map-change free */
    u8 pad0D[3];
} WmGalleonState;

STATIC_ASSERT(sizeof(WmGalleonState) == 0x10);

void WM_ObjCreator_update(int obj)
{
    extern undefined8 GameBit_Set(int eventId, int value); /* #57 */
    extern void* ObjGroup_GetObjects(); /* #57 */
    int setup;
    int spawned;
    int n;
    WmObjCreatorPlacement* placement;
    WmObjCreatorState* state;
    int count;
    s8 ok;
    struct
    {
        s16 dir[3];
        s16 pad;
        f32 pos[4];
    } vec;

    placement = (WmObjCreatorPlacement*)((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    if (Obj_IsLoadingLocked() != 0)
    {
        switch (placement->spawnMode)
        {
        case 0:
            {
                int* objs;
                int k;
                ok = 0;
                if (((GameObject*)obj)->unkF8 == 0)
                {
                    ok = 1;
                    if (GameBit_Get(0x78) != 0)
                    {
                        ok = 0;
                    }
                    objs = (int*)ObjGroup_GetObjects(3, &count);
                    k = 0;
                    while (k < count && ok)
                    {
                        if (*(s16*)(*objs + 0x46) == 0x139)
                        {
                            ok = 0;
                        }
                        objs += 1;
                        k += 1;
                    }
                }
                if (ok)
                {
                    setup = Obj_AllocObjectSetup(0x24, 0x139);
                    ((ObjPlacement*)setup)->posX = placement->base.posX;
                    ((ObjPlacement*)setup)->posY = placement->base.posY;
                    ((ObjPlacement*)setup)->posZ = placement->base.posZ;
                    *(u8*)(setup + 4) = placement->base.unk04[0];
                    *(u8*)(setup + 5) = placement->base.unk04[1];
                    *(u8*)(setup + 6) = placement->base.unk04[2];
                    *(u8*)(setup + 7) = placement->base.unk04[3];
                    *(s16*)(setup + 0x1e) = 0xffff;
                    *(s16*)(setup + 0x1a) = 2;
                    *(u8*)(setup + 0x18) = placement->yaw;
                    spawned = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                              *(int*)&((GameObject*)obj)->anim.parent);
                    if ((u32)spawned != 0)
                    {
                        ((GameObject*)spawned)->unkF4 = 8;
                    }
                    ((GameObject*)obj)->unkF8 = 1;
                }
                break;
            }
        case 1:
            if ((GameBit_Get(state->gameBit) != 0 || state->gameBit == -1) &&
                (state->spawnTimer -= framesThisStep, state->spawnTimer <= 0))
            {
                int setup = Obj_AllocObjectSetup(0x28, 0x263);
                *(u8*)(setup + 4) = 0x20;
                *(u8*)(setup + 5) = 2;
                *(u8*)(setup + 7) = 0xff;
                ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
                ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
                ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
                *(s16*)(setup + 0x20) = 0x50;
                *(s16*)(setup + 0x1e) = 0x10f;
                *(s16*)(setup + 0x22) = 0xffff;
                *(s16*)(setup + 0x18) = randomGetRange(-500, 500) + 0x5dc;
                *(s16*)(setup + 0x1a) = 0;
                *(s16*)(setup + 0x1c) = randomGetRange(-500, 500) + 0x5dc;
                spawned = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                          *(int*)&((GameObject*)obj)->anim.parent);
                if ((u32)spawned != 0)
                {
                    ((GameObject*)spawned)->anim.velocityX = lbl_803E5CCC + (f32)(int)
                    randomGetRange(0, 10);
                }
                state->spawnTimer = state->spawnPeriod + randomGetRange(0, state->spawnJitter);
            }
            break;
        case 5:
            if ((GameBit_Get(state->gameBit) != 0 || state->gameBit == -1) &&
                (state->spawnTimer -= framesThisStep, state->spawnTimer <= 0))
            {
                setup = Obj_AllocObjectSetup(0x24, 0x275);
                *(s8*)(setup + 0x18) = randomGetRange(-0x7f, 0x7e);
                ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX + (f32)(int)
                randomGetRange(-100, 100);
                ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
                ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ + (f32)(int)
                randomGetRange(-100, 100);
                *(s16*)(setup + 0x1a) = 0x31;
                *(s16*)(setup + 0x1c) = 200;
                spawned = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                          *(int*)&((GameObject*)obj)->anim.parent);
                if ((u32)spawned != 0)
                {
                    lbl_803DDC68 += 1;
                }
                state->spawnTimer = state->spawnPeriod + randomGetRange(0, state->spawnJitter);
            }
            break;
        case 8:
            if ((GameBit_Get(state->gameBit) != 0 || state->gameBit == -1) &&
                (state->spawnTimer -= framesThisStep, state->spawnTimer <= 0))
            {
                setup = Obj_AllocObjectSetup(0x38, 0x4ac);
                GameBit_Set(state->gameBit, 0);
                *(s8*)(setup + 0x2a) = randomGetRange(-0x7f, 0x7e);
                ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
                ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
                ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
                *(s16*)(setup + 0x18) = state->gameBit;
                *(s16*)(setup + 0x22) = 1;
                spawned = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                          *(int*)&((GameObject*)obj)->anim.parent);
                if ((u32)spawned != 0)
                {
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x1c3, NULL, 2, -1, NULL);
                }
                state->spawnTimer = state->spawnPeriod + randomGetRange(0, state->spawnJitter);
            }
            break;
        case 2:
            if ((GameBit_Get(state->gameBit) != 0 || state->gameBit == -1) &&
                (state->spawnTimer -= framesThisStep, state->spawnTimer <= 0))
            {
                setup = Obj_AllocObjectSetup(0x28, 0x263);
                *(u8*)(setup + 4) = 4;
                *(u8*)(setup + 5) = 2;
                ((ObjPlacement*)setup)->posX = placement->base.posX;
                ((ObjPlacement*)setup)->posY = placement->base.posY + (f32)(int)
                randomGetRange(-0x28, 0x28);
                ((ObjPlacement*)setup)->posZ = placement->base.posZ + (f32)(int)
                randomGetRange(-0x28, 0x28);
                *(s16*)(setup + 0x20) = 100;
                *(s16*)(setup + 0x1e) = 0x10f;
                *(s16*)(setup + 0x22) = 0xffff;
                *(s16*)(setup + 0x18) = randomGetRange(-500, 500) + 0x5dc;
                *(s16*)(setup + 0x1c) = randomGetRange(-500, 500) + 0x5dc;
                spawned = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                          *(int*)&((GameObject*)obj)->anim.parent);
                if ((u32)spawned != 0)
                {
                    ((GameObject*)spawned)->anim.velocityX = lbl_803E5CD0 - (f32)(int)
                    randomGetRange(0, 10);
                }
                state->spawnTimer = state->spawnPeriod + randomGetRange(0, state->spawnJitter);
            }
            break;
        case 4:
            if (GameBit_Get(state->gameBit) != 0 || state->gameBit == -1)
            {
                n = 2;
                do
                {
                    int setup;
                    n -= 1;
                    setup = Obj_AllocObjectSetup(0x28, 0x263);
                    *(u8*)(setup + 4) = 0x20;
                    *(u8*)(setup + 5) = 2;
                    *(u8*)(setup + 7) = 0xff;
                    ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
                    ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
                    ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
                    *(s16*)(setup + 0x20) = 400;
                    *(s16*)(setup + 0x1e) = 0xf;
                    *(s16*)(setup + 0x22) = 0x222;
                    *(s16*)(setup + 0x18) = 0;
                    *(s16*)(setup + 0x1a) = 0;
                    *(s16*)(setup + 0x1c) = 0;
                    *(u8*)(setup + 0x24) = 0;
                    spawned = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                              *(int*)&((GameObject*)obj)->anim.parent);
                    if ((u32)spawned != 0)
                    {
                        *(u8*)(*(int*)&((GameObject*)spawned)->extra + 0x120) |= 2;
                        ((GameObject*)spawned)->anim.velocityX = lbl_803E5CD4 * (f32)(int)
                        randomGetRange(-0x23, 0x23);
                        ((GameObject*)spawned)->anim.velocityZ = lbl_803E5CD4 * (f32)(int)
                        randomGetRange(-0x23, 0x23);
                        ((GameObject*)spawned)->anim.velocityY = lbl_803E5CD8;
                        vec.pos[0] = lbl_803E5CC8;
                        vec.dir[0] = 0;
                        vec.dir[1] = 0;
                        vec.dir[2] = 0;
                        vec.pos[1] = ((GameObject*)spawned)->anim.velocityX;
                        vec.pos[3] = ((GameObject*)spawned)->anim.velocityZ;
                        vec.pos[2] = lbl_803E5CD8;
                        (*gPartfxInterface)->spawnObject((void*)spawned, 0x1a7, &vec,
                                                         0x10000, -1, NULL);
                    }
                }
                while (n != 0);
                GameBit_Set(state->gameBit, 0);
            }
            break;
        case 7:
            if ((GameBit_Get(state->gameBit) != 0 || state->gameBit == -1) &&
                (state->spawnTimer -= framesThisStep, state->spawnTimer <= 0))
            {
                setup = Obj_AllocObjectSetup(0x28, 0x263);
                *(u8*)(setup + 4) = 4;
                *(u8*)(setup + 5) = 2;
                ((ObjPlacement*)setup)->posX = placement->base.posX + (f32)(int)
                randomGetRange(-0x28, 0x28);
                ((ObjPlacement*)setup)->posY = placement->base.posY + (f32)(int)
                randomGetRange(0, 0x14);
                ((ObjPlacement*)setup)->posZ = placement->base.posZ + (f32)(int)
                randomGetRange(-0x28, 0x28);
                *(s16*)(setup + 0x20) = 0x1c2;
                *(s16*)(setup + 0x1e) = randomGetRange(0, 2) + 0x1cc;
                *(s16*)(setup + 0x22) = 0xffff;
                *(s16*)(setup + 0x18) = randomGetRange(-500, 500) + 0x5dc;
                *(s16*)(setup + 0x1c) = randomGetRange(-500, 500) + 0x5dc;
                Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                *(int*)&((GameObject*)obj)->anim.parent);
                state->spawnTimer = state->spawnPeriod + randomGetRange(0, state->spawnJitter);
            }
            break;
        case 6:
            if (GameBit_Get(state->gameBit) != 0 || state->gameBit == -1)
            {
                setup = Obj_AllocObjectSetup(0x24, 700);
                ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX + (f32)(int)
                randomGetRange(-0x104, 0x104);
                ((ObjPlacement*)setup)->posY = lbl_803E5CDC + ((GameObject*)obj)->anim.localPosY;
                ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ + (f32)(int)
                randomGetRange(-0x50, 0x50);
                *(u8*)(setup + 4) = 0x20;
                *(u8*)(setup + 5) = 2;
                *(u8*)(setup + 7) = 0xff;
                *(s16*)(setup + 0x1e) = 0xffff;
                *(s8*)(setup + 0x18) = *(s16*)obj >> 8;
                Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                *(int*)&((GameObject*)obj)->anim.parent);
                for (n = randomGetRange(2, 5); n != 0; n -= 1)
                {
                    vec.pos[0] = 1.0f;
                    vec.dir[0] = 0;
                    vec.dir[1] = 0;
                    vec.dir[2] = 0;
                    vec.pos[1] = (f32)(int)
                    randomGetRange(-200, 200);
                    vec.pos[3] = (f32)(int)
                    randomGetRange(-0x14, 0x14);
                    vec.pos[2] = 200.0f;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x1a6, &vec, 0x10002, -1,
                                                     NULL);
                }
                GameBit_Set(state->gameBit, 0);
            }
            break;
        }
    }
}

void WM_ObjCreator_release(void)
{
}

void WM_ObjCreator_initialise(void)
{
}

void WM_Galleon_hitDetect(void);

void WM_ObjCreator_init(int* obj, s8* def)
{
    WmObjCreatorPlacement* placement = (WmObjCreatorPlacement*)def;
    WmObjCreatorState* state = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)((s32)placement->yaw << 8);
    state->gameBit = placement->gameBit;
    state->spawnPeriod = placement->spawnPeriod;
    state->spawnTimer = state->spawnPeriod;
    state->spawnJitter = (s16)(s32)
    placement->spawnJitter;
}
