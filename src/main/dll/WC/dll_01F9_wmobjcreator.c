/* === moved from main/dll/WC/WClevcontrol.c [801EF360-801EF3A8) (TU re-split, docs/boundary_audit.md) === */
#include "main/expgfx.h"

typedef struct SBCloudRunnerState
{
    u8 pad0[0x10 - 0x0];
    s32 unk10;
    u8 pad14[0x2C - 0x14];
    s16 unk2C;
    s16 rotZ;
    u8 pad30[0x4C - 0x30];
    f32 unk4C;
    f32 unk50;
    f32 unk54;
    u8 pad58[0x64 - 0x58];
    u8 unk64;
    u8 pad65[0x6E - 0x65];
    u8 unk6E;
    u8 pad6F[0x84 - 0x6F];
} SBCloudRunnerState;


extern uint GameBit_Get(int eventId);
extern void WCPushBlock_SpawnFromPath(s16 * path, u8 * state);
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4* DAT_803dd6e4;
extern EffectInterface** gPartfxInterface;
extern f64 DOUBLE_803e6938;
extern f32 lbl_803DC074;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803E6908;
extern f32 lbl_803E690C;
extern f32 lbl_803E6924;
extern f32 lbl_803E6928;
extern f32 lbl_803E692C;
extern f32 lbl_803E6930;
extern f32 lbl_803E6940;
extern f32 lbl_803E6944;
extern f32 lbl_803E6948;
extern f32 lbl_803E694C;
extern f32 lbl_803E6950;
extern f32 lbl_803E6954;
extern f32 lbl_803E6958;

/*
 * --INFO--
 *
 * Function: FUN_801ee668
 * EN v1.0 Address: 0x801EE668
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x801EE880
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801eefcc
 * EN v1.0 Address: 0x801EEFCC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801EF0A0
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801eefd0
 * EN v1.0 Address: 0x801EEFD0
 * EN v1.0 Size: 468b
 * EN v1.1 Address: 0x801EF188
 * EN v1.1 Size: 468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801ef1a4
 * EN v1.0 Address: 0x801EF1A4
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x801EF35C
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801ef200
 * EN v1.0 Address: 0x801EF200
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801EF3B8
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801ef980
 * EN v1.0 Address: 0x801EF980
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801EF8E8
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801ef984
 * EN v1.0 Address: 0x801EF984
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801EF9AC
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void fn_801EED7C(void);

void fn_801EEDA8(void);

void fn_801EEDD4(void);

void SB_CloudRunner_hitDetect(void);

void SB_CloudRunner_release(void);

void SB_CloudRunner_initialise(void);

void WM_ObjCreator_free(void)
{
}

void WM_ObjCreator_hitDetect(void)
{
}

/* 8b "li r3, N; blr" returners. */
int fn_801EEDAC(void);
int fn_801EEDD8(void);
int fn_801EEDFC(void);
int fn_801EEE04(void);
int fn_801EEE2C(void);
int fn_801EEE34(void);
int SB_CloudRunner_getExtraSize(void);
int SB_CloudRunner_getObjectTypeId(void);
int WM_ObjCreator_getExtraSize(void) { return 0x8; }
int WM_ObjCreator_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5CC8;

void WM_ObjCreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderFn_8003b8f4(f32); /* #57 */
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5CC8);
}

extern f32 lbl_803E5C70;

f32 fn_801EEDB4(int unused, f32* p);

/* copy 3 floats from struct to out args */
void fn_801EEDE0(int* src, f32* out_x, f32* out_y, f32* out_z);

/* virtual call through obj[0xb8][0x10] context, vtable double-deref at +0x68 */
void shipBattleFn_801eed24(void* obj);

/* copy 3 floats from obj->b8 [0x4c..0x54] to out args */
void fn_801EED5C(int* obj, f32* x, f32* y, f32* z);

extern void objSetMtxFn_800412d4();

void fn_801EED80(void* obj);

void fn_801EEDC0(int p1, f32* out, int* outInt);

void fn_801EEE0C(int* obj, f32* x, f32* y, f32* z);

/* Path-follow steering update for the cloudrunner block (target 0x801EE668;
 * Ghidra split this body as FUN_801eeafc). */
extern u32 getButtonsHeld(int pad);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E5C98;
extern f32 lbl_803E5CA8;
extern f32 lbl_803E5CAC;
extern f32 lbl_803E5CB0;
extern f32 lbl_803E5CB4;

typedef struct
{
    u8 held : 1;
} WCButtonFlag;

typedef struct
{
    u8 pad[0x1b];
    s8 sfxFlag;
} WCAnimEvents;

void fn_801EE668(s16* obj, u8* state);

/* SB_CloudRunner_HandlePriorityHit: when the laser hits an object whose
 * type isn't 281 and isn't currently in fade state, fade it red, rumble,
 * play SFX, gate further damage on a GameBit, then if the hit type is 154
 * emit 3 partfx of effect 168 followed by a 10-shot burst of effect 169. */
extern int objGetFlagsE5_2(int obj);
extern void Obj_SetModelColorFadeRecursive(int obj, int r, int g, int b, int a, int frames);
extern void doRumble(f32 val);
extern f32 lbl_803E5CB8;
extern f32 lbl_803E5C74;

struct WCPartfxArgs
{
    s16 v[3];
    s16 _pad;
    f32 scale;
};

void SB_CloudRunner_HandlePriorityHit(int obj, u8* state);

extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern void Obj_BuildInverseWorldTransformMatrix(int obj, f32* mtx);
extern void PSMTXMultVec(f32 * mtx, f32 * in, f32 * out);

void SB_CloudRunner_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

extern int Obj_GetPlayerObject(void);
extern void SB_CloudRunner_onSeqFree(void);
extern void objHitDetectFn_80062e84(int player, int hitObj, int p3);
extern void fn_80295918(int player, int p2, f32 p3);


extern void textureFree(void* tex);

void SB_CloudRunner_free(int* obj);

extern void* textureLoadAsset(int id);

void SB_CloudRunner_init(int* obj);

extern void setAButtonIcon(int idx);
extern int padGetStickX(int controller);
extern int padGetStickY(int controller);
extern f32 lbl_803E5CA0;
extern f32 lbl_803E5CBC;
extern f32 lbl_803E5CC0;
extern void WCPushBlock_UpdateRideTilt(int obj, int state);
extern void WCPushBlock_UpdateCloudAction(int obj, int state);

void SB_CloudRunner_update(int obj);

/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

#include "main/dll/WC/dll_01F9_wmobjcreator.h"
#include "main/effect_interfaces.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/resource.h"

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


extern u32 randomGetRange(int min, int max);
extern void getLActions(int obj, int obj2, int action, int p4, int p5, int p6);
extern void* FUN_80017aa4();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_803dc070;
extern u32 lbl_803DC0F0;
extern s8 lbl_803DDC70;
extern undefined4 DAT_803de8e8;
extern int* gScreensInterface;
extern undefined4* lbl_803DCA94;
extern void* lbl_803DDC74;
extern f64 DOUBLE_803e6978;
extern f32 lbl_803E5CE8;
extern f32 lbl_803E6960;
extern f32 lbl_803E6964;
extern f32 lbl_803E6968;
extern f32 lbl_803E696C;
extern f32 lbl_803E6970;
extern f32 lbl_803E6974;


#define WM_GALLEON_GAMEBIT_CUTSCENE_DONE 0x429
#define WM_GALLEON_GAMEBIT_CLEAR_DOOR 0xD1
#define WM_GALLEON_COMMAND_OPENED 1
#define WM_GALLEON_COMMAND_CLEAR_LACTIONS 2
#define WM_GALLEON_COMMAND_SCREEN_FADE 3
#define WM_GALLEON_COMMAND_ACTION_12 4
#define WM_GALLEON_COMMAND_ACTION_13 5
#define WM_GALLEON_COMMAND_CLEAR_MAP_EVENTS 6
#define WM_GALLEON_COMMAND_SHOW_MODEL 7
#define WM_GALLEON_COMMAND_HIDE_MODEL 8
#define WM_GALLEON_COMMAND_ACTION_11 9
#define WM_GALLEON_ACTION_OPENED 10
#define WM_GALLEON_ACTION_11 11
#define WM_GALLEON_ACTION_12 12
#define WM_GALLEON_ACTION_13 13

#define OBJ_U8(obj, offset) (*(u8 *)((u8 *)(obj) + (offset)))
#define OBJ_S16(obj, offset) (*(s16 *)((u8 *)(obj) + (offset)))
#define OBJ_S32(obj, offset) (*(s32 *)((u8 *)(obj) + (offset)))

/*
 * --INFO--
 *
 * Function: WM_ObjCreator_update
 * EN v1.0 Address: 0x801EF3A8
 * EN v1.0 Size: 3548b
 * EN v1.1 Address: 0x801EF9E0
 * EN v1.1 Size: 2956b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int a, int b);
extern int Obj_SetupObject(int setup, int a, int b, int c, int d);
extern int lbl_803DDC68;
extern f32 lbl_803E5CCC;
extern f32 lbl_803E5CD0;
extern f32 lbl_803E5CD4;
extern f32 lbl_803E5CD8;
extern f32 lbl_803E5CDC;

void WM_ObjCreator_update(int obj)
{
    extern undefined8 GameBit_Set(int eventId, int value); /* #57 */
    extern void* ObjGroup_GetObjects(); /* #57 */
    WmObjCreatorPlacement* placement;
    WmObjCreatorState* state;
    int count;
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
                s8 ok = 0;
                if (((GameObject*)obj)->unkF8 == 0)
                {
                    int* objs;
                    int k;
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
                    int setup = Obj_AllocObjectSetup(0x24, 0x139);
                    int spawned;
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
                int spawned;
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
                int setup = Obj_AllocObjectSetup(0x24, 0x275);
                int spawned;
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
                int setup = Obj_AllocObjectSetup(0x38, 0x4ac);
                int spawned;
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
                int setup = Obj_AllocObjectSetup(0x28, 0x263);
                int spawned;
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
                int n = 2;
                do
                {
                    int setup;
                    int spawned;
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
                        vec.pos[2] = lbl_803E5CD8;
                        ((GameObject*)spawned)->anim.velocityY = lbl_803E5CD8;
                        vec.pos[0] = lbl_803E5CC8;
                        vec.dir[0] = 0;
                        vec.dir[1] = 0;
                        vec.dir[2] = 0;
                        vec.pos[1] = ((GameObject*)spawned)->anim.velocityX;
                        vec.pos[3] = ((GameObject*)spawned)->anim.velocityZ;
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
                int setup = Obj_AllocObjectSetup(0x28, 0x263);
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
                int setup = Obj_AllocObjectSetup(0x24, 700);
                int n;
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
                {
                    f32 size = lbl_803E5CC8;
                    f32 yoff = lbl_803E5CDC;
                    for (n = randomGetRange(2, 5); n != 0; n -= 1)
                    {
                        vec.pos[0] = size;
                        vec.dir[0] = 0;
                        vec.dir[1] = 0;
                        vec.dir[2] = 0;
                        vec.pos[1] = (f32)(int)
                        randomGetRange(-200, 200);
                        vec.pos[3] = (f32)(int)
                        randomGetRange(-0x14, 0x14);
                        vec.pos[2] = yoff;
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x1a6, &vec, 0x10002, -1,
                                                         NULL);
                    }
                }
                GameBit_Set(state->gameBit, 0);
            }
            break;
        }
    }
}


/* Trivial 4b 0-arg blr leaves. */
void WM_ObjCreator_release(void)
{
}

void WM_ObjCreator_initialise(void)
{
}

void WM_Galleon_hitDetect(void);



/* 8b "li r3, N; blr" returners. */
int WM_Galleon_getExtraSize(void);
int WM_Galleon_getObjectTypeId(void);

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

