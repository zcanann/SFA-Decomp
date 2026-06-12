/* === moved from main/dll/DIM/DIMcannon.c [801B0670-801B0924) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/DIM/dimcannon_state.h"
#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/DIM/DIMcannon.h"
#include "main/dll/DIM/dimlogfire.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"
#include "global.h"

typedef struct Lavaball1bePlacement
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 pad19[0x20 - 0x19];
} Lavaball1bePlacement;


typedef struct Lavaball1bfPlacement
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 pad19[0x1E - 0x19];
    s16 unk1E;
    u8 pad20[0x24 - 0x20];
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} Lavaball1bfPlacement;


/* imanimspacecraft_getExtraSize == 0x4. */
typedef struct ImAnimSpacecraftState
{
    s16 blinkTimer; /* 0x00 */
    u8 maskBits; /* 0x02: per-event toggle bits (bit4..6 = group) */
    u8 flags; /* 0x03: 2 = blink phase, 4/8 = SeqFn toggles */
} ImAnimSpacecraftState;

STATIC_ASSERT(sizeof(ImAnimSpacecraftState) == 0x4);

/* imspacethruster_getExtraSize == 0xc. */
typedef struct ImSpaceThrusterState
{
    u8 kind; /* 0x00: thruster slot from def+0x19 */
    u8 phase; /* 0x01 */
    s16 blendTimer; /* 0x02 */
    void* bufA; /* 0x04: mmAlloc'd getTabEntry rows */
    void* bufB; /* 0x08 */
} ImSpaceThrusterState;

STATIC_ASSERT(sizeof(ImSpaceThrusterState) == 0xC);

/* link_levcontrol_getExtraSize == 0x10. */
typedef struct LinkLevControlState
{
    s8 areaCell; /* 0x00 */
    u8 pad01[3];
    int unk04; /* 0x04: init -1 */
    int musicTrack; /* 0x08 */
    int latch; /* 0x0c: SCGameBitLatch block */
} LinkLevControlState;

STATIC_ASSERT(sizeof(LinkLevControlState) == 0x10);

/* lavaball1be extra (getExtraSize 0x14 for the non-0x1fa variant). */
typedef struct Lavaball1beState
{
    char* targetObj; /* 0x00: ObjList_FindObjectById(linkedId) */
    u8* light; /* 0x04 */
    f32 floorY; /* 0x08: spawn height; falling below it re-arms */
    int linkedId; /* 0x0c */
    u8 flags; /* 0x10: 8 = ticked, 0x10 = dormant, 0x20 = whistle sfx */
    u8 explodeCooldown; /* 0x11 */
    u8 pad12[2];
} Lavaball1beState;

STATIC_ASSERT(sizeof(Lavaball1beState) == 0x14);

/* lavaball1bf_getExtraSize == 0x1c (launcher). */
typedef struct Lavaball1bfState
{
    u8 pad00[8];
    int* spawnedObj; /* 0x08: the 0x18d cannon object */
    f32 fireTimer; /* 0x0c */
    f32 firePeriod; /* 0x10 */
    s16 gateA; /* 0x14 */
    s16 pending; /* 0x16 */
    u8 gateB; /* 0x18 */
    u8 pad19;
    u8 gbState; /* 0x1a */
    u8 soloLatch; /* 0x1b */
} Lavaball1bfState;

STATIC_ASSERT(sizeof(Lavaball1bfState) == 0x1C);

static inline int* DIMcannon_GetActiveModel(void* obj);

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017ac8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80057690();
extern undefined4 FUN_801adca0();
extern undefined8 FUN_80286830();
extern undefined4 FUN_8028687c();

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern EffectInterface** gPartfxInterface;
extern MapEventInterface** gMapEventInterface;

extern void imicepillar_free(void);
extern int imicepillar_getObjectTypeId(void);
extern int imicepillar_getExtraSize(void);

/*
 * --INFO--
 *
 * Function: imicepillar_render
 * EN v1.0 Address: 0x801AE100
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801AE134
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_801ae0_dropped_old_imicepillar_render(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4, undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9);

/*
 * --INFO--
 *
 * Function: FUN_801ae184
 * EN v1.0 Address: 0x801AE184
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x801AE160
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ae184(undefined4 param_1, undefined4 param_2, undefined4 param_3, undefined4 param_4, undefined4 param_5, char param_6);


/*
 * --INFO--
 *
 * Function: FUN_801ae9e4
 * EN v1.0 Address: 0x801AE9E4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801AE9BC
 * EN v1.1 Size: 48b
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
 * Function: FUN_801aea18
 * EN v1.0 Address: 0x801AEA18
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801AE9EC
 * EN v1.1 Size: 76b
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
 * Function: FUN_801aea40
 * EN v1.0 Address: 0x801AEA40
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801AEA38
 * EN v1.1 Size: 148b
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
 * Function: FUN_801aea44
 * EN v1.0 Address: 0x801AEA44
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x801AEACC
 * EN v1.1 Size: 72b
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
 * Function: FUN_801b0190
 * EN v1.0 Address: 0x801B0190
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801AFE04
 * EN v1.1 Size: 96b
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
 * Function: FUN_801b01e8
 * EN v1.0 Address: 0x801B01E8
 * EN v1.0 Size: 308b
 * EN v1.1 Address: 0x801AFE64
 * EN v1.1 Size: 200b
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
void imicepillar_hitDetect(void);

void imicepillar_update(void);

void imicepillar_init(void);

void imicepillar_release(void);

void imicepillar_initialise(void);

ObjectDescriptor gIMIcePillarObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)imicepillar_initialise,
    (ObjectDescriptorCallback)imicepillar_release,
    0,
    (ObjectDescriptorCallback)imicepillar_init,
    (ObjectDescriptorCallback)imicepillar_update,
    (ObjectDescriptorCallback)imicepillar_hitDetect,
    (ObjectDescriptorCallback)imicepillar_render,
    (ObjectDescriptorCallback)imicepillar_free,
    (ObjectDescriptorCallback)imicepillar_getObjectTypeId,
    imicepillar_getExtraSize,
};

void imanimspacecraft_modelMtxFn(void);

void imanimspacecraft_hitDetect(void);

void imanimspacecraft_release(void);

void imanimspacecraft_initialise(void);

void imspacethruster_hitDetect(void);

void imspacethruster_release(void);

void imspacethruster_initialise(void);

void imspacering_free(void);

void imspacering_hitDetect(void);

void imspacering_release(void);

void imspacering_initialise(void);

void imspaceringgen_hitDetect(void);

void imspaceringgen_release(void);

void imspaceringgen_initialise(void);

void lavaball1be_hitDetect(void);

void lavaball1be_release(void);

void lavaball1be_initialise(void);

void lavaball1bf_hitDetect(void);

void lavaball1bf_release(void);

void lavaball1bf_initialise(void);

/* 8b "li r3, N; blr" returners. */
int imanimspacecraft_getExtraSize(void);
int imanimspacecraft_getObjectTypeId(void);
int imspacethruster_getExtraSize(void);
int imspacethruster_getObjectTypeId(void);
int imspacering_getExtraSize(void);
int imspacering_getObjectTypeId(void);
int imspaceringgen_getExtraSize(void);
int imspaceringgen_getObjectTypeId(void);
int linkb_levcontrol_getExtraSize(void);
int link_levcontrol_getExtraSize(void);
int lavaball1bf_getExtraSize(void);
int lavaball1bf_getObjectTypeId(void);
int dimlogfire_getExtraSize(void) { return 0x24; }
int dimlogfire_getObjectTypeId(void) { return 0x1; }

/* Pattern wrappers. */
extern u32 lbl_803DDB48;
void imspaceringgen_free(void);

/* Init: clear obj->_F4 and record obj globally in lbl_803DDB48. */
void imspaceringgen_init(int* obj);

/* If obj->_F4 == 0, set it to 1; else early-return. */
void imanimspacecraft_update(int* obj);

/* Free: call vtable[6] on obj through global dll-services pointer. */
void imanimspacecraft_free(int* obj);

extern f32 lbl_803E4784;
extern char lbl_803AC948[];

void imanimspacecraft_init(int* obj);

/* setScale (test): is bit (1 << idx) set in obj->_b8->_2? Returns 1/0. */
int imanimspacecraft_setScale(int* obj, int bitIdx);

/* lavaball1bf "consume" hook: only clear pending flag if both gates set. */
void lavaball1bf_func11(int* obj);

/* lavaball1bf "request" hook: set pending if gated, return success. */
int lavaball1bf_setScale(int* obj);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4768;
extern f32 lbl_803E4780;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E4788;
extern f32 lbl_803E47B8;
extern f32 lbl_803E4810;

void imicepillar_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void imanimspacecraft_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void imspacethruster_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void imspacering_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void lavaball1bf_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* if (o->_X == K) return A; else return B;  pattern. */
int lavaball1be_getExtraSize(int* obj);

int lavaball1be_getObjectTypeId(int* obj);

/* chained byte mask. */
u32 imanimspacecraft_func0B(int* obj);
u32 lavaball1be_func11(int* obj);

int fn_801B0784(int obj, int delta)
{
    s8* inner = ((GameObject*)obj)->extra;
    inner[0x1c] = (s8)(inner[0x1c] - delta);
    return inner[0x1c] <= 0;
}

extern void Music_Trigger(int id, int p2);
extern int getSaveGameLoadStatus(void);
extern int coordsToMapCell(f32 x, f32 z);

void link_levcontrol_free(int obj);

void link_levcontrol_update(int* obj);

extern void* gSHthorntailAnimationInterface;
extern void SCGameBitLatch_Update(void* p, int a, int b, int c, int d, int e);

void link_levcontrol_updateAreaMusic(int* obj);

extern void fn_80088870(u8 * a, u8 * b, u8 * c, u8 * d);
extern void envFxActFn_800887f8(int id);
extern void getEnvfxAct(int a, int b, int c, int d);
extern u8 lbl_803239F0[];

void link_levcontrol_applyEnterAreaEffects(int* obj);

extern void ObjModel_SetBlendChannelTargets(int* model, int channel, int p3, int p4, f32 weight, int p6);
extern void ObjModel_SetBlendChannelWeight(int* model, int channel, f32 weight);
extern f32 lbl_803E47A8, lbl_803E47AC, lbl_803E47B0, lbl_803E47B4, lbl_803E4798, lbl_803E4788;
extern s16 lbl_80323818[], lbl_80323824[];

void imspacethruster_init(int* obj, u8* param2);

void link_levcontrol_init(int* obj);

extern u8 lbl_803238D8[];
extern void getEnvfxActImmediately(int a, int b, int c, int d);
extern void fn_80138908(int* tricky, int mode);
extern f32 timeDelta;
extern f32 lbl_803E47C8;

typedef struct
{
    int flags;
    s8 cnt : 2;
    u8 stage : 3;
    u8 low : 3;
    u8 flag5 : 1;
    u8 pad5 : 7;
    u8 pad6[2];
    f32 timer;
    s16 music;
} LinkbLevState;

void linkb_levcontrol_init(int* obj);

void linkb_levcontrol_update(int* obj);

extern f32 lbl_803E47C0;
extern u8 framesThisStep;
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern int* ObjList_GetObjects(int* startIndex, int* objectCount);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int extraSize, int id);
extern void Obj_SetupObject(int obj, int a, int b, int c, int d);
extern f32 lbl_803E47C4;

typedef struct
{
    int* ringA;
    int* ringB;
    u8 visible;
} RingGenState;

void imspacering_init(s16* obj, s8* p);

void imspacering_update(s16* obj);

void imspaceringgen_render(int obj, int p1, int p2, int p3, int p4, s8 visible);

void imspaceringgen_update(s16* obj);

extern void ModelLightStruct_free(void* light);
extern void mm_free(void* p);

extern f32 lbl_803E4814;

void lavaball1bf_init(s16* obj, u8* p);

void lavaball1bf_free(int obj, int mode);

void lavaball1be_free(int obj);

void imspacethruster_free(int obj);

void dimlogfire_free(int* obj, int mode)
{
    extern void Obj_FreeObject(void* o); /* #57 */
    DimLogFireState* inner = ((GameObject*)obj)->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    if ((void*)inner->subObj != NULL && mode == 0)
    {
        Obj_FreeObject((int*)inner->subObj);
    }
    ObjGroup_RemoveObject(obj, 0x31);
    if ((void*)inner->light != NULL)
    {
        ModelLightStruct_free((void*)inner->light);
    }
}

extern void Sfx_StopObjectChannel(int* obj, int channel);

int dimlogfire_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern int Sfx_PlayFromObject(int* obj, int sfxId); /* #57 */
    DimLogFireState* state = ((GameObject*)obj)->extra;
    if (state->mode == 1)
    {
        Sfx_PlayFromObject(obj, SFXmn_eggylaugh216);
    }
    else
    {
        Sfx_StopObjectChannel(obj, 64);
    }
    switch (animUpdate->triggerCommand)
    {
    case 1:
        state->smokeToggle = (u8)(state->smokeToggle ^ 1);
        break;
    case 2:
        GameBit_Set(46, 1);
        break;
    case 3:
        state->mode = 4;
        break;
    }
    if (state->smokeToggle != 0)
    {
        (*gPartfxInterface)->spawnObject(obj, 215, NULL, 0, -1, NULL);
        Sfx_StopObjectChannel(obj, 5);
    }
    else
    {
        Sfx_StopObjectChannel(obj, 1);
    }
    animUpdate->triggerCommand = 0;
    return 0;
}

extern void queueGlowRender(int* obj);
extern f32 lbl_803E4820;

void dimlogfire_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    DimLogFireState* state;
    int* subobj;
    if ((s32)visible != 0)
    {
        state = ((GameObject*)obj)->extra;
        subobj = (int*)state->subObj;
        if (subobj != NULL)
        {
            int* q = (int*)((ObjAnimComponent*)subobj)->banks[((ObjAnimComponent*)subobj)->bankIndex];
            *(u16*)((char*)q + 0x18) = (u16)(*(u16*)((char*)q + 0x18) & ~0x8);
            *(u8*)((char*)(int*)state->subObj + 0x37) = *(u8*)((char*)obj + 0x37);
            ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(
                (int*)state->subObj, p2, p3, p4, p5, lbl_803E4820);
        }
        ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E4820);
        if (*(void**)&state->light != NULL)
        {
            if (*(u8*)((char*)*(void**)&state->light + 0x2f8) != 0)
            {
                if (*(u8*)((char*)*(void**)&state->light + 0x4c) != 0)
                {
                    queueGlowRender(*(int**)&state->light);
                }
            }
        }
    }
}

extern int modelLightStruct_getActiveState(int* p);
extern f32 lbl_803E47F0;

void lavaball1be_render(int* obj, int p2, int p3, int p4, int p5);

extern void spawnExplosion(s16* obj, f32 scale, int a, int b, int c, int d, int e, int f, int g);
extern void modelLightStruct_updateGlowAlpha(int p);
extern f32 lbl_803E47D0, lbl_803E47F4, lbl_803E47F8, lbl_803E47FC;
extern f32 lbl_803E47D4, lbl_803E47D8, lbl_803E47DC, lbl_803E47E0;
extern f32 lbl_803E4800, lbl_803E4804, lbl_803E4808;
extern u8 lbl_802C2318[];
extern void vecRotateZXY(void* in, void* out);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);

typedef struct
{
    f32 x, y, z;
} LavaVec;

void lavaball1be_init(s16* obj, u8* p);

void lavaball1be_update(s16* obj);

extern int* objFindTexture(int* obj, int a, int b);
extern f32 lbl_803E4770, lbl_803E4774, lbl_803E4778, lbl_803E477C;

int imanimspacecraft_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate);

extern f32 lbl_803E478C, lbl_803E4790, lbl_803E4794, lbl_803E4798;

void imspacethruster_update(int* obj);


void lavaball1bf_update(int* obj);

void lavaball1be_setScale(s16* obj, int p2, int p3);

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

#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/dll/DIM/DIMlavasmash.h"
#include "main/dll/DIM/dimlogfire.h"
#include "main/objanim_internal.h"

typedef struct DimlogfirePlacement
{
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
    u8 pad20[0x68 - 0x20];
    void* unk68;
    u8 pad6C[0x70 - 0x6C];
} DimlogfirePlacement;


typedef struct DimlogfireObjectDef
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 strengthInit;
    s16 unk1E;
} DimlogfireObjectDef;


typedef struct DimsnowballState
{
    u8 pad0[0xC - 0x0];
    s8 unkC;
    u8 padD[0x10 - 0xD];
} DimsnowballState;


extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern void fn_80098B18(int obj, f32 scale, int type, int param_4, int param_5, int param_6);
extern undefined4 ObjGroup_AddObject();
extern void modelLightStruct_setSpecularColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setEnabled(int light, int mode, f32 value);
extern void modelLightStruct_setPosition(int light, f32 x, f32 y, f32 z);
extern void modelLightStruct_startColorFade(int light, int param_2, int param_3);
extern void modelLightStruct_setDiffuseTargetColor(int light, int r, int g, int b, int a);

extern EffectInterface** gPartfxInterface;
extern f64 DOUBLE_803e54b0;
extern f64 DOUBLE_803e54d8;
extern f32 timeDelta;
extern f32 oneOverTimeDelta;
extern u8 framesThisStep;
extern s16 lbl_803DBEE8;
extern f32 lbl_803DC074;
extern s16 gDimSnowballCoords[];
extern f32 lbl_803E4820;
extern f32 lbl_803E4824;
extern f32 lbl_803E4828;
extern f32 lbl_803E482C;
extern f32 lbl_803E4830;
extern f32 lbl_803E4834;
extern f32 lbl_803E4838;
extern f32 lbl_803E483C;
extern f64 lbl_803E4840;
extern f32 lbl_803E484C;
extern f32 lbl_803E4850;
extern f32 lbl_803E4854;
extern f64 lbl_803E4858;
extern f32 lbl_803E54AC;
extern f32 lbl_803E54B8;
extern f32 lbl_803E54BC;
extern f32 lbl_803E54C0;
extern f32 lbl_803E54C4;
extern f32 lbl_803E54C8;
extern f32 lbl_803E54CC;
extern f32 lbl_803E54D0;
extern f32 lbl_803E54D4;

/*
 * --INFO--
 *
 * Function: dimlogfire_update
 * EN v1.0 Address: 0x801B0924
 * EN v1.0 Size: 708b
 * EN v1.1 Address: 0x801B0B58
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimlogfire_update(int obj)
{
    extern int getTrickyObject(void); /* #57 */
    extern void Sfx_PlayFromObject(int obj, int sfxId); /* #57 */
    int a;
    int b;
    int rand;
    s16 alpha;
    uint light;
    int tricky;
    DimLogFireState* state;
    struct
    {
        f32 x, y, z;
    } vec;

    state = ((GameObject*)obj)->extra;
    tricky = *(int*)&((GameObject*)obj)->anim.placementData;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    switch (state->mode)
    {
    case 1:
        if (*(int**)&state->light != NULL)
        {
            modelLightStruct_setEnabled(state->light, 1, lbl_803E4824);
        }
        Sfx_PlayFromObject(obj, SFXmn_eggylaugh216);
        state->flickerTimerA = state->flickerTimerA - timeDelta;
        if (state->flickerTimerA <= lbl_803E4828)
        {
            a = 7;
            state->flickerTimerA = state->flickerTimerA + lbl_803E482C;
        }
        else
        {
            a = 0;
        }
        state->flickerTimerB = state->flickerTimerB - timeDelta;
        if (state->flickerTimerB <= lbl_803E4828)
        {
            b = 1;
            state->flickerTimerB = state->flickerTimerB + lbl_803E4820;
        }
        else
        {
            b = 0;
        }
        vec.x = lbl_803E4828;
        vec.y = lbl_803E482C;
        vec.z = lbl_803E4828;
        fn_80098B18(obj, ((GameObject*)obj)->anim.rootMotionScale, 2, a, b, (int)&vec);
        ObjHits_SetHitVolumeSlot(obj, 0x1f, 1, 0);
        break;
    case 2:
        if (*(int**)&state->light != NULL)
        {
            modelLightStruct_setEnabled(state->light, 0, lbl_803E4824);
        }
        if (state->strengthInit <= 0)
        {
            ObjHits_DisableObject(obj);
            state->mode = 1;
            state->dousedLatch = 1;
            GameBit_Set(((DimlogfirePlacement*)tricky)->unk1E, 1);
        }
        tricky = getTrickyObject();
        if ((uint)tricky != 0)
        {
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
            {
                (*(void (**)(int, int, int, int))(**(int**)&((DimlogfirePlacement*)tricky)->unk68 + 0x28))(
                    tricky, obj, 1, 4);
            }
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
        }
        ObjHits_SetHitVolumeSlot(obj, 0, 0, 0);
        break;
    case 4:
        break;
    default:
        if (state->unk18 == 0)
        {
            state->mode = 1;
            state->dousedLatch = 1;
        }
        else
        {
            state->mode = 2;
        }
        break;
    }
    if (*(s8*)&state->dousedLatch != 0)
    {
        state->dousedLatch = 0;
    }
    light = state->light;
    if (light != 0 && *(u8*)(light + 0x2f8) != 0 && *(u8*)(light + 0x4c) != 0)
    {
        rand = randomGetRange(-0x19, 0x19);
        light = state->light;
        alpha = *(u8*)(light + 0x2f9) + (*(s8*)(light + 0x2fa) + rand);
        if (alpha < 0)
        {
            alpha = 0;
            *(u8*)(light + 0x2fa) = 0;
        }
        else if (alpha > 0xff)
        {
            alpha = 0xff;
            *(u8*)(light + 0x2fa) = 0;
        }
        *(u8*)(state->light + 0x2f9) = alpha;
    }
}

/*
 * --INFO--
 *
 * Function: FUN_801b09dc
 * EN v1.0 Address: 0x801B09DC
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x801B0C24
 * EN v1.1 Size: 336b
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
 * Function: dimlogfire_init
 * EN v1.0 Address: 0x801B0BE8
 * EN v1.0 Size: 492b
 * EN v1.1 Address: 0x801B0DFC
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void dimlogfire_init(int obj, int def)
{
    extern void modelLightStruct_setGlowProjectionRadius(int light, f32 radius); /* #57 */
    extern void modelLightStruct_setupGlow(int light, int param_2, int r, int g, int b, int a, f32 radius); /* #57 */
    extern void modelLightStruct_setDistanceAttenuation(int light, f32 near, f32 far); /* #57 */
    extern void modelLightStruct_setDiffuseColor(int light, int r, int g, int b, int a); /* #57 */
    extern void modelLightStruct_setLightKind(int light, int value); /* #57 */
    extern int objCreateLight(int obj, int param_2); /* #57 */
    int radius;
    DimLogFireState* state;

    ((GameObject*)obj)->animEventCallback = (void*)dimlogfire_SeqFn;
    ObjGroup_AddObject(obj, 0x31);
    state = ((GameObject*)obj)->extra;
    state->unk20 = 0;
    state->unk18 = ((DimlogfireObjectDef*)def)->unk1A;
    state->strengthInit = (s8)((DimlogfireObjectDef*)def)->strengthInit;
    *(u8*)&state->strength = *(u8*)&state->strengthInit;
    if (GameBit_Get(((DimlogfireObjectDef*)def)->unk1E) != 0)
    {
        state->mode = 1;
        state->dousedLatch = 1;
    }
    ((GameObject*)obj)->objectFlags |= 0x2000;
    state->flickerTimerA = lbl_803E482C;
    state->flickerTimerB = lbl_803E4820;
    if (*(int**)&state->light == NULL)
    {
        state->light = objCreateLight(obj, 1);
    }
    if (*(int**)&state->light != NULL)
    {
        modelLightStruct_setLightKind(state->light, 2);
        modelLightStruct_setDiffuseColor(state->light, 0xff, 0x7f, 0, 0xff);
        modelLightStruct_setSpecularColor(state->light, 0xff, 0x7f, 0, 0xff);
        radius = (int)(lbl_803E4830 * ((GameObject*)obj)->anim.rootMotionScale);
        modelLightStruct_setDistanceAttenuation(state->light, (f32)radius, lbl_803E4834 + (f32)radius);
        modelLightStruct_setEnabled(state->light, 1, lbl_803E4828);
        modelLightStruct_setPosition(state->light, lbl_803E4828, lbl_803E4838, *(f32*)&lbl_803E4828);
        modelLightStruct_startColorFade(state->light, 1, 3);
        modelLightStruct_setDiffuseTargetColor(state->light, 0xff, 0x5c, 0, 0xff);
        modelLightStruct_setupGlow(state->light, 0, 0xff, 0x7f, 0, 0x87,
                                   lbl_803E483C * ((GameObject*)obj)->anim.rootMotionScale);
        modelLightStruct_setGlowProjectionRadius(state->light, lbl_803E4834);
    }
}

/*
 * --INFO--
 *
 * Function: dimsnowball_getExtraSize
 * EN v1.0 Address: 0x801B0DD4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801B0F50
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dimsnowball_getExtraSize(void)
{
    return 0x10;
}

/*
 * --INFO--
 *
 * Function: dimsnowball_getObjectTypeId
 * EN v1.0 Address: 0x801B0DDC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801B0F58
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dimsnowball_getObjectTypeId(void)
{
    return 2;
}

/*
 * --INFO--
 *
 * Function: dimsnowball_free
 * EN v1.0 Address: 0x801B0DE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B0F60
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimsnowball_free(void)
{
}

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4848;
extern void objRenderFn_8003b8f4(f32);

void dimsnowball_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4848);
}

void dimsnowball_hitDetect(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    int* inner = (int*)state[0];
    if ((*(u16*)((char*)inner + 0xb0) & 0x40) == 0) return;
    state[0] = 0;
}

void dimsnowball_update(int obj)
{
    extern void Obj_FreeObject(int obj); /* #57 */
    extern int Obj_GetPlayerObject(void); /* #57 */
    extern void Sfx_PlayFromObject(int obj, int sfxId); /* #57 */
    s16 idx[4];
    f32 x[4];
    f32 y[4];
    f32 z[4];
    void* ap;
    int* state;
    int player;
    int count;
    int last;
    u8 frames;
    u8* model;
    f32 dy1;
    f32 dy2;
    f32 v24;

    ap = idx;
    ap = x;
    ap = y;
    ap = z;
    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    if (*(void**)state == NULL)
    {
        Obj_FreeObject(obj);
        return;
    }
    frames = framesThisStep;
    idx[1] = (s16)state[2];
    count = lbl_803DBEE8;
    last = count - 1;
    if (idx[1] >= last)
    {
        Obj_FreeObject(obj);
        return;
    }
    idx[0] = idx[1] - 1;
    if (idx[0] < 0)
    {
        idx[0] = 0;
    }
    idx[2] = idx[1] + 1;
    if (idx[2] >= count)
    {
        idx[2] = last;
    }
    idx[3] = idx[1] + 2;
    if (idx[3] >= count)
    {
        idx[3] = last;
    }
    idx[0] *= 3;
    x[0] = (f32)gDimSnowballCoords[idx[0]] * lbl_803E484C;
    y[0] = (f32)gDimSnowballCoords[idx[0] + 1] * lbl_803E484C;
    z[0] = (f32)gDimSnowballCoords[idx[0] + 2] * lbl_803E484C;
    idx[1] *= 3;
    x[1] = (f32)gDimSnowballCoords[idx[1]] * lbl_803E484C;
    y[1] = (f32)gDimSnowballCoords[idx[1] + 1] * lbl_803E484C;
    z[1] = (f32)gDimSnowballCoords[idx[1] + 2] * lbl_803E484C;
    idx[2] *= 3;
    x[2] = (f32)gDimSnowballCoords[idx[2]] * lbl_803E484C;
    y[2] = (f32)gDimSnowballCoords[idx[2] + 1] * lbl_803E484C;
    z[2] = (f32)gDimSnowballCoords[idx[2] + 2] * lbl_803E484C;
    idx[3] *= 3;
    x[3] = (f32)gDimSnowballCoords[idx[3]] * lbl_803E484C;
    y[3] = (f32)gDimSnowballCoords[idx[3] + 1] * lbl_803E484C;
    z[3] = (f32)gDimSnowballCoords[idx[3] + 2] * lbl_803E484C;
    dy1 = y[1] - y[0];
    dy2 = y[2] - y[3];
    if (dy2 <= lbl_803E4850 && dy1 <= lbl_803E4850 && ((DimsnowballState*)state)->unkC <= 0)
    {
        sqrtf(((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ +
            (((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX + ((GameObject*)obj)->anim.
                velocityY * ((GameObject*)obj)->anim.velocityY));
        if ((((GameObject*)player)->objectFlags & 0x1000) == 0)
        {
            Sfx_PlayFromObject(obj, SFXfoot_run_jingle2);
        }
        ((DimsnowballState*)state)->unkC = 0x1e;
    }
    ((GameObject*)obj)->anim.localPosX = lbl_803E4850 * (x[2] - x[1]) + x[1];
    ((GameObject*)obj)->anim.localPosY = lbl_803E4850 * (y[2] - y[1]) + y[1];
    ((GameObject*)obj)->anim.localPosZ = lbl_803E4850 * (z[2] - z[1]) + z[1];
    ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.localPosX + *(f32*)(*state + 0xc);
    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + *(f32*)(*state + 0x10);
    ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ + *(f32*)(*state + 0x14);
    ((GameObject*)obj)->anim.velocityX = oneOverTimeDelta * (((GameObject*)obj)->anim.localPosX - ((GameObject*)obj)->
        anim.previousLocalPosX);
    ((GameObject*)obj)->anim.velocityY = oneOverTimeDelta * (((GameObject*)obj)->anim.localPosY - ((GameObject*)obj)->
        anim.previousLocalPosY);
    ((GameObject*)obj)->anim.velocityZ = oneOverTimeDelta * (((GameObject*)obj)->anim.localPosZ - ((GameObject*)obj)->
        anim.previousLocalPosZ);
    state[2] = state[2] + frames;
    if (((DimsnowballState*)state)->unkC > 0)
    {
        ((DimsnowballState*)state)->unkC -= frames;
    }
    v24 = ((GameObject*)obj)->anim.velocityX;
    ((GameObject*)obj)->anim.rotY = (int)-(lbl_803E4854 * -((GameObject*)obj)->anim.velocityZ - (f32)((GameObject*)obj)
        ->anim.rotY);
    ((GameObject*)obj)->anim.rotZ = (int)-(lbl_803E4854 * v24 - (f32)((GameObject*)obj)->anim.rotZ);
    model = *(u8**)&((GameObject*)obj)->anim.hitReactState;
    if (model != NULL)
    {
        ((ObjHitsPriorityState*)model)->flags |= 1;
        *(u8*)&((ObjHitsPriorityState*)model)->hitVolumePriority = 4;
        *(u8*)&((ObjHitsPriorityState*)model)->hitVolumeId = 2;
        *(int*)&((ObjHitsPriorityState*)model)->objectHitMask = 0x10;
        *(int*)&((ObjHitsPriorityState*)model)->skeletonHitMask = 0x10;
    }
}

/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset

/* === moved from main/dll/DIM/dimsnowball_init.c [801B1354-801B13E8) (TU re-split, docs/boundary_audit.md) === */
#include "ghidra_import.h"


typedef struct DimSnowballState
{
    void* target;
    int targetId;
} DimSnowballState;

typedef struct DimSnowballObject
{
    u8 unk0[0x54];
    u8* handle54;
    u8 unk58[0xc];
    u8* handle64;
    u8 unk68[0x48];
    u16 flags;
    u8 unkB2[6];
    DimSnowballState* state;
} DimSnowballObject;

typedef struct DimSnowballDef
{
    u8 unk0[0x14];
    int targetId;
} DimSnowballDef;

void dimsnowball_init(DimSnowballObject* param_1, DimSnowballDef* def)
{
    extern u8* ObjList_FindObjectById(int objectId); /* #57 */
    DimSnowballObject* obj = param_1;
    DimSnowballState* state;

    state = obj->state;
    state->targetId = def->targetId;
    def->targetId = -1;
    state->target = ObjList_FindObjectById(state->targetId);
    if (obj->handle54 != NULL)
    {
        obj->handle54[0x6a] = 0;
    }
    if (obj->handle64 != NULL)
    {
        *(u32*)(obj->handle64 + 0x30) |= 0x810;
    }
    obj->flags = (u16)(obj->flags | 0x4000);
}

void dimsnowball_release(void)
{
}

void dimsnowball_initialise(void)
{
}

int dimsnowball1c2_getExtraSize(void);
