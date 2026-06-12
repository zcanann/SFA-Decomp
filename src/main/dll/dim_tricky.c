/* === moved from main/dll/shrine1CE.c [801CCFA4-801CCFB4) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling on
#pragma peephole on
#include "ghidra_import.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/shrine1CE.h"
#include "main/dll/torch1CD.h"
#include "main/objseq.h"
#include "main/resource.h"

typedef struct Dll19CPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 posX;
    f32 unkC;
    f32 posZ;
    u8 pad14[0x19 - 0x14];
    u8 unk19;
    u8 pad1A[0x20 - 0x1A];
} Dll19CPlacement;


typedef struct Dll19DPlacement
{
    u8 pad0[0x19 - 0x0];
    u8 unk19;
    u8 pad1A[0x20 - 0x1A];
} Dll19DPlacement;


typedef struct Dll19DState
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x2C - 0x14];
    s16 unk2C;
    s16 unk2E;
    s16 unk30;
    s16 unk32;
    u16 unk34;
    u8 unk36;
    u8 pad37[0x38 - 0x37];
} Dll19DState;


typedef struct Dll19CState
{
    u8 pad0[0x2 - 0x0];
    s16 unk2;
    s16 unk4;
    s16 unk6;
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x2C - 0x14];
    s16 unk2C;
    s16 unk2E;
    s16 unk30;
    s16 unk32;
    u16 unk34;
    u8 unk36;
    u8 pad37[0x38 - 0x37];
} Dll19CState;


typedef struct Dll19BState
{
    u8 pad0[0x12 - 0x0];
    u8 unk12;
    u8 unk13;
    u8 unk14;
    u8 pad15[0x16 - 0x15];
    u8 unk16;
    u8 pad17[0x18 - 0x17];
} Dll19BState;


#pragma peephole off
#pragma scheduling off
extern undefined4 getLActions();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_8001771c();
extern uint FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80135814();
extern int FUN_80286834();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80294d68();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f0;
extern f64 DOUBLE_803e5e40;
extern f32 lbl_803DC074;
extern f32 lbl_803E5E24;
extern f32 lbl_803E5E28;
extern f32 lbl_803E5E2C;
extern f32 lbl_803E5E30;
extern f32 lbl_803E5E34;
extern f32 lbl_803E5E38;
extern f32 lbl_803E5E4C;

/*
 * --INFO--
 *
 * Function: dll_19B_update
 * EN v1.0 Address: 0x801CBD88
 * EN v1.0 Size: 2124b
 * EN v1.1 Address: 0x801CC33C
 * EN v1.1 Size: 2032b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int ObjGroup_FindNearestObject(int group, int obj, f32* outDist);
extern int ObjMsg_Pop(int obj, int* msg, int* a, int* b);
extern uint GameBit_Get(int eventId);
extern f32 Vec_distance(f32 * a, f32 * b);
extern void fn_80296B78(int obj, int a);
extern void fn_80137948(char* fmt, ...);
extern char sShrineTimeFormat[];
extern void* gTitleMenuControlInterface;
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern ModgfxInterface** gModgfxInterface;
extern f32 lbl_803E518C;
extern f32 lbl_803E5190;
extern f32 lbl_803E5194;
extern f32 lbl_803E5198;
extern f32 lbl_803E519C;
extern f32 lbl_803E51A0;
extern f32 timeDelta;
extern u8 framesThisStep;

void dll_19B_update(int obj);


/* Trivial 4b 0-arg blr leaves. */
void dll_19B_release(void);

void dll_19B_initialise(void);

void dll_19C_free(void);

void dll_19C_hitDetect(void);

void dll_19C_release(void);

void dll_19C_initialise(void);

void dll_19D_render(void);

void dll_19D_release(void);

void dll_19D_initialise(void);

/* 8b "li r3, N; blr" returners. */
int dll_19C_getExtraSize(void);
int dll_19C_getObjectTypeId(void);
int dll_19D_getExtraSize(void);
int dll_19D_getObjectTypeId(void);
int dll_19E_getExtraSize(void) { return 0x10; }
int dll_19E_getObjectTypeId(void) { return 0x1; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E51B0;
#pragma peephole off
void dll_19C_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
#pragma peephole reset

/* Stubs to align function set with v1.0 asm. */
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int type);
extern int* Obj_SetupObject(void* setup, int a, int b, int c, void* d);
extern void ObjHits_ClearHitVolumes(int obj);
extern void Obj_FreeObject(int obj);
extern f32 lbl_803E51B4;

#pragma peephole off
void dll_19C_update(int* obj);
#pragma peephole reset

#pragma peephole off
void dll_19B_init(u8* obj, u8* params);
#pragma peephole reset

/*
 * Function: dll_19C_init
 * EN v1.0 Address: 0x801CC950
 * EN v1.0 Size: 64b
 */
#pragma peephole off
void dll_19C_init(int obj, u8* initData);
#pragma peephole reset

/*
 * Function: dll_19D_free
 * EN v1.0 Address: 0x801CC9A8
 * EN v1.0 Size: 132b
 */
#pragma peephole off
void dll_19D_free(int obj);
#pragma peephole reset

extern int ObjHits_SetHitVolumeSlot(int obj, int volumeIdx, int hitType, int extra);

/*
 * Function: dll_19D_init
 * EN v1.0 Address: 0x801CCECC
 * EN v1.0 Size: 208b
 */
#pragma peephole off
void dll_19D_init(int obj);
#pragma peephole reset

extern EffectInterface** gPartfxInterface;
extern f32 lbl_803E51B8;
extern f64 lbl_803E51C0;

/*
 * Function: dll_19D_hitDetect
 * EN v1.0 Address: 0x801CCA30
 * EN v1.0 Size: 276b
 */
#pragma peephole off
void dll_19D_hitDetect(int obj);
#pragma peephole reset

/*
 * Function: dll_19D_update
 * EN v1.0 Address: 0x801CCB44
 * EN v1.0 Size: 904b
 */
#pragma peephole off
void dll_19D_update(int obj);
#pragma peephole reset
#pragma scheduling reset
#pragma peephole reset
/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma peephole reset

/* === merged from main/dll/creator1CF.c [801CCFB4-801CD258) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/creator1CF.h"
#include "main/game_object.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"

extern void* Camera_GetCurrentViewSlot(void);
extern float sqrtf(float x);
extern int randomGetRange(int min, int max);
extern void voxmaps_worldToGrid(void* world, void* grid);
extern int voxmaps_traceLine(void* from, void* to, void* out, int param4, int param5);

extern ModgfxInterface** gModgfxInterface;
extern EffectInterface** gPartfxInterface;
extern u8 framesThisStep;
extern f32 lbl_803E51C8;
extern f32 lbl_803E51CC;
extern f32 lbl_803E51D0;
extern f32 lbl_803E51D4;
extern f32 lbl_803E51D8;
extern f32 lbl_803E51DC;

/*
 * --INFO--
 *
 * Function: dll_19E_free
 * EN v1.0 Address: 0x801CCFB4
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801CCFE4
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_19E_free(int param_1)
{
    (*gModgfxInterface)->detachSource((void*)param_1);
    (*gExpgfxInterface)->freeSource2((u32)param_1);
}

/*
 * --INFO--
 *
 * Function: dll_19E_render
 * EN v1.0 Address: 0x801CD008
 * EN v1.0 Size: 588b
 * EN v1.1 Address: 0x801CD0F8
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_19E_render(int obj, int param_2, int param_3, int param_4,
                    int param_5, s8 visible)
{
    int state;
    u8* camera;
    f32 dist;
    f32 invDist;
    f32 facz, facy, facx;
    f32 facz2, facy2, facx2;
    f32 nz, ny, nx;
    struct
    {
        f32 delta[3];

        struct
        {
            u8 pad[0xc];
            f32 x, y, z;
        } args;
    } stk;
    f32 midA[3];
    f32 midB[3];
    f32 gridA[2];
    f32 gridB[2];
    int traceOut[2];

    state = *(int*)&((GameObject*)obj)->extra;
    if (visible == 0)
    {
        *(s16*)(state + 4) = 0;
        *(u8*)(state + 0xa) = 0;
    }
    else if (*(u8*)(state + 0xc) != 0)
    {
        *(u8*)(state + 0xa) = 1;
        camera = (u8*)Camera_GetCurrentViewSlot();
        stk.delta[0] = *(f32*)(camera + 0xc) - ((GameObject*)obj)->anim.localPosX;
        stk.delta[1] = *(f32*)(camera + 0x10) - ((GameObject*)obj)->anim.localPosY;
        stk.delta[2] = *(f32*)(camera + 0x14) - ((GameObject*)obj)->anim.localPosZ;
        dist = sqrtf(stk.delta[2] * stk.delta[2] + (stk.delta[0] * stk.delta[0] + stk.delta[1] * stk.delta[1]));
        if (dist > lbl_803E51C8)
        {
            invDist = lbl_803E51CC / dist;
            nx = stk.delta[0] * invDist;
            stk.delta[0] = nx;
            ny = stk.delta[1] * invDist;
            stk.delta[1] = ny;
            nz = stk.delta[2] * invDist;
            stk.delta[2] = nz;
            facx = lbl_803E51D0 * nx;
            midA[0] = facx;
            facy = lbl_803E51D0 * ny;
            midA[1] = facy;
            facz = lbl_803E51D0 * nz;
            midA[2] = facz;
            midA[0] = facx + ((GameObject*)obj)->anim.localPosX;
            midA[1] = facy + ((GameObject*)obj)->anim.localPosY;
            midA[2] = facz + ((GameObject*)obj)->anim.localPosZ;
            facx2 = lbl_803E51D4 * nx;
            midB[0] = facx2;
            facy2 = lbl_803E51D4 * ny;
            midB[1] = facy2;
            facz2 = lbl_803E51D4 * nz;
            midB[2] = facz2;
            midB[0] = facx2 + *(f32*)(camera + 0xc);
            midB[1] = facy2 + *(f32*)(camera + 0x10);
            midB[2] = facz2 + *(f32*)(camera + 0x14);
            voxmaps_worldToGrid(midA, gridA);
            voxmaps_worldToGrid(midB, gridB);
            if (voxmaps_traceLine(gridA, gridB, traceOut, 0, 0) == 0)
            {
                *(u8*)(state + 0xa) = 0;
                (*gExpgfxInterface)->freeSource(obj);
            }
        }
        if (*(s16*)(state + 4) > 0)
        {
            *(s16*)(state + 4) -= framesThisStep;
        }
        else
        {
            if (*(u8*)(state + 0xa) != 0)
            {
                stk.args.x = lbl_803E51D8;
                stk.args.y = lbl_803E51DC;
                stk.args.z = lbl_803E51D8;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x1f7, &stk.args, 0x12, -1, NULL);
            }
            *(s16*)(state + 4) = (s16)(randomGetRange(-10, 10) + 0x3c);
        }
    }
}


/* Trivial 4b 0-arg blr leaves. */
void dll_19E_hitDetect(void)
{
}

#include "main/audio/sfx_ids.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/dll/dim_tricky.h"
#include "main/effect_interfaces.h"
#include "main/gameplay_runtime.h"
#include "main/obj_placement.h"
#include "main/resource.h"


extern void Sfx_StopObjectChannel(void* obj, int channel);
extern void objUpdateOpacity(void* obj);
extern int ObjHits_GetPriorityHit(void* obj, int a, int b, int c);

extern u8 framesThisStep;
extern ModgfxInterface** gModgfxInterface;
extern EffectInterface** gPartfxInterface;
extern s8 lbl_803DDBE8;
extern undefined4 lbl_802C23D8[4];
extern f32 lbl_803E51E0;
extern f32 lbl_803E51E4;
extern f32 lbl_803E51E8;
extern f64 lbl_803E51F0;

typedef struct Dll19EState
{
    s32 gameBitId;
    s16 delayTimer;
    s16 resetTimer;
    s16 settleTimer;
    u8 pad0A;
    u8 mode;
    u8 active;
    u8 needsOpenSfx;
    u8 previousActive;
    u8 sequenceIndex;
} Dll19EState;

typedef struct Dll19ESetup
{
    ObjPlacement base;
    s8 objectType;
    u8 mode;
    s16 scaleTimer;
    s16 sequenceIndex;
    s16 gameBitId;
} Dll19ESetup;

STATIC_ASSERT(sizeof(Dll19ESetup) == 0x20);
STATIC_ASSERT(offsetof(Dll19ESetup, objectType) == 0x18);
STATIC_ASSERT(offsetof(Dll19ESetup, mode) == 0x19);
STATIC_ASSERT(offsetof(Dll19ESetup, scaleTimer) == 0x1A);
STATIC_ASSERT(offsetof(Dll19ESetup, sequenceIndex) == 0x1C);
STATIC_ASSERT(offsetof(Dll19ESetup, gameBitId) == 0x1E);

/*
 * --INFO--
 *
 * Function: dll_19E_update
 * EN v1.0 Address: 0x801CD258
 * EN v1.0 Size: 1056b
 */
void dll_19E_update(void* obj)
{
    extern void Sfx_PlayFromObject(void* obj, int sfxId);
    extern int GameBit_Set(int eventId, int value);
    Dll19EState* state;
    void* resource;
    volatile f32 localScale;
    undefined effectArgs[16];
    undefined4 resourceArgs[4];
    int i;

    state = ((GameObject*)obj)->extra;
    resourceArgs[0] = lbl_802C23D8[0];
    resourceArgs[1] = lbl_802C23D8[1];
    resourceArgs[2] = lbl_802C23D8[2];
    resourceArgs[3] = lbl_802C23D8[3];

    Sfx_PlayFromObject(obj, SFXmn_eggylaugh216);
    objUpdateOpacity(obj);
    if (state->settleTimer > 0)
    {
        *(u16*)&state->settleTimer = state->settleTimer - (u16)framesThisStep;
    }

    if (state->mode == 1)
    {
        localScale = lbl_803E51E0;
        state->previousActive = state->active;
        if ((ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0) ||
            ((state->settleTimer != 0) && (state->settleTimer <= 0x14)))
        {
            state->active = (u8)(1 - state->active);
            if (state->active != 0)
            {
                state->resetTimer = 1000;
            }
            if (state->settleTimer != 0)
            {
                state->settleTimer = 0;
                lbl_803DDBE8 = 3;
                state->resetTimer = 300;
                if (state->sequenceIndex == 2)
                {
                    GameBit_Set(0x1d1, 1);
                }
            }
        }

        if ((state->active != 0) && (state->resetTimer != 0))
        {
            *(u16*)&state->resetTimer = state->resetTimer - (u16)framesThisStep;
            if (state->resetTimer <= 0)
            {
                state->resetTimer = 0;
                state->active = 0;
            }
        }

        if ((state->active != 0) && (state->delayTimer <= 0) && (state->needsOpenSfx != 0))
        {
            state->needsOpenSfx = 0;
            Sfx_PlayFromObject(obj, SFXmn_sml_trex_snap1);
        }

        if (state->active != state->previousActive)
        {
            if (state->active != 0)
            {
                resource = Resource_Acquire(0x69, 1);
                resourceArgs[1] = (u32)state->sequenceIndex * 2 + 0x19d;
                resourceArgs[2] = (u32)state->sequenceIndex * 2 + 0x19e;
                (*(void (*)(void*, int, undefined*, int, int, undefined4*))(*(int*)(*(int*)resource + 4)))(
                    obj, 1, effectArgs, 0x10004, -1, resourceArgs);
                Resource_Release(resource);

                i = 0;
                do
                {
                    (*gPartfxInterface)->spawnObject(obj, 0x1a3, NULL, 0, -1, NULL);
                    i++;
                }
                while (i < 100);

                if ((state->gameBitId != -1) && (GameBit_Get(state->gameBitId) == 0))
                {
                    GameBit_Set(state->gameBitId, 1);
                }
                if ((lbl_803DDBE8 == 0) && (state->sequenceIndex == 0) &&
                    (GameBit_Get(state->gameBitId) != 0))
                {
                    lbl_803DDBE8 = 1;
                }
                if ((lbl_803DDBE8 == 1) && (state->sequenceIndex == 1) &&
                    (GameBit_Get(state->gameBitId) != 0))
                {
                    lbl_803DDBE8 = 2;
                }
                if ((lbl_803DDBE8 == 2) && (state->sequenceIndex == 2) &&
                    (GameBit_Get(state->gameBitId) != 0))
                {
                    GameBit_Set(0x1d1, 1);
                    lbl_803DDBE8 = 3;
                }
                state->needsOpenSfx = 1;
                state->delayTimer = 1;
            }
            else
            {
                Sfx_StopObjectChannel(obj, 0x40);
                (*gModgfxInterface)->detachSource(obj);
                (*gExpgfxInterface)->freeSource((u32)obj);
                if ((state->gameBitId != -1) && (GameBit_Get(state->gameBitId) != 0))
                {
                    GameBit_Set(state->gameBitId, 0);
                }
                if ((lbl_803DDBE8 == 1) && (state->sequenceIndex == 0))
                {
                    lbl_803DDBE8 = 0;
                }
                if ((lbl_803DDBE8 == 2) && (state->sequenceIndex == 1))
                {
                    lbl_803DDBE8 = 0;
                }
                if ((lbl_803DDBE8 == 3) && (state->sequenceIndex == 2) &&
                    (GameBit_Get(0x1d5) == 0))
                {
                    GameBit_Set(0x1d1, 0);
                    lbl_803DDBE8 = 0;
                }
            }
        }
    }
}


/*
 * --INFO--
 *
 * Function: dll_19E_init
 * EN v1.0 Address: 0x801CD678
 * EN v1.0 Size: 348b
 */
void dll_19E_init(u8* obj, Dll19ESetup* setup)
{
    Dll19EState* state;
    void* resource;
    undefined stackArg[16];
    volatile f32 localScale;

    state = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)(((s32)setup->objectType & 0x3f) << 10);
    if (setup->scaleTimer > 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = (f32)setup->scaleTimer / lbl_803E51E4;
    }
    else
    {
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E51E8;
    }

    state->mode = setup->mode;
    state->active = 0;
    state->sequenceIndex = 0;
    state->gameBitId = setup->gameBitId;
    localScale = lbl_803E51E0;

    if (state->mode == 1)
    {
        state->sequenceIndex = (u8)setup->sequenceIndex;
        state->needsOpenSfx = 0;
        state->settleTimer = state->sequenceIndex * 0x28 + 0x398;
        state->previousActive = 0;
    }
    else if (state->mode == 0)
    {
        state->active = 1;
        resource = Resource_Acquire(0x69, 1);
        if (setup->sequenceIndex == 0)
        {
            (*(void (**)(u8*, int, undefined*, int, int, int))(*(int*)resource + 4))(
                obj, 0, stackArg, 0x10004, -1, 0);
        }
    }
    state->delayTimer = 0;
}


/* Trivial 4b 0-arg blr leaves. */
void dll_19E_release(void)
{
}

void dll_19E_initialise(void)
{
}
