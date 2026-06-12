/* === moved from main/dll/CF/CFforcecontrol.c [8018CD64-8018CDAC) (TU re-split, docs/boundary_audit.md) === */
#include "main/audio/sfx_ids.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/dll/CF/CFforcecontrol.h"
#include "main/screen_transition.h"


extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHits_RecordObjectHit();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern int ObjTrigger_IsSet();
extern void GXSetAlphaCompare(int comp0, int ref0, int op, int comp1, int ref1);
extern void GXSetBlendMode(int type, int srcFactor, int dstFactor, int op);
extern void gxSetPeControl_ZCompLoc_();
extern void gxSetZMode_();

extern f64 DOUBLE_803e4910;
extern f64 DOUBLE_803e4950;
extern f64 DOUBLE_803e4998;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e48e4;
extern f32 FLOAT_803e4918;
extern f32 FLOAT_803e491c;
extern f32 FLOAT_803e4920;
extern f32 FLOAT_803e4924;
extern f32 FLOAT_803e4928;
extern f32 FLOAT_803e492c;
extern f32 FLOAT_803e4930;
extern f32 FLOAT_803e4934;
extern f32 FLOAT_803e4938;
extern f32 FLOAT_803e493c;
extern f32 FLOAT_803e4940;
extern f32 FLOAT_803e4944;
extern f32 FLOAT_803e4948;
extern f32 FLOAT_803e494c;
extern f32 FLOAT_803e4960;
extern f32 FLOAT_803e4964;
extern f32 FLOAT_803e4968;
extern f32 FLOAT_803e496c;
extern f32 FLOAT_803e4970;
extern f32 FLOAT_803e4974;
extern f32 FLOAT_803e4978;
extern f32 FLOAT_803e497c;
extern f32 FLOAT_803e4980;
extern f32 FLOAT_803e4984;
extern f32 FLOAT_803e4988;
extern f32 FLOAT_803e498c;
extern f32 FLOAT_803e4990;
extern f32 FLOAT_803e49a0;
extern f32 FLOAT_803e49a4;
extern f32 FLOAT_803e49a8;

/*
 * --INFO--
 *
 * Function: deathgas_free
 * EN v1.0 Address: 0x8018BC50
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x8018BC64
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern s16* Camera_GetCurrentViewSlot(void);
extern ScreenTransitionInterface** gScreenTransitionInterface;
extern void setScreenTransitionPause(int v);
extern void addButtonObject(int* obj);
extern f32 lbl_803E3D1C;
extern f32 lbl_803E3D58;
extern f32 lbl_803E3D2C;

void deathseq_init(int* obj);


/* Trivial 4b 0-arg blr leaves. */
void deathseq_render(void);

void deathseq_hitDetect(void);

void deathseq_release(void);

void deathseq_initialise(void);

void dll_127_free_nop(void)
{
}

void dll_127_hitDetect_nop(void)
{
}

/* 8b "li r3, N; blr" returners. */
int fuelcell_getExtraSize(void);
int deathseq_getExtraSize(void);
int deathseq_getObjectTypeId(void);
int dll_127_getExtraSize_ret_0(void) { return 0x0; }
int dll_127_getObjectTypeId(void) { return 0x13; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3D60;
extern void objRenderFn_8003b8f4(f32);

void dll_127_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3D60);
}

/* Drift-recovery: add new fns with v1.0 names. */
extern void setPendingMapLoad(int v);
extern void removeButtonObject(int* obj);
extern void* Obj_GetActiveModel(int* obj);
extern void ObjModel_SetPostRenderCallback(void* model, void* cb);
extern f32 lbl_803E3CC0;
extern void mm_free_(void* ptr);

typedef struct
{
    f32 timer; // 0x0
    f32 hitTimer; // 0x4
    f32 radius; // 0x8
    u8 fogOn : 1; // 0xc bit 7
    u8 draining : 1; // bit 6
    u8 noFog : 1; // bit 5
} DeathGasState;

typedef struct
{
    u8 pad[0x18];
    u8 drainRate; // 0x18
    u8 fillRate; // 0x19
    s16 activeBit; // 0x1a
} DeathGasSetup;

typedef struct
{
    u16 msg; // 0x0
    u8 pad[0x5a];
    u8 lit : 1; // 0x5c bit 7
    u8 grabbed : 1; // bit 6
    u8 unkBit5 : 1; // bit 5
    u8 resetPos : 1; // bit 4
} FuelcellState;

typedef struct
{
    u8 pad[8];
    f32 homeX; // 0x8
    f32 homeY; // 0xc
    f32 homeZ; // 0x10
    u8 pad2[0xa];
    s16 offBit; // 0x1e
    s16 onBit; // 0x20
} FuelcellSetup;


void deathseq_free(int* obj);

void deathgas_init(int* obj);

int fuelcell_func0B(int* obj);


void fuelcell_free(int* obj);

void fuelcell_init(int* obj);

extern void disableHeavyFog(void);


extern int playerIsDisguised(void);
extern f32 Vec_distance(void* a, void* b);
extern void enableHeavyFog(f32 top, f32 bottom, f32 r, f32 g, f32 b, int p6);
extern f32 timeDelta;
extern f32 lbl_803E3C90;
extern f32 lbl_803E3C94;
extern f32 lbl_803E3C98;
extern f32 lbl_803E3C9C;
extern f32 lbl_803E3CA0;
extern f32 lbl_803E3CA4;
extern f32 lbl_803E3CA8;
extern f32 lbl_803E3CAC;
extern f32 lbl_803E3CB0;
extern f32 lbl_803E3CB4;

void deathgas_update(int* obj);

extern void gameBitIncrement(int eventId);
extern void Sfx_PlayFromObject(int* obj, int soundId);
extern f32 getXZDistance(void* a, void* b);
extern f32 lbl_803E3D08;
extern f32 lbl_803E3D0C;
extern f32 lbl_803E3D10;

void fuelcell_update(int* obj);

extern void objfx_spawnDirectionalBurst(int* obj, int idx, f32 scale, int b, int c, int d, f32 speed, int e, int f);
extern int ObjModel_GetRenderOp(int model, int idx);
extern void lightningRender(void* particle);
extern int getHudHiddenFrameCount(void);
extern f32 vec3f_distanceSquared(void* a, void* b);
extern int lightningCreate(float* start, float* end, f32 radiusX, f32 radiusY, int param_5, int param_6, int param_7);
extern f32 lbl_803E3CC8;
extern f32 lbl_803E3CCC;
extern f32 lbl_803E3CD0;
extern f32 lbl_803E3CD4;
extern f32 lbl_803E3CD8;
extern f32 lbl_803E3CDC;
extern f32 lbl_803E3CE0;
extern f32 lbl_803E3CE4;
extern f32 lbl_803E3CE8;
extern f32 lbl_803E3CEC;
extern f32 lbl_803E3CF0;
extern f32 lbl_803E3CF4;
extern f32 lbl_803E3CF8;

typedef struct
{
    u8 pad0[0xc];
    f32 pos[3]; // 0xc
    f32 pos2[3]; // 0x18
} GameObjPos;

#pragma opt_loop_invariants off
void fuelcell_render(int* obj, int p2, int p3, int p4, int p5);
#pragma opt_loop_invariants reset

typedef struct
{
    f32 timer; // 0x0
    f32 camX; // 0x4
    f32 camY; // 0x8
    f32 camZ; // 0xc
    f32 dist; // 0x10
    f32 distTarget; // 0x14
    int camRotY; // 0x18
    int camRotX; // 0x1c
    u8 menuShown : 1; // 0x20 bit 7
    u8 camActive : 1; // bit 6
    u8 transitionStarted : 1; // bit 5
} DeathSeqState;

extern int fn_80296C5C(void);
extern void fn_80296C6C(int* player, int v);
extern void AudioStream_StopCurrent(void);
extern void AudioStream_StartPrepared(void);
extern void AudioStream_Play(int streamId, void* cb);
extern int* objFindTexture(int* obj, int idx, int p3);
extern void cutsceneFadeInOut(int v);
extern void Obj_FreeObject(int* obj);
extern void showDeathMenu(void);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern f32 interpolate(f32 cur, f32 target, f32 t);
extern void Camera_SetFovY(f32 fov);
extern void Rcp_SetViewFinderHudEnabled(int v);
extern f32 lbl_803E3D18;
extern f32 lbl_803E3D20;
extern f32 lbl_803E3D24;
extern f32 lbl_803E3D28;
extern f32 lbl_803E3D30;
extern f32 lbl_803E3D34;
extern f32 lbl_803E3D38;
extern f32 lbl_803E3D3C;
extern f32 lbl_803E3D40;
extern f32 lbl_803E3D44;
extern f32 lbl_803E3D48;

void deathseq_update(int* obj);

#include "main/dll/CF/treasureRelated0177.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"
#include "main/objhits_types.h"
#include "main/screen_transition.h"

typedef struct KtTorchPlacement
{
    u8 pad0[0x1B - 0x0];
    u8 unk1B;
    u8 pad1C[0x20 - 0x1C];
} KtTorchPlacement;


extern void ModelLightStruct_free(void* effect);
extern u32 GameBit_Get(int bit);
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern void queueGlowRender(void* effect);
extern void* SUB42();

extern u8 framesThisStep;
extern f64 DOUBLE_803e4a08;
extern f32 FLOAT_803e49b0;
extern f32 FLOAT_803e49b4;
extern f32 FLOAT_803e49b8;
extern f32 FLOAT_803e49bc;
extern f32 FLOAT_803e49c0;
extern f32 FLOAT_803e49c4;
extern f32 FLOAT_803e49d0;
extern f32 FLOAT_803e49dc;
extern f32 FLOAT_803e49e0;
extern f32 FLOAT_803e49f0;
extern f32 FLOAT_803e49fc;
extern f32 FLOAT_803e4a00;
extern f32 FLOAT_803e4a10;
extern f32 FLOAT_803e4a14;
extern f32 FLOAT_803e4a18;
extern f32 lbl_803E3D64;
extern f32 lbl_803E3D68;
extern f64 lbl_803E3D70;
extern f32 lbl_803E3D78;
extern f32 lbl_803E3DB0;
extern f32 lbl_803E3DB4;
extern f64 lbl_803E3DB8;

/*
 * --INFO--
 *
 * Function: dll_127_update
 * EN v1.0 Address: 0x8018CDAC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018CDAC
 * EN v1.1 Size: 1116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_127_update(int obj)
{
    int flags;

    if (((GameObject*)obj)->anim.hitReactState == 0)
    {
        return;
    }
    if (*(short*)(obj + 0xf8) > 0)
    {
        *(short*)(obj + 0xf8) -= framesThisStep;
    }
    flags = (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags & 8;
    if (flags == 0)
    {
        return;
    }
    if (*(short*)(obj + 0xf8) > 0)
    {
        return;
    }
    *(short*)(obj + 0xf8) = 100;
}


/*
 * --INFO--
 *
 * Function: dll_127_init
 * EN v1.0 Address: 0x8018CF80
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x8018D378
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_127_init(short* param_1, int param_2)
{
    ObjAnimComponent* objAnim;
    float fVar1;
    uint uVar2;
    u8 b;

    objAnim = (ObjAnimComponent*)param_1;
    param_1[3] = param_1[3] | 2;
    b = *(u8*)(param_2 + 0x19);
    fVar1 = (f32)(int)
    b;
    if ((f32)(int)b < lbl_803E3D64
    )
    {
        fVar1 = *(f32*)&lbl_803E3D64;
    }
    fVar1 = fVar1 * lbl_803E3D68;
    *(float*)(param_1 + 4) = *(float*)(*(int*)(param_1 + 0x28) + 4) * fVar1;
    if (*(float**)(param_1 + 0x32) != (float*)0x0)
    {
        **(float**)(param_1 + 0x32) = **(float**)(param_1 + 0x28) * fVar1;
    }
    objAnim->bankIndex = (s8) * (u8*)(param_2 + 0x18);
    uVar2 = *(byte*)(param_2 + 0x1a) & 0x3f;
    *param_1 = (short)(uVar2 << 10);
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    *(undefined4*)(param_1 + 0x7a) = 0;
    *(undefined4*)(param_1 + 0x7c) = 0;
    return;
}


/* Trivial 4b 0-arg blr leaves. */
void dll_127_release_nop(void)
{
}

void dll_127_initialise_nop(void)
{
}

extern int* gSHthorntailAnimationInterface;
extern void modelLightStruct_setEnabled(int light, int arg, f32 f);
extern void fn_80098B18(int obj, f32 scale, int type, int mode, int arg5, f32* vec);
extern f32 lbl_803E3D7C;
extern f32 lbl_803E3D80;
extern f32 lbl_803E3D84;

typedef int (*ThorntailQueryFn)(u8*);

/*
 * --INFO--
 *
 * Function: campfire_update
 * EN v1.0 Address: 0x8018CFA4
 * EN v1.0 Size: 556b
 */
void campfire_update(int obj)
{
    extern void Sfx_RemoveLoopedObjectSound(int obj, int sfxId);
    extern void Sfx_AddLoopedObjectSound(int obj, int sfxId);
    extern int Obj_GetPlayerObject(void);
    int* state;
    int type;
    int mode;
    int flag;
    u8 buf[4];
    f32 params[3];

    state = ((GameObject*)obj)->extra;
    Obj_GetPlayerObject();
    if ((*(ThorntailQueryFn*)(*gSHthorntailAnimationInterface + 0x24))(buf) != 0)
    {
        if (*(void**)state != NULL)
        {
            modelLightStruct_setEnabled(*state, 1, lbl_803E3D78);
        }
        ObjHits_SetHitVolumeSlot(obj, 0x1f, 1, 0);
        *(f32*)((char*)state + 8) -= timeDelta;
        if (*(f32*)((char*)state + 8) <= lbl_803E3D7C)
        {
            flag = 1;
            *(f32*)((char*)state + 8) += lbl_803E3D78;
        }
        else
        {
            flag = 0;
        }
        type = 2;
        mode = 0;
        if (*((u8*)state + 0x12) == 0)
        {
            Sfx_AddLoopedObjectSound(obj, 0x9e);
            *((u8*)state + 0x12) = 1;
        }
    }
    else
    {
        if (*(void**)state != NULL)
        {
            modelLightStruct_setEnabled(*state, 0, lbl_803E3D78);
        }
        ObjHits_ClearHitVolumes(obj);
        *(f32*)((char*)state + 4) -= timeDelta;
        if (*(f32*)((char*)state + 4) <= lbl_803E3D7C)
        {
            mode = 3;
            *(f32*)((char*)state + 4) += lbl_803E3D80;
        }
        else
        {
            mode = 0;
        }
        type = 0;
        flag = 0;
        if (*((u8*)state + 0x12) != 0)
        {
            Sfx_RemoveLoopedObjectSound(obj, 0x9e);
            *((u8*)state + 0x12) = 0;
        }
    }
    params[0] = lbl_803E3D7C;
    params[1] = lbl_803E3D80;
    params[2] = lbl_803E3D7C;
    fn_80098B18(obj, lbl_803E3D84 * ((GameObject*)obj)->anim.rootMotionScale, type, mode, flag, params);
    {
        u8* light = *(u8**)state;
        if (light != NULL && light[0x2f8] != 0 && light[0x4c] != 0)
        {
            int rnd;
            u8* l2;
            s16 v;
            rnd = randomGetRange(-0x19, 0x19);
            l2 = *(u8**)state;
            v = l2[0x2f9] + *(s8*)(l2 + 0x2fa) + rnd;
            if (v < 0)
            {
                v = 0;
                l2[0x2fa] = 0;
            }
            else if (v > 0xff)
            {
                v = 0xff;
                l2[0x2fa] = 0;
            }
            *(u8*)(*state + 0x2f9) = v;
        }
    }
}

extern void ObjHitbox_SetCapsuleBounds(int obj, int x, int y, int z);
extern int objCreateLight(int a, int b);
extern void modelLightStruct_setLightKind(int h, int v);
extern void modelLightStruct_setDiffuseColor(int h, int r, int g, int b, int a);
extern void modelLightStruct_setSpecularColor(int h, int r, int g, int b, int a);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 min, f32 max);
extern void modelLightStruct_setPosition(int light, f32 x, f32 y, f32 z);
extern void modelLightStruct_startColorFade(int light, int a, int b);
extern void modelLightStruct_setDiffuseTargetColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setupGlow(int light, int a, int r, int g, int b, int c, f32 scale);
extern void modelLightStruct_setGlowProjectionRadius(int light, f32 v);
extern f32 lbl_803E3D88;
extern f32 lbl_803E3D8C;
extern f32 lbl_803E3D90;
extern f32 lbl_803E3D94;
extern f32 lbl_803E3D98;

/*
 * --INFO--
 *
 * Function: campfire_init
 * EN v1.0 Address: 0x8018D1D0
 * EN v1.0 Size: 732b
 */
void campfire_init(int obj, int p2)
{
    int* state;
    u8 buf[4];
    u32 size;
    s16 bit;

    state = ((GameObject*)obj)->extra;
    size = *(u8*)(p2 + 0x1a);
    if (size != 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3D88 * (f32)size;
    }
    if (GameBit_Get(0x8c) != 0)
    {
        *((u8*)state + 0x11) |= 1;
    }
    *(s16*)((char*)state + 0xc) = *(s16*)(p2 + 0x18);
    bit = *(s16*)((char*)state + 0xc);
    if (bit != -1 && GameBit_Get(bit) != 0)
    {
        *((u8*)state + 0x11) |= 4;
    }
    *((u8*)state + 0x10) = *(u8*)(p2 + 0x1b);
    {
        f32 scale = ((GameObject*)obj)->anim.rootMotionScale / *(f32*)(*(int*)&((GameObject*)obj)->anim.modelInstance +
            4);
        int m = *(int*)&((GameObject*)obj)->anim.hitReactState;
        ObjHitbox_SetCapsuleBounds(obj,
                                   (int)((f32)((ObjHitsPriorityState*)m)->primaryRadius * scale),
                                   (int)((f32)((ObjHitsPriorityState*)m)->primaryCapsuleOffsetA * scale),
                                   (int)((f32)((ObjHitsPriorityState*)m)->primaryCapsuleOffsetB * scale));
    }
    *(f32*)(state + 1) = lbl_803E3D80;
    *(f32*)(state + 2) = lbl_803E3D78;
    if (*(void**)state == NULL)
    {
        *state = objCreateLight(obj, 1);
    }
    if (*(void**)state != NULL)
    {
        int atten;
        modelLightStruct_setLightKind(*state, 2);
        modelLightStruct_setDiffuseColor(*state, 0xff, 0x7f, 0, 0xff);
        modelLightStruct_setSpecularColor(*state, 0xff, 0x7f, 0, 0xff);
        atten = (int)(lbl_803E3D8C * ((GameObject*)obj)->anim.rootMotionScale);
        modelLightStruct_setDistanceAttenuation(*state, (f32)atten, lbl_803E3D90 + (f32)atten);
        if ((*(ThorntailQueryFn*)(*gSHthorntailAnimationInterface + 0x24))(buf) != 0)
        {
            modelLightStruct_setEnabled(*state, 1, lbl_803E3D7C);
        }
        else
        {
            modelLightStruct_setEnabled(*state, 0, lbl_803E3D7C);
        }
        modelLightStruct_setPosition(*state, lbl_803E3D7C, lbl_803E3D94, *(f32*)&lbl_803E3D7C);
        modelLightStruct_startColorFade(*state, 1, 3);
        modelLightStruct_setDiffuseTargetColor(*state, 0xff, 0x5c, 0, 0xff);
        modelLightStruct_setupGlow(*state, 0, 0xff, 0x7f, 0, 0x87,
                                   lbl_803E3D98 * ((GameObject*)obj)->anim.rootMotionScale);
        modelLightStruct_setGlowProjectionRadius(*state, lbl_803E3D90);
    }
}

extern f32 lbl_803E3DC0;
extern f32 lbl_803E3DC4;
extern f32 lbl_803E3DC8;

/*
 * --INFO--
 *
 * Function: kt_torch_init
 * EN v1.0 Address: 0x8018D584
 * EN v1.0 Size: 348b
 */
void kt_torch_init(int obj, int p2)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    f32 scale;
    u8 b;

    ((GameObject*)obj)->anim.flags |= 2;
    b = *(u8*)(p2 + 0x1c);
    scale = (f32)(int)
    b;
    if ((f32)(int)b < lbl_803E3DC0
    )
    {
        scale = *(f32*)&lbl_803E3DC0;
    }
    scale *= lbl_803E3DC4;
    ((GameObject*)obj)->anim.rootMotionScale = *(f32*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 4) * scale;
    *(s16*)obj = (s16)((*(u8*)(p2 + 0x1d) & 0x3f) << 10);
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        **(f32**)&((GameObject*)obj)->anim.modelState = **(f32**)&((GameObject*)obj)->anim.modelInstance * scale;
    }
    objAnim->bankIndex = (s8) * (u8*)(p2 + 0x18);
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    ObjAnim_SetCurrentMove(obj, *(u8*)(p2 + 0x19), (f32) * (u8*)(p2 + 0x1a) * lbl_803E3DC8, 0);
    {
        s16 bit = *(s16*)(p2 + 0x20);
        if (bit != -1)
        {
            if (GameBit_Get(bit) != 0)
            {
                ((GameObject*)obj)->anim.alpha = 0xff;
            }
            else
            {
                ((GameObject*)obj)->anim.alpha = 0;
            }
        }
    }
}

void campfire_free(int obj)
{
    void** state;
    void* effect;

    state = ((GameObject*)obj)->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    effect = *state;
    if (effect != 0)
    {
        ModelLightStruct_free(effect);
    }
}

void campfire_render(int obj, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    void** state;
    void* effect;
    s32 isVisible;

    state = ((GameObject*)obj)->extra;
    isVisible = visible;
    if (isVisible != 0)
    {
        objRenderFn_8003b8f4(lbl_803E3D78);
        effect = *state;
        if (((effect != 0) && (*(u8*)((int)effect + 0x2f8) != 0)) &&
            (*(u8*)((int)effect + 0x4c) != 0))
        {
            queueGlowRender(effect);
        }
    }
}

void kt_torch_free(void)
{
}

void kt_torch_hitDetect(void)
{
}

void kt_torch_release(void)
{
}

void kt_torch_initialise(void)
{
}

void kt_torch_update(int obj)
{
    int mapData;
    int bit;

    mapData = *(int*)&((GameObject*)obj)->anim.placementData;
    ObjAnim_AdvanceCurrentMove((f32)((KtTorchPlacement*)mapData)->unk1B / lbl_803E3DB4,
                               timeDelta, obj, (ObjAnimEventList*)0);
    bit = *(short*)(mapData + 0x20);
    if (bit != -1)
    {
        if (GameBit_Get(bit) != 0)
        {
            ((GameObject*)obj)->anim.alpha = 0xff;
        }
        else
        {
            ((GameObject*)obj)->anim.alpha = 0;
        }
    }
}

/* 8b "li r3, N; blr" returners. */
int campfire_getExtraSize(void) { return 0x14; }
int campfire_getObjectTypeId(void) { return 0x1; }
int kt_torch_getExtraSize(void) { return 0x0; }
int kt_torch_getObjectTypeId(void) { return 0x0; }


/* render-with-objRenderFn_8003b8f4 pattern. */
void kt_torch_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3DB0);
}
