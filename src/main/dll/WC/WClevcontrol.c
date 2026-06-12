#include "main/audio/sfx_ids.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/dll/WC/WClevcontrol.h"
#include "main/resource.h"

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
extern undefined4 ObjHits_SetTargetMask();
extern int ObjHits_GetPriorityHitWithPosition();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 ObjPath_GetPointModelMtx();
extern undefined4 ObjPath_GetPointWorldPosition();
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
void FUN_801ee668(ushort* param_1, int param_2)
{
    float fVar1;
    double dVar2;
    double dVar3;
    double dVar4;
    double dVar5;

    (**(code**)(*DAT_803dd6e4 + 0x20))((int)*(short*)(param_2 + 0x6a));
    dVar3 = (double)FUN_80294964();
    dVar4 = (double)FUN_80293f90();
    fVar1 = lbl_803E6908;
    if (*(int*)(param_2 + 0x10) != 0)
    {
        fVar1 = (float)((double)CONCAT44(0x43300000, (int)*(short*)(param_2 + 0x2e) ^ 0x80000000) -
            DOUBLE_803e6938) / lbl_803E6924;
    }
    *(float*)(param_2 + 0x60) =
        lbl_803DC074 * (fVar1 - *(float*)(param_2 + 0x60)) * lbl_803E6928 +
        *(float*)(param_2 + 0x60);
    fVar1 = lbl_803E692C;
    dVar5 = (double)lbl_803E692C;
    dVar2 = -(double)*(float*)(param_2 + 0x60);
    *(float*)(param_2 + 0x78) = *(float*)(param_2 + 0x60);
    *(float*)(param_2 + 0x7c) = fVar1;
    (**(code**)(*DAT_803dd6e4 + 0x28))
    ((double)(((float)(dVar4 * dVar2 + (double)(float)(dVar5 * -dVar3)) * lbl_803DC074) /
         lbl_803E6930),
     (double)(((float)(dVar3 * dVar2 + (double)(float)(dVar5 * dVar4)) * lbl_803DC074) /
         lbl_803E6930));
    return;
}


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
void fn_801EED7C(void)
{
}

void fn_801EEDA8(void)
{
}

void fn_801EEDD4(void)
{
}

void SB_CloudRunner_hitDetect(void)
{
}

void SB_CloudRunner_release(void)
{
}

void SB_CloudRunner_initialise(void)
{
}

void WM_ObjCreator_free(void);

void WM_ObjCreator_hitDetect(void);

/* 8b "li r3, N; blr" returners. */
int fn_801EEDAC(void) { return 0x0; }
int fn_801EEDD8(void) { return 0x2; }
int fn_801EEDFC(void) { return 0x0; }
int fn_801EEE04(void) { return 0x0; }
int fn_801EEE2C(void) { return 0x0; }
int fn_801EEE34(void) { return 0x0; }
int SB_CloudRunner_getExtraSize(void) { return 0x84; }
int SB_CloudRunner_getObjectTypeId(void) { return 0x43; }
int WM_ObjCreator_getExtraSize(void);
int WM_ObjCreator_getObjectTypeId(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5CC8;
extern void objRenderFn_8003b8f4(f32);

void WM_ObjCreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

extern f32 lbl_803E5C70;

f32 fn_801EEDB4(int unused, f32* p)
{
    f32 v = lbl_803E5C70;
    *p = v;
    return v;
}

/* copy 3 floats from struct to out args */
void fn_801EEDE0(int* src, f32* out_x, f32* out_y, f32* out_z)
{
    *out_x = *(f32*)((char*)src + 0xc);
    *out_y = *(f32*)((char*)src + 0x10);
    *out_z = *(f32*)((char*)src + 0x14);
}

/* virtual call through obj[0xb8][0x10] context, vtable double-deref at +0x68 */
void shipBattleFn_801eed24(void* obj)
{
    void* this_ = *(void**)((char*)(*(void**)&((GameObject*)obj)->extra) + 0x10);
    void* vt = *(void**)*(void**)((char*)this_ + 0x68);
    void (*fn)(void*) = *(void(**)(void*))((char*)vt + 0x24);
    fn(this_);
}

/* copy 3 floats from obj->b8 [0x4c..0x54] to out args */
void fn_801EED5C(int* obj, f32* x, f32* y, f32* z)
{
    char* p = ((GameObject*)obj)->extra;
    *x = *(f32*)(p + 0x4c);
    *y = *(f32*)(p + 0x50);
    *z = *(f32*)(p + 0x54);
}

extern void objSetMtxFn_800412d4();

void fn_801EED80(void* obj)
{
    objSetMtxFn_800412d4(ObjPath_GetPointModelMtx((int)obj, 3));
}

void fn_801EEDC0(int p1, f32* out, int* outInt)
{
    *out = lbl_803E5C70;
    *outInt = 0;
}

void fn_801EEE0C(int* obj, f32* x, f32* y, f32* z)
{
    f32* p = ((GameObject*)obj)->extra;
    *x = p[0];
    *y = p[1];
    *z = p[2];
}

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

void fn_801EE668(s16* obj, u8* state)
{
    WCAnimEvents events;
    int doSpawn;
    int yaw;
    int pitch;
    int d;
    int v;
    f32 spd;

    yaw = (-*(int*)(state + 0x74) * 6000) / 70;
    pitch = (-*(int*)(state + 0x70) * 12000) / 70;

    {
        f32 t = (f32)(*(int*)(state + 0x70) << 3) / lbl_803E5C98;
        *(s16*)(state + 0x2c) = -(t * timeDelta - (f32) * (s16*)(state + 0x2c));
    }
    *(s16*)(state + 0x2c) -= (*(s16*)(state + 0x2c) * framesThisStep) >> 5;

    d = yaw - (u16)((GameObject*)obj)->anim.rotY;
    if (d > 0x8000)
    {
        d -= 0xFFFF;
    }
    if (d < -0x8000)
    {
        d += 0xFFFF;
    }
    ((GameObject*)obj)->anim.rotY = lbl_803E5CA8 * ((f32)d * timeDelta) + (f32) * (s16*)(int)(obj + 1);

    d = pitch - (u16) * (s16*)(state + 0x2e);
    if (d > 0x8000)
    {
        d -= 0xFFFF;
    }
    if (d < -0x8000)
    {
        d += 0xFFFF;
    }
    *(s16*)(state + 0x2e) = lbl_803E5CA8 * ((f32)d * timeDelta) + (f32) * (s16*)(int)(state + 0x2e);

    v = ((GameObject*)obj)->anim.rotY;
    v = (v < -8000) ? -8000 : ((v > 8000) ? 8000 : v);
    ((GameObject*)obj)->anim.rotY = v;

    v = *(s16*)(state + 0x2e);
    v = (v < -13000) ? -13000 : ((v > 13000) ? 13000 : v);
    *(s16*)(state + 0x2e) = v;

    ((GameObject*)obj)->anim.rotX = *(s16*)(state + 0x2c) + 0x4000;
    ((GameObject*)obj)->anim.rotZ = *(s16*)(state + 0x2e);

    events.sfxFlag = 0;
    spd = lbl_803E5CB0 * (f32)((GameObject*)obj)->anim.rotY + lbl_803E5CAC;
    if (spd > lbl_803E5CB4)
    {
        if (((GameObject*)obj)->anim.currentMove != 5)
        {
            ObjAnim_SetCurrentMove((int)obj, 5, lbl_803E5C70, 0);
        }
    }
    else
    {
        spd = lbl_803E5CAC;
        if (((GameObject*)obj)->anim.currentMove != 256)
        {
            ObjAnim_SetCurrentMove((int)obj, 256, lbl_803E5C70, 0);
        }
    }
    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)obj, spd, timeDelta, (ObjAnimEventList*)&events);

    *(f32*)(obj + 6) = *(f32*)(state + 0x4c);
    *(f32*)(obj + 8) = *(f32*)(state + 0x50);
    *(f32*)(obj + 10) = *(f32*)(state + 0x54);

    if (events.sfxFlag)
    {
        Sfx_PlayFromObject(0, 294);
    }

    doSpawn = 0;
    if (((WCButtonFlag*)(state + 0x80))->held)
    {
        if ((getButtonsHeld(0) & 0x100) == 0)
        {
            ((WCButtonFlag*)(state + 0x80))->held = 0;
        }
        else if (*(s8*)(state + 0x64) == 0)
        {
            doSpawn = 1;
            *(s8*)(state + 0x64) = 40;
        }
    }
    else
    {
        if ((getButtonsHeld(0) & 0x100) != 0)
        {
            ((WCButtonFlag*)(state + 0x80))->held = 1;
            if (*(s8*)(state + 0x64) < 20)
            {
                doSpawn = 1;
                *(s8*)(state + 0x64) = 40;
            }
        }
    }
    if (doSpawn)
    {
        WCPushBlock_SpawnFromPath(obj, state);
    }
}

/* SB_CloudRunner_HandlePriorityHit: when the laser hits an object whose
 * type isn't 281 and isn't currently in fade state, fade it red, rumble,
 * play SFX, gate further damage on a GameBit, then if the hit type is 154
 * emit 3 partfx of effect 168 followed by a 10-shot burst of effect 169. */
extern int ObjHits_GetPriorityHitWithPosition(int obj, int* outHit, int* p3, int* p4, f32* outX, f32* outY, f32* outZ);
extern int objGetFlagsE5_2(int obj);
extern void Obj_SetModelColorFadeRecursive(int obj, int r, int g, int b, int a, int frames);
extern void doRumble(f32 val);
extern void GameBit_Set(int id, int v);
extern f32 lbl_803E5CB8;
extern f32 lbl_803E5C74;

struct WCPartfxArgs
{
    s16 v[3];
    s16 _pad;
    f32 scale;
};

void SB_CloudRunner_HandlePriorityHit(int obj, u8* state)
{
    int hitObj;
    f32 pos[3];
    struct WCPartfxArgs args;
    int i;

    if (ObjHits_GetPriorityHitWithPosition(obj, &hitObj, 0, 0, &pos[0], &pos[1], &pos[2]) != 0)
    {
        if (objGetFlagsE5_2(obj) == 0)
        {
            if (*(s16*)(hitObj + 0x46) != 281)
            {
                Obj_SetModelColorFadeRecursive(obj, 175, 200, 0, 0, 1);
                doRumble(lbl_803E5CB8);
                Sfx_PlayFromObject(0, SFXtr_bcrek2_c);
                if (GameBit_Get(3870) != 0)
                {
                    Sfx_PlayFromObject(obj, 1169);
                }
                ((GameObject*)obj)->anim.rotY = 4000;
                state[0x65] = 1;
                args.scale = lbl_803E5C74;
                args.v[0] = 0;
                args.v[1] = 0;
                args.v[2] = 0;
                if (*(s16*)(hitObj + 0x46) == 154)
                {
                    (*gPartfxInterface)->spawnObject((void*)obj, 168, &args,
                                                     0x200001, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)obj, 168, &args,
                                                     0x200001, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)obj, 168, &args,
                                                     0x200001, -1, NULL);
                    for (i = 0; i < 10; i++)
                    {
                        (*gPartfxInterface)->spawnObject((void*)obj, 169,
                                                         &args, 0x200001, -1,
                                                         NULL);
                    }
                }
            }
        }
    }
}

extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern void Obj_BuildInverseWorldTransformMatrix(int obj, f32* mtx);
extern void PSMTXMultVec(f32 * mtx, f32 * in, f32 * out);

void SB_CloudRunner_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    f32* state = ((GameObject*)obj)->extra;
    f32 mtx[16];
    if (visible == -1)
    {
        objRenderFn_8003b8f4(lbl_803E5C74);
        ObjPath_GetPointWorldPosition(obj, 3, state, state + 1, state + 2, 0);
        if (((GameObject*)obj)->anim.parent != NULL)
        {
            *state = *state - playerMapOffsetX;
            state[2] = state[2] - playerMapOffsetZ;
            Obj_BuildInverseWorldTransformMatrix(*(int*)&((GameObject*)obj)->anim.parent, mtx);
            PSMTXMultVec(mtx, state, state);
        }
    }
    else if (visible != 0)
    {
        objRenderFn_8003b8f4(lbl_803E5C74);
        ObjPath_GetPointWorldPosition(obj, 3, state, state + 1, state + 2, 0);
        if (((GameObject*)obj)->anim.parent != NULL)
        {
            *state = *state - playerMapOffsetX;
            state[2] = state[2] - playerMapOffsetZ;
            Obj_BuildInverseWorldTransformMatrix(*(int*)&((GameObject*)obj)->anim.parent, mtx);
            PSMTXMultVec(mtx, state, state);
        }
    }
    else
    {
        *state = ((GameObject*)obj)->anim.localPosX;
        state[1] = ((GameObject*)obj)->anim.localPosY;
        state[2] = ((GameObject*)obj)->anim.localPosZ;
    }
}

extern int Obj_GetPlayerObject(void);
extern void SB_CloudRunner_onSeqFree(void);
extern void objHitDetectFn_80062e84(int player, int hitObj, int p3);
extern void fn_80295918(int player, int p2, f32 p3);

int SB_CloudRunner_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int* state = ((GameObject*)obj)->extra;
    int player = Obj_GetPlayerObject();
    int i;
    animUpdate->freeCallback = (ObjAnimSequenceFreeCallback)SB_CloudRunner_onSeqFree;
    ((SBCloudRunnerState*)state)->unk4C = ((GameObject*)obj)->anim.localPosX;
    ((SBCloudRunnerState*)state)->unk50 = ((GameObject*)obj)->anim.localPosY;
    ((SBCloudRunnerState*)state)->unk54 = ((GameObject*)obj)->anim.localPosZ;
    ((SBCloudRunnerState*)state)->unk2C = (s16)(*(s16*)obj - 0x4000);
    ((SBCloudRunnerState*)state)->rotZ = ((GameObject*)obj)->anim.rotZ;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == 1)
        {
            objHitDetectFn_80062e84(player, ((SBCloudRunnerState*)state)->unk10, 0);
            fn_80295918(player, 5, lbl_803E5C70);
            ((SBCloudRunnerState*)state)->unk6E = 1;
        }
    }
    animUpdate->sequenceEventActive = 0;
    ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    return 0;
}

extern void textureFree(void* tex);

void SB_CloudRunner_free(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    if (*(void**)((char*)state + 0x18) != NULL)
    {
        textureFree(*(void**)((char*)state + 0x18));
        *(void**)((char*)state + 0x18) = NULL;
    }
    if (*(void**)((char*)state + 0x1c) != NULL)
    {
        textureFree(*(void**)((char*)state + 0x1c));
        *(void**)((char*)state + 0x1c) = NULL;
    }
    Resource_Release(*(void**)((char*)state + 0x14));
    *(void**)((char*)state + 0x14) = NULL;
    ObjGroup_RemoveObject(obj, 10);
}

extern void* textureLoadAsset(int id);

void SB_CloudRunner_init(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = (void*)SB_CloudRunner_SeqFn;
    ((SBCloudRunnerState*)state)->unk4C = ((GameObject*)obj)->anim.localPosX;
    ((SBCloudRunnerState*)state)->unk50 = ((GameObject*)obj)->anim.localPosY;
    ((SBCloudRunnerState*)state)->unk54 = ((GameObject*)obj)->anim.localPosZ;
    ((SBCloudRunnerState*)state)->unk64 = 100;
    *(s16*)obj = 0x4000;
    *(void**)((char*)state + 0x18) = textureLoadAsset(342);
    *(void**)((char*)state + 0x1c) = textureLoadAsset(3085);
    *(void**)((char*)state + 0x14) = Resource_Acquire(121, 1);
    ObjHits_SetTargetMask(obj, 1);
    ObjGroup_AddObject(obj, 10);
}

extern void setAButtonIcon(int idx);
extern int padGetStickX(int controller);
extern int padGetStickY(int controller);
extern f32 lbl_803E5CA0;
extern f32 lbl_803E5CBC;
extern f32 lbl_803E5CC0;
extern void WCPushBlock_UpdateRideTilt(int obj, int state);
extern void WCPushBlock_UpdateCloudAction(int obj, int state);

void SB_CloudRunner_update(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    int prevKey;

    if (*(s8*)&((SBCloudRunnerState*)state)->unk6E != 0 || ((GameObject*)obj)->anim.mapEventSlot == 0xb)
    {
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        return;
    }
    setAButtonIcon(6);
    *(int*)(state + 0x70) = (int)(s8)padGetStickX(0);
    *(int*)(state + 0x74) = (int)(s8)padGetStickY(0);
    if (*(void**)&((SBCloudRunnerState*)state)->unk10 == NULL)
    {
        int count;
        int* objs = (int*)ObjGroup_GetObjects(3, &count);
        int i;
        for (i = 0; i < count; i++)
        {
            int o = objs[i];
            if (*(s16*)(o + 0x46) == 0x8e)
            {
                ((SBCloudRunnerState*)state)->unk10 = o;
                i = count;
            }
        }
    }
    ((GameObject*)obj)->unkF4 = 0;
    prevKey = *(s8*)(state + 0x65);
    *(s8*)&((SBCloudRunnerState*)state)->unk64 = (s8)(*(s8*)&((SBCloudRunnerState*)state)->unk64 - framesThisStep);
    if (*(s8*)&((SBCloudRunnerState*)state)->unk64 < 0)
    {
        *(s8*)&((SBCloudRunnerState*)state)->unk64 = 0;
    }
    switch (*(s8*)(state + 0x65))
    {
    case 0:
        ((void (*)(int, int))fn_801EE668)(obj, state);
        ((void (*)(int, int))SB_CloudRunner_HandlePriorityHit)(obj, state);
        break;
    case 1:
        WCPushBlock_UpdateRideTilt(obj, state);
        break;
    case 2:
    case 3:
        ((GameObject*)obj)->unkF4 = 1;
        break;
    }
    *(f32*)(state + 0x5c) = *(f32*)(state + 0x5c) + (f32)(int)((GameObject*)obj)->anim.rotZ * timeDelta / lbl_803E5CBC;
    *(f32*)(state + 0x58) = *(f32*)(state + 0x58) + (f32)(int)((GameObject*)obj)->anim.rotY * timeDelta / lbl_803E5CBC;
    *(f32*)(state + 0x5c) = *(f32*)(state + 0x5c) - timeDelta * (*(f32*)(state + 0x5c) * lbl_803E5CC0);
    *(f32*)(state + 0x58) = *(f32*)(state + 0x58) - timeDelta * (*(f32*)(state + 0x58) * lbl_803E5CC0);
    ((GameObject*)obj)->anim.rotY = (s16)(((GameObject*)obj)->anim.rotY - (int)(lbl_803E5CB8 * *(f32*)(state + 0x58)));
    ((GameObject*)obj)->anim.localPosY = lbl_803E5CB8 * *(f32*)(state + 0x58) + ((SBCloudRunnerState*)state)->unk50;
    ((GameObject*)obj)->anim.localPosZ = lbl_803E5CB8 * *(f32*)(state + 0x5c) + ((SBCloudRunnerState*)state)->unk54;
    *(s16*)(state + 0x6c) = (s16)(*(s16*)(state + 0x6c) + framesThisStep);
    if (*(s8*)(state + 0x65) != prevKey)
    {
        *(s16*)(state + 0x6c) = 0;
    }
    ((void (*)(int, int))WCPushBlock_UpdateCloudAction)(obj, state);
}
