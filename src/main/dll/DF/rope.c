#include "ghidra_import.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/objhits_types.h"
#include "main/dll/DF/rope.h"
#include "main/dll/mmsh_waterspike.h"

typedef struct DimbosscrackparPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
} DimbosscrackparPlacement;


typedef struct MagicmakerPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
} MagicmakerPlacement;


typedef struct DIMbossspitUpdateBurstState
{
    u8 pad0[0x4 - 0x0];
    s32 light;
    u8 pad8[0x3DC - 0x8];
    s32 unk3DC;
    u8 pad3E0[0x400 - 0x3E0];
    u16 unk400;
    u8 pad402[0x40C - 0x402];
    s32 unk40C;
} DIMbossspitUpdateBurstState;


typedef struct Dimbossgut2State
{
    u8 pad0[0x4 - 0x0];
    s32 unk4;
    u8 pad8[0x3DC - 0x8];
    s32 unk3DC;
    u8 pad3E0[0x400 - 0x3E0];
    u16 unk400;
    u8 pad402[0x40C - 0x402];
    s32 unk40C;
    u8 pad410[0x42C - 0x410];
} Dimbossgut2State;


typedef struct DIMbossspitState
{
    s16 unk0;
    s16 unk2;
    s32 light;
    u8 pad8[0x3DC - 0x8];
    s32 unk3DC;
    u8 pad3E0[0x400 - 0x3E0];
    u16 unk400;
    u8 pad402[0x40C - 0x402];
    s32 unk40C;
} DIMbossspitState;


extern void ModelLightStruct_free(void* light);
extern int randomGetRange(int min, int max);
extern void Obj_FreeObject(int obj);
extern undefined4 ObjHits_RegisterActiveHitVolumeObject();
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_EnableObject();
extern undefined8 ObjGroup_RemoveObject();
extern int ObjMsg_Pop();
extern void objRenderFn_8003b8f4(f32 scale);
extern void queueGlowRender(void* light);

extern undefined4* gBaddieControlInterface;
extern f32 lbl_803E4CF0;
extern f32 lbl_803E4D44;

extern u8 framesThisStep;
extern f32 timeDelta;
extern EffectInterface** gPartfxInterface;
extern void objMove(int obj, f32 x, f32 y, f32 z);
extern void Sfx_PlayFromObject(int obj, int id);
extern void CameraShake_SetAllMagnitudes(f32 mag);
extern void doRumble(f32 v);
extern void modelLightStruct_setEnabled(int light, int v, f32 f);
extern f32 lbl_803E4D38;
extern f32 lbl_803E4D3C;
extern f32 lbl_803E4D40;
extern f32 lbl_803E4D48;
extern f32 lbl_803E4D4C;
extern f32 lbl_803E4D50;
extern f32 lbl_803E4D60;
extern f32 lbl_803E4D64;
extern f32 lbl_803E4D68;
extern f32 lbl_803E4D6C;
extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern f32 lbl_803E4CD0;
extern f32 lbl_803E4CD4;
extern f32 lbl_803E4CD8;
extern f32 lbl_803E4CDC;
extern f32 lbl_803E4CE0;
extern f32 lbl_803E4CE4;
extern f32 lbl_803E4CE8;
extern f32 lbl_803E4CEC;
extern f32 lbl_803E4D20;
extern int Curve_AdvanceAlongPath(int a, f32 f);
extern int getAngle(f32 dx, f32 dy);
extern int Obj_GetPlayerObject(void);
extern f32 lbl_803E4D10;
extern f32 lbl_803E4D14;
extern f32 lbl_803E4D18;
extern f32 lbl_803E4D1C;

/*
 * --INFO--
 *
 * Function: dimbossgut2_updateTracking
 * EN v1.0 Address: 0x801BF048
 * EN v1.0 Size: 652b
 * EN v1.1 Address: 0x801BF5FC
 * EN v1.1 Size: 680b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbossgut2_updateTracking(int obj, int state)
{
    int curve;
    int r30v;
    s16 delta;
    s16 angle;
    int q;
    f32 fv;
    int player;
    int rel;

    curve = ((Dimbossgut2State*)state)->unk40C;
    r30v = ((Dimbossgut2State*)state)->unk3DC;
    if ((((Dimbossgut2State*)state)->unk400 & 8) != 0)
    {
        if ((Curve_AdvanceAlongPath(r30v, *(f32*)(curve + 0x10)) != 0) || (*(int*)(r30v + 0x10) != 0))
        {
            if ((*gRomCurveInterface)->goNextPoint((void*)r30v) != 0)
            {
                ((Dimbossgut2State*)state)->unk400 = ((Dimbossgut2State*)state)->unk400 & ~0x8;
            }
        }
        angle = (s16)(getAngle(*(f32*)(r30v + 0x74), *(f32*)(r30v + 0x7c)) + 0x8000);
        delta = (s16)(angle - (u16) * (s16*)obj);
        if (delta > 0x8000)
        {
            delta = (s16)(delta - 0xffff);
        }
        if (delta < -0x8000)
        {
            delta = (s16)(delta + 0xffff);
        }
        *(s16*)obj = angle;
        *(f32*)(curve + 4) = *(f32*)(curve + 4) + (f32)(delta >> 4);
        if (*(f32*)(curve + 0x10) < lbl_803E4D14)
        {
            *(f32*)(curve + 0x10) = *(f32*)(curve + 0x10) + lbl_803E4D18;
        }
        q = delta / 0xb6;
        if (q < 0)
        {
            q = -q;
        }
        fv = (f32)(s32)
        q * lbl_803E4CD4;
        if (lbl_803E4CF0 < fv)
        {
            *(f32*)(curve + 0x10) = *(f32*)(curve + 0x10) / fv;
            *(f32*)(curve + 8) = *(f32*)(curve + 8) + lbl_803E4D1C;
        }
        if (lbl_803E4CD8 < *(f32*)(curve + 8))
        {
            *(f32*)(curve + 8) = *(f32*)(curve + 8) / lbl_803E4D10;
        }
        ((GameObject*)obj)->anim.localPosX = *(f32*)(r30v + 0x68);
        ((GameObject*)obj)->anim.localPosZ = *(f32*)(r30v + 0x70);
    }
    else
    {
        player = Obj_GetPlayerObject();
        rel = (int)(u16)getAngle(-(*(f32*)(player + 0x18) - ((GameObject*)obj)->anim.worldPosX),
                                 -(*(f32*)(player + 0x20) - ((GameObject*)obj)->anim.worldPosZ)) -
            (int)(u16) * (s16*)obj;
        if (rel > 0x8000)
        {
            rel = rel - 0xffff;
        }
        if (rel < -0x8000)
        {
            rel = rel + 0xffff;
        }
        *(s16*)obj = (s16)(*(s16*)obj + rel * (u8)framesThisStep / 3);
    }
    return;
}

/*
 * --INFO--
 *
 * Function: dimbossgut2_free
 * EN v1.0 Address: 0x801BF2F0
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x801BF8A4
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbossgut2_free(int arg9)
{
    int obj = arg9;
    uint handle;
    int state;
    void* childObj;

    state = *(int*)&((GameObject*)obj)->extra;
    handle = *(uint*)(((Dimbossgut2State*)state)->unk40C + 0x18);
    if (handle != 0)
    {
        ModelLightStruct_free((void*)handle);
    }
    ObjGroup_RemoveObject(obj, 3);
    childObj = ((GameObject*)obj)->childObjs[0];
    if (childObj != 0)
    {
        Obj_FreeObject((int)childObj);
        *(undefined4*)(obj + 200) = 0;
    }
    (*(void (*)(int, int, int))(*(int*)(*gBaddieControlInterface + 0x40)))(obj, state, 0);
    return;
}

/*
 * --INFO--
 *
 * Function: dimbossgut2_render
 * EN v1.0 Address: 0x801BF37C
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x801BF930
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbossgut2_render(int obj, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    u8* light;

    light = ((GameObject*)obj)->extra;
    if (visible != 0)
    {
        ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, param_2, param_3, param_4, param_5,
                                                                      lbl_803E4CF0);
        light = *(u8**)(((Dimbossgut2State*)light)->unk40C + 0x18);
        if (((light != 0) && (light[0x2f8] != 0)) && (light[0x4c] != 0))
        {
            queueGlowRender(light);
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: dimbossgut2_update
 * EN v1.0 Address: 0x801BF3E8
 * EN v1.0 Size: 716b
 * EN v1.1 Address: 0x801BF99C
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbossgut2_update(int obj)
{
    int state;
    int iVar;
    uint uval;
    uint n;
    float* pfVar4;
    int val;
    f32 fdiff;
    f32 fscale;
    u8* p;
    uint msgB;
    uint msgA;
    uint msgC;
    struct
    {
        u8 pad[8];
        f32 f54;
        f32 f50;
        f32 f4c;
        f32 f48;
    } stk;

    state = *(int*)&((GameObject*)obj)->extra;
    if ((((GameObject*)obj)->unkF4 == 0) &&
        ((((GameObject*)obj)->anim.parent != NULL ||
            (iVar = objPosToMapBlockIdx(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                        ((GameObject*)obj)->anim.localPosZ),
                iVar >= 0))))
    {
        msgC = 0;
        do
        {
            iVar = ObjMsg_Pop(obj, &msgA, &msgB, &msgC);
        }
        while (iVar != 0);
        pfVar4 = *(float**)&((Dimbossgut2State*)state)->unk40C;
        if ((*pfVar4 < lbl_803E4CD0) && (pfVar4[4] < lbl_803E4CD4))
        {
            fdiff = pfVar4[3] - ((GameObject*)obj)->anim.localPosY;
            if (fdiff < lbl_803E4CD8)
            {
                fdiff = -fdiff;
            }
            if ((fdiff < lbl_803E4CDC) &&
                (stk.f4c = pfVar4[3], uval = randomGetRange(0x1e, 0x3c),
                    (int)(uint) * (u16*)((int)pfVar4 + 0x16) > (int)uval))
            {
                fscale = lbl_803E4CE0 * pfVar4[4];
                stk.f50 = ((GameObject*)obj)->anim.localPosX -
                    fscale * mathSinf(lbl_803E4CE4 * (f32) * (s16*)obj / lbl_803E4CE8);
                stk.f48 = ((GameObject*)obj)->anim.localPosZ -
                    fscale * mathCosf(lbl_803E4CE4 * (f32) * (s16*)obj / lbl_803E4CE8);
                stk.f54 = lbl_803E4CEC * (lbl_803E4CF0 - fdiff / lbl_803E4CDC);
                (*gPartfxInterface)->spawnObject((void*)obj, 0x32b, &stk, 1, -1,
                                                 NULL);
                *(u16*)((int)pfVar4 + 0x16) = 0;
            }
        }
        *(u16*)((int)pfVar4 + 0x16) += (u8)framesThisStep;
        fn_801BEEA0((s16*)obj, (u8*)state);
        dimbossgut2_updateTracking(obj, state);
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, lbl_803E4D20, timeDelta, NULL);
        ((ObjHitsPriorityState*)*(int*)&((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = 9;
        ((ObjHitsPriorityState*)*(int*)&((GameObject*)obj)->anim.hitReactState)->hitVolumeId = 1;
        ObjHits_RegisterActiveHitVolumeObject(obj);
        val = ((Dimbossgut2State*)state)->unk40C;
        p = *(u8**)(val + 0x18);
        if ((p != NULL) && (p[0x2f8] != 0) && (p[0x4c] != 0))
        {
            n = (p[0x2f9] + *(s8*)(p + 0x2fa)) & 0xffff;
            if (0xc < n)
            {
                n = (n + randomGetRange(-12, 12)) & 0xffff;
                if (0xff < n)
                {
                    n = 0xff;
                    *(u8*)(*(int*)(val + 0x18) + 0x2fa) = 0;
                }
            }
            *(u8*)(*(int*)(val + 0x18) + 0x2f9) = (u8)n;
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: dimbossgut2_init
 * EN v1.0 Address: 0x801BF6B4
 * EN v1.0 Size: 540b
 * EN v1.1 Address: 0x801BFC68
 * EN v1.1 Size: 540b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z, int** out, int a, int b);
extern void lightSetFieldBC_8001db14(int light, int v);
extern void* objCreateLight(int obj, int n);
extern void modelLightStruct_setLightKind(int light, int v);
extern void modelLightStruct_setDiffuseColor(int light, int a, int b, int c, int d);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 a, f32 b);
extern void modelLightStruct_setupGlow(int light, int a, int b, int c, int d, int e, f32 f);
extern void modelLightStruct_setGlowProjectionRadius(int light, f32 f);
extern f32 lbl_803E4D24;
extern f32 lbl_803E4D28;
extern f32 lbl_803E4D2C;
extern f32 lbl_803E4D30;
extern f32 lbl_803E4D04;

void dimbossgut2_init(int obj, int def, int p3)
{
    int state;
    int p;
    int count;
    int i;
    int* list;
    u8 flags;
    f32 z;

    state = *(int*)&((GameObject*)obj)->extra;
    flags = 0x16;
    if (p3 != 0)
    {
        flags |= 1;
    }
    (*(void (*)(int, int, int, int, int, int, u8, f32))(*(int*)(*gBaddieControlInterface + 0x58)))(
        obj, def, state, 0, 0, 0x102, flags, lbl_803E4CE0);
    ((GameObject*)obj)->animEventCallback = NULL;
    p = ((Dimbossgut2State*)state)->unk40C;
    z = lbl_803E4CD8;
    *(f32*)(p + 0x0) = z;
    *(f32*)(p + 0x4) = z;
    *(s16*)(p + 0x14) = randomGetRange(-0x7fff, 0x7fff);
    z = lbl_803E4CD8;
    *(f32*)(p + 0x8) = z;
    *(s16*)(p + 0x16) = 0;
    *(f32*)(p + 0x10) = z;
    count = hitDetectFn_80065e50(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                 ((GameObject*)obj)->anim.localPosZ, &list, 0, 0);
    *(f32*)(p + 0xc) = lbl_803E4CD8;
    if (count != 0)
    {
        *(f32*)(p + 0xc) = lbl_803E4D24;
        for (i = 0; i < count; i++)
        {
            f32 d = *(f32*)list[i] - ((GameObject*)obj)->anim.localPosY;
            if (*(s8*)(list[i] + 0x14) == 0xe)
            {
                if (d > *(f32*)(p + 0xc))
                {
                    *(f32*)(p + 0xc) = d;
                }
            }
        }
    }
    *(f32*)(p + 0xc) += ((GameObject*)obj)->anim.localPosY;
    ObjAnim_SetCurrentMove(obj, 0, (f32)(int)randomGetRange(0, 0x63) / lbl_803E4D28, 0);
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, lbl_803E4D20, timeDelta, NULL);
    *(int*)(p + 0x18) = (int)objCreateLight(obj, 1);
    if (*(void**)(p + 0x18) != NULL)
    {
        modelLightStruct_setLightKind(*(int*)(p + 0x18), 2);
        modelLightStruct_setDiffuseColor(*(int*)(p + 0x18), 0, 255, 0, 0);
        lightSetFieldBC_8001db14(*(int*)(p + 0x18), 1);
        modelLightStruct_setDistanceAttenuation(*(int*)(p + 0x18), lbl_803E4D2C, lbl_803E4CE0);
        modelLightStruct_setupGlow(*(int*)(p + 0x18), 0, 0, 255, 0, 127, lbl_803E4D30);
        modelLightStruct_setGlowProjectionRadius(*(int*)(p + 0x18), lbl_803E4D04);
    }
}

/*
 * --INFO--
 *
 * Function: DIMbossspit_updateBurst
 * EN v1.0 Address: 0x801BF8D8
 * EN v1.0 Size: 648b
 * EN v1.1 Address: 0x801BFE8C
 * EN v1.1 Size: 664b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DIMbossspit_updateBurst(int obj)
{
    int state;
    s16 v;
    int iVar;
    int n;
    int radius;
    int i;

    state = *(int*)&((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale + lbl_803E4D38;
    ((GameObject*)obj)->anim.rotX += 0xaaa;
    ((GameObject*)obj)->anim.rotZ += 0x38e;
    ((GameObject*)obj)->anim.rotY += 0x38e;
    if (*(s16*)state == 1)
    {
        i = 0;
        do
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x340, NULL, 1, -1,
                                             NULL);
            i = i + 1;
        }
        while (i < 0x12);
        (*gPartfxInterface)->spawnObject((void*)obj, 0x4bb, NULL, 1, -1,
                                         NULL);
        Sfx_PlayFromObject(obj, SFXwmap_name);
        Sfx_PlayFromObject(obj, SFXar_bblast16);
        CameraShake_SetAllMagnitudes(lbl_803E4D3C);
        doRumble(lbl_803E4D40);
        if (*(void**)&((DIMbossspitUpdateBurstState*)state)->light != NULL)
        {
            modelLightStruct_setEnabled(((DIMbossspitUpdateBurstState*)state)->light, 0, lbl_803E4D44);
        }
    }
    *(s16*)state += (u8)framesThisStep;
    v = *(s16*)state;
    if (v > 0x200)
    {
        if (v > 0x22a)
        {
            Obj_FreeObject(obj);
        }
        return;
    }
    iVar = (int)
    (lbl_803E4D48 * ((f32)(s32)
    v * lbl_803E4D4C
    )
    )
    ;
    n = 0xff - iVar;
    radius = 0x94 - (v >> 2);
    if (n >= 0)
    {
        ObjHits_SetHitVolumeSlot(obj, 5, 2, 0);
        ObjHitbox_SetSphereRadius(obj, (s16)((radius - 0x40) >> 1));
        ((GameObject*)obj)->anim.alpha = (u8)n;
    }
    else
    {
        if (*(void**)&((DIMbossspitUpdateBurstState*)state)->light != NULL)
        {
            ModelLightStruct_free(*(void**)&((DIMbossspitUpdateBurstState*)state)->light);
            ((DIMbossspitUpdateBurstState*)state)->light = 0;
        }
        ((GameObject*)obj)->anim.alpha = 0;
        if ((f32)(s32)((radius - 0x40) >> 1) > lbl_803E4D50)
        {
            ObjHits_SetHitVolumeSlot(obj, 9, 1, 0);
            ObjHitbox_SetSphereRadius(obj, (s16)((radius - 0x40) >> 1));
        }
    }
    (*gPartfxInterface)->spawnObject((void*)obj, 0x4bc, NULL, 1, -1,
                                     &radius);
}

/*
 * --INFO--
 *
 * Function: DIMbossspit_free
 * EN v1.0 Address: 0x801BFB70
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801C0124
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DIMbossspit_free(int param_1)
{
    int obj = param_1;
    uint state;

    state = *(uint*)(*(int*)&((GameObject*)obj)->extra + 4);
    if (state != 0)
    {
        ModelLightStruct_free((void*)state);
    }
    (*gExpgfxInterface)->freeSource2((u32)obj);
    return;
}

/*
 * --INFO--
 *
 * Function: DIMbossspit_render
 * EN v1.0 Address: 0x801BFBC4
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x801C0178
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DIMbossspit_render(int obj, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    u8* light;

    light = ((GameObject*)obj)->extra;
    if (visible != 0)
    {
        ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, param_2, param_3, param_4, param_5,
                                                                      lbl_803E4D44);
        light = *(u8**)&((DIMbossspitState*)light)->light;
        if (((light != 0) && (light[0x2f8] != 0)) && (light[0x4c] != 0))
        {
            queueGlowRender(light);
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: DIMbossspit_update
 * EN v1.0 Address: 0x801BFC2C
 * EN v1.0 Size: 648b
 * EN v1.1 Address: 0x801C01E0
 * EN v1.1 Size: 648b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DIMbossspit_update(int obj)
{
    int state;
    int i;
    s16 v;
    u8* p;

    state = *(int*)&((GameObject*)obj)->extra;
    if (*(s16*)state == 0)
    {
        ((GameObject*)obj)->unkF4 -= (u8)framesThisStep;
        if (((GameObject*)obj)->unkF4 < 0)
        {
            Obj_FreeObject(obj);
            return;
        }
        ObjHits_SetHitVolumeSlot(obj, 5, 4, 0);
        ObjHitbox_SetSphereRadius(obj, 10);
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY - lbl_803E4D60 * timeDelta;
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * lbl_803E4D64;
        ((GameObject*)obj)->anim.rotX = lbl_803E4D68 * timeDelta + (f32)((GameObject*)obj)->anim.rotX;
        ((GameObject*)obj)->anim.rotZ = lbl_803E4D6C * timeDelta + (f32)((GameObject*)obj)->anim.rotZ;
        ((GameObject*)obj)->anim.rotY = lbl_803E4D6C * timeDelta + (f32)((GameObject*)obj)->anim.rotY;
        objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
                ((GameObject*)obj)->anim.velocityZ * timeDelta);
        i = 0;
        do
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x4ba, NULL, 1, -1,
                                             NULL);
            i = i + 1;
        }
        while (i < 3);
        if ((*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->contactFlags != 0)
        {
            ((GameObject*)obj)->anim.localPosX = (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->
                contactPosX;
            ((GameObject*)obj)->anim.localPosY = (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->
                contactPosY - lbl_803E4D50;
            ((GameObject*)obj)->anim.localPosZ = (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->
                contactPosZ;
            *(s16*)state = 1;
        }
    }
    else
    {
        DIMbossspit_updateBurst(obj);
    }
    p = *(u8**)&((DIMbossspitState*)state)->light;
    if (p != NULL && p[0x2f8] != 0 && p[0x4c] != 0)
    {
        v = (s16)(p[0x2f9] + *(s8*)(p + 0x2fa));
        if (v < 0)
        {
            v = 0;
            p[0x2fa] = 0;
        }
        else if (v > 0xc)
        {
            v = (s16)(v + randomGetRange(-12, 12));
            if (v > 0xff)
            {
                v = 0xff;
                (*(u8**)&((DIMbossspitState*)state)->light)[0x2fa] = 0;
            }
        }
        (*(u8**)&((DIMbossspitState*)state)->light)[0x2f9] = (u8)v;
    }
    return;
}

/*
 * --INFO--
 *
 * Function: DIMbossspit_init
 * EN v1.0 Address: 0x801BFEB4
 * EN v1.0 Size: 312b
 * EN v1.1 Address: 0x801C0468
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void modelLightStruct_setSpecularColor(int light, int a, int b, int c, int d);
extern void lightSetField4D(int light, int v);
extern void modelLightStruct_setAffectsAabbLightSelection(int light, int v);
extern int Obj_GetActiveModel(int obj);
extern void ObjModel_SetPostRenderCallback(int model, void* cb);
extern void postRenderSetAlphaBlendState(void);
extern f32 lbl_803E4D70;
extern f32 lbl_803E4D74;
extern f32 lbl_803E4D78;
extern f32 lbl_803E4D7C;
extern f32 lbl_803E4D80;

void DIMbossspit_init(int obj)
{
    u8* state = ((GameObject*)obj)->extra;

    *(void**)&((DIMbossspitState*)state)->light = objCreateLight(obj, 1);
    if (*(void**)&((DIMbossspitState*)state)->light != NULL)
    {
        modelLightStruct_setLightKind(((DIMbossspitState*)state)->light, 2);
        modelLightStruct_setDiffuseColor(((DIMbossspitState*)state)->light, 0, 255, 0, 0);
        modelLightStruct_setSpecularColor(((DIMbossspitState*)state)->light, 0, 255, 0, 0);
        modelLightStruct_setDistanceAttenuation(((DIMbossspitState*)state)->light, lbl_803E4D70, lbl_803E4D74);
        lightSetField4D(((DIMbossspitState*)state)->light, 1);
        modelLightStruct_setEnabled(((DIMbossspitState*)state)->light, 1, lbl_803E4D78);
        modelLightStruct_setAffectsAabbLightSelection(((DIMbossspitState*)state)->light, 1);
        modelLightStruct_setupGlow(((DIMbossspitState*)state)->light, 0, 0, 255, 0, 127, lbl_803E4D7C);
        modelLightStruct_setGlowProjectionRadius(((DIMbossspitState*)state)->light, lbl_803E4D80);
    }
    ((GameObject*)obj)->unkF4 = 0xb4;
    ObjHits_SetHitVolumeSlot(obj, 0, 0, 0);
    ObjHitbox_SetSphereRadius(obj, 0);
    ((DIMbossspitState*)state)->unk0 = 0;
    ((DIMbossspitState*)state)->unk2 = 0;
    ObjHits_EnableObject(obj);
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), postRenderSetAlphaBlendState);
}


/* Trivial 4b 0-arg blr leaves. */
void dimbossgut2_func11(void)
{
}

void dimbossgut2_hitDetect(void)
{
}

void dimbossgut2_release(void)
{
}

void dimbossgut2_initialise(void)
{
}

void DIMbossspit_hitDetect(void)
{
}

void DIMbossspit_release(void)
{
}

void DIMbossspit_initialise(void)
{
}

void magicmaker_free(void)
{
}

void magicmaker_hitDetect(void)
{
}

void magicmaker_init(void)
{
}

void magicmaker_release(void)
{
}

void magicmaker_initialise(void)
{
}

void dimbosscrackpar_hitDetect(void)
{
}

void dimbosscrackpar_release(void)
{
}

void dimbosscrackpar_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: magicmaker_update
 * EN v1.0 Address: 0x801C0080
 * EN v1.0 Size: 624b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 Obj_IsLoadingLocked(void);
extern void GameBit_Set(int eventId, int value);
extern int* ObjGroup_GetObjects(int group, int* countOut);
extern char* Obj_AllocObjectSetup(int size, int typeId);
extern char* Obj_SetupObject(char* setup, int a, int b, int c, int d);
extern void hitDetectFn_80097070(char* obj, f32 f, int a, int b, int c, int d);
extern u16 lbl_80325CE8[];
extern f32 lbl_803E4D8C;
extern f32 lbl_803E4D88;

void magicmaker_update(int obj)
{
    int def;
    char* newobj;
    int n;
    int count;
    int* objs;
    int i;
    int j;
    char* setup;
    int o;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    if (Obj_IsLoadingLocked() != 0)
    {
        if ((u32)GameBit_Get(0x26b) != 0u)
        {
            GameBit_Set(0x26b, 0);
            objs = ObjGroup_GetObjects(4, &count);
            n = 0;
            for (i = 0; i < count; i++)
            {
                o = *objs;
                for (j = 0; j < 6; j++)
                {
                    if (*(s16*)(o + 0x46) == lbl_80325CE8[j])
                    {
                        n++;
                    }
                }
                objs++;
            }
            if (n < 10)
            {
                setup = Obj_AllocObjectSetup(0x30, lbl_80325CE8[randomGetRange(0, 5)]);
                if (setup != NULL)
                {
                    *(u8*)(setup + 0x1a) = 0x14;
                    *(s16*)(setup + 0x2c) = -1;
                    *(s16*)(setup + 0x1c) = -1;
                    ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX + (f32)(int)
                    randomGetRange(-0x15e, 0x15e);
                    ((ObjPlacement*)setup)->posY = lbl_803E4D8C + ((GameObject*)obj)->anim.localPosY;
                    ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ + (f32)(int)
                    randomGetRange(-0x15e, 0x15e);
                    *(s16*)(setup + 0x24) = -1;
                    *(u8*)(setup + 0x4) = ((MagicmakerPlacement*)def)->unk4;
                    *(u8*)(setup + 0x6) = ((MagicmakerPlacement*)def)->unk6;
                    *(u8*)(setup + 0x5) = ((MagicmakerPlacement*)def)->unk5;
                    *(u8*)(setup + 0x7) = ((MagicmakerPlacement*)def)->unk7;
                    *(s16*)(setup + 0x2e) = 3;
                    newobj = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                             *(int*)&((GameObject*)obj)->anim.parent);
                    if (newobj != NULL)
                    {
                        i = 3;
                        do
                        {
                            hitDetectFn_80097070(newobj, lbl_803E4D88, 2, 2, 0x64, 0);
                            i--;
                        }
                        while (i != 0);
                    }
                }
            }
        }
    }
}

extern f32 lbl_803E4D98;

int dimbosscrackpar_SeqFn(int* obj)
{
    int* side = *(int**)&((GameObject*)obj)->anim.placementData;
    if ((u32)GameBit_Get(((DimbosscrackparPlacement*)side)->unk1E) == 0u)
    {
        return 0;
    }
    (*gPartfxInterface)->spawnObject(
        obj, ((DimbosscrackparPlacement*)side)->unk1A + 1222, NULL, 2, -1, NULL);
    (*gPartfxInterface)->spawnObject(obj, 1224, NULL, 2, -1, NULL);
    return 0;
}

void dimbosscrackpar_update(int* obj)
{
    int* side = *(int**)&((GameObject*)obj)->anim.placementData;
    if ((u32)GameBit_Get(((DimbosscrackparPlacement*)side)->unk1E) != 0u)
    {
        (*gPartfxInterface)->spawnObject(
            obj, ((DimbosscrackparPlacement*)side)->unk1A + 1222, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, 1224, NULL, 2, -1, NULL);
    }
}

void dimbosscrackpar_free(int* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void dimbosscrackpar_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

void dimbosscrackpar_init(s16* obj, s8* def)
{
    ((GameObject*)obj)->anim.rotX = 0;
    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E4D98;
    ((GameObject*)obj)->animEventCallback = (void*)dimbosscrackpar_SeqFn;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)def[0x24] << 8);
    ((GameObject*)obj)->anim.rotY = (s16)((s32)def[0x23] << 8);
    ((GameObject*)obj)->anim.rotZ = (s16)((s32)def[0x22] << 8);
}

void dimbossfire_hitDetect(void)
{
}

/*
 * --INFO--
 *
 * Function: dimbossfire_free
 * EN v1.0 Address: 0x801C04C8
 * EN v1.0 Size: 100b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbossfire_free(int obj)
{
    int o = obj;
    int state;
    void* light;

    state = *(int*)(o + 0xb8);
    light = *(void**)(state + 0x10);
    if (light != 0)
    {
        ModelLightStruct_free(light);
        *(undefined4*)(state + 0x10) = 0;
    }
    (*gExpgfxInterface)->freeSource2((u32)o);
}

void dimbossfire_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

/* 8b "li r3, N; blr" returners. */
int dimbossgut2_setScale(void) { return 0x0; }
int dimbossgut2_getExtraSize(void) { return 0x42c; }
int dimbossgut2_getObjectTypeId(void) { return 0x49; }
int DIMbossspit_getExtraSize(void) { return 0x8; }
int DIMbossspit_getObjectTypeId(void) { return 0x0; }
int magicmaker_getExtraSize(void) { return 0x0; }
int magicmaker_getObjectTypeId(void) { return 0x0; }
int dimbosscrackpar_getExtraSize(void) { return 0x0; }
int dimbosscrackpar_getObjectTypeId(void) { return 0x0; }
int dimbossfire_getExtraSize(void) { return 0x14; }
int dimbossfire_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
void magicmaker_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4D88);
}
