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


extern undefined8 FUN_80006894();
extern undefined4 FUN_800068a0();
extern undefined4 FUN_800068cc();
extern undefined4 FUN_800068d0();
extern void* FUN_800069a8();
extern undefined4 FUN_80006a00();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_80017620();
extern undefined4 FUN_80017664();
extern undefined4 FUN_800176c8();
extern double FUN_800176f4();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern void ModelLightStruct_free(void* effect);
extern u32 GameBit_Get(int bit);
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 FUN_80039520();
extern undefined4 FUN_8003b818();
extern void objRenderFn_8003b8f4(f32);
extern undefined4 FUN_80053bf0();
extern undefined8 FUN_8005d1e8();
extern undefined4 FUN_8005fe14();
extern void queueGlowRender(void* effect);
extern undefined4 FUN_80081110();
extern undefined4 FUN_800d7780();
extern undefined4 FUN_8011daf8();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern byte FUN_80294d90();
extern undefined4 FUN_80294d98();
extern void* SUB42();

extern ScreenTransitionInterface** gScreenTransitionInterface;
extern undefined4* DAT_803dd6d8;
extern u8 framesThisStep;
extern f64 DOUBLE_803e4a08;
extern f32 FLOAT_803dc074;
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
extern f32 timeDelta;
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

extern int Obj_GetPlayerObject(void);
extern int* gSHthorntailAnimationInterface;
extern void modelLightStruct_setEnabled(int light, int arg, f32 f);
extern void Sfx_AddLoopedObjectSound(int obj, int sfxId);
extern void Sfx_RemoveLoopedObjectSound(int obj, int sfxId);
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
int cfccrate_getExtraSize(void) { return 0x4c; }
int cfccrate_getObjectTypeId(void) { return 0x1; }

void cfccrate_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

/* render-with-objRenderFn_8003b8f4 pattern. */
void kt_torch_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3DB0);
}
