#include "main/obj_placement.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/DF/rope.h"
#include "main/dll/mmsh_waterspike.h"





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
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_EnableObject();
extern void objRenderFn_8003b8f4(f32 scale);
extern void queueGlowRender(void* light);

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
extern const f32 lbl_803E4D6C;

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
extern void* objCreateLight(int obj, int n);
extern void modelLightStruct_setLightKind(int light, int v);
extern void modelLightStruct_setDiffuseColor(int light, int a, int b, int c, int d);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 a, f32 b);
extern void modelLightStruct_setupGlow(int light, int a, int b, int c, int d, int e, f32 f);
extern void modelLightStruct_setGlowProjectionRadius(int light, f32 f);


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
void dimbossgut2_func11(void);




void DIMbossspit_hitDetect(void)
{
}

void DIMbossspit_release(void)
{
}

void DIMbossspit_initialise(void)
{
}

void magicmaker_free(void);








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


/* 8b "li r3, N; blr" returners. */
int DIMbossspit_getExtraSize(void) { return 0x8; }
int DIMbossspit_getObjectTypeId(void) { return 0x0; }
int magicmaker_getExtraSize(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
