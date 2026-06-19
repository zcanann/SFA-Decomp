/* DLL 0x0129 — campfire area objects [8018CD64-8018CDAC) */
#include "main/game_object.h"

extern u32 GameBit_Get(int eventId);
extern int randomGetRange(int lo, int hi);

extern void objRenderFn_8003b8f4(f32);

extern f32 timeDelta;

#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/sky_interface.h"

extern void ModelLightStruct_free(void* effect);
extern u32 GameBit_Get(int eventId);
extern u32 ObjHits_ClearHitVolumes();
extern void ObjHits_SetHitVolumeSlot(u32 objPtr, int hitVolume, int hitType, int sourceSlot);
extern void queueGlowRender(void* effect);

extern f32 lbl_803E3D78;

extern void modelLightStruct_setEnabled(int light, int arg, f32 f);
extern void fn_80098B18(int obj, f32 scale, int type, int mode, int arg5, f32* vec);
extern f32 lbl_803E3D7C;
extern f32 lbl_803E3D80;
extern f32 lbl_803E3D84;

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

void campfire_update(int obj)
{
    extern void Sfx_RemoveLoopedObjectSound(u32 obj, u32 sfxId);
    extern void Sfx_AddLoopedObjectSound(int obj, int sfxId);
    extern void* Obj_GetPlayerObject(void);
    int* state;
    int type;
    int mode;
    int flag;
    f32 sunTime;
    f32 params[3];

    state = ((GameObject*)obj)->extra;
    Obj_GetPlayerObject();
    if ((*gSkyInterface)->getSunPosition(&sunTime) != 0)
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

void campfire_init(int obj, int p2)
{
    int* state;
    f32 sunTime;
    u32 size;
    s16 bit;

    state = ((GameObject*)obj)->extra;
    size = *(u8*)(p2 + 0x1a);
    if (size != 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3D88 * size;
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
        f32 scale = ((GameObject*)obj)->anim.rootMotionScale / ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
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
        modelLightStruct_setDistanceAttenuation(*state, atten, lbl_803E3D90 + atten);
        if ((*gSkyInterface)->getSunPosition(&sunTime) != 0)
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

void kt_torch_free(void);

int campfire_getExtraSize(void) { return 0x14; }
int campfire_getObjectTypeId(void) { return 0x1; }
int kt_torch_getExtraSize(void);
