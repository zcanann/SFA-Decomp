/*
 * dimbossspit (DLL 0x1E5) - the DIM boss spit-ball projectile object.
 * Launched from the boss, the spit ball drifts under gravity, spinning on all
 * axes, and spawns particle trail fx each frame.  On contact it transitions to
 * a burst phase (DIMbossspit_updateBurst): camera shake, rumble, expanding
 * transparent sphere hitbox, and a shrinking hit volume.  Carries a green glow
 * light whose intensity flickers frame-by-frame.
 */
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/model_light.h"
#include "main/audio/sfx_ids.h"
#include "main/objlib.h"
#include "main/objhits.h"

#define MODEL_LIGHT_KIND_POINT 2

typedef struct DIMbossspitUpdateBurstState
{
    u8 pad0[0x4 - 0x0];
    ModelLightStruct* light;
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
    ModelLightStruct* light;
    u8 pad8[0x3DC - 0x8];
    s32 unk3DC;
    u8 pad3E0[0x400 - 0x3E0];
    u16 unk400;
    u8 pad402[0x40C - 0x402];
    s32 unk40C;
} DIMbossspitState;

extern void ModelLightStruct_free(ModelLightStruct* light);
extern int randomGetRange(int lo, int hi);
extern void Obj_FreeObject(int obj);
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern f32 lbl_803E4D44;
extern u8 framesThisStep;
extern f32 timeDelta;
extern void objMove(int obj, f32 x, f32 y, f32 z);
extern void Sfx_PlayFromObject(int obj, int id);
extern void CameraShake_SetAllMagnitudes(f32 magnitude);
extern void doRumble(f32 duration);
extern f32 lbl_803E4D38;
extern f32 lbl_803E4D3C;
extern f32 lbl_803E4D40;
extern f32 lbl_803E4D48;
extern f32 gDimBossSpitBurstAlphaScale;
extern f32 lbl_803E4D50;
extern f32 gDimBossSpitGravity;
extern f32 gDimBossSpitVelocityDamping;
extern f32 lbl_803E4D68;
extern const f32 lbl_803E4D6C;
extern void* objCreateLight(int arg, u8 addToList);
extern void modelLightStruct_setDistanceAttenuation(ModelLightStruct* light, f32 a, f32 b);
extern void lightSetField4D(ModelLightStruct* p, u8 v);
extern int Obj_GetActiveModel(int obj);
extern void ObjModel_SetPostRenderCallback(int model, void* cb);
extern void postRenderSetAlphaBlendState(void);
extern f32 lbl_803E4D70;
extern f32 lbl_803E4D74;
extern f32 lbl_803E4D78;
extern f32 lbl_803E4D7C;
extern f32 lbl_803E4D80;

void DIMbossspit_updateBurst(int obj)
{
    int state;
    s16 burstTimer;
    int iVar;
    int alpha;
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
    *(s16*)state += framesThisStep;
    burstTimer = *(s16*)state;
    if (burstTimer > 0x200)
    {
        if (burstTimer > 0x22a)
        {
            Obj_FreeObject(obj);
        }
        return;
    }
    iVar = (int)
    (lbl_803E4D48 * ((f32)(s32)
    burstTimer * gDimBossSpitBurstAlphaScale
    )
    )
    ;
    alpha = 0xff - iVar;
    radius = 0x94 - (burstTimer >> 2);
    if (alpha >= 0)
    {
        ObjHits_SetHitVolumeSlot(obj, 5, 2, 0);
        ObjHitbox_SetSphereRadius(obj, (s16)((radius - 0x40) >> 1));
        ((GameObject*)obj)->anim.alpha = alpha;
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

void DIMbossspit_free(int objArg)
{
    int obj = objArg;
    u32 state;

    state = *(u32*)(*(int*)&((GameObject*)obj)->extra + 4);
    if (state != 0)
    {
        ModelLightStruct_free((void*)state);
    }
    (*gExpgfxInterface)->freeSource2((u32)obj);
    return;
}

void DIMbossspit_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    ModelLightStruct* light;

    light = ((GameObject*)obj)->extra;
    if (visible != 0)
    {
        ((void(*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5,
                                                                      lbl_803E4D44);
        light = ((DIMbossspitState*)light)->light;
        if (((light != 0) && (light->glowType != 0)) && (light->enabled != 0))
        {
            queueGlowRender(light);
        }
    }
    return;
}

void DIMbossspit_update(int obj)
{
    int state;
    int i;
    s16 glowAlpha;
    ModelLightStruct* p;

    state = *(int*)&((GameObject*)obj)->extra;
    if (*(s16*)state == 0)
    {
        ((GameObject*)obj)->unkF4 -= framesThisStep;
        if (((GameObject*)obj)->unkF4 < 0)
        {
            Obj_FreeObject(obj);
            return;
        }
        ObjHits_SetHitVolumeSlot(obj, 5, 4, 0);
        ObjHitbox_SetSphereRadius(obj, 10);
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY - gDimBossSpitGravity * timeDelta;
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * gDimBossSpitVelocityDamping;
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
    p = ((DIMbossspitState*)state)->light;
    if (p != NULL && p->glowType != 0 && p->enabled != 0)
    {
        glowAlpha = (s16)(p->glowAlpha + p->glowAlphaStep);
        if (glowAlpha < 0)
        {
            glowAlpha = 0;
            p->glowAlphaStep = 0;
        }
        else if (glowAlpha > 0xc)
        {
            glowAlpha = (s16)(glowAlpha + randomGetRange(-12, 12));
            if (glowAlpha > 0xff)
            {
                glowAlpha = 0xff;
                ((DIMbossspitState*)state)->light->glowAlphaStep = 0;
            }
        }
        ((DIMbossspitState*)state)->light->glowAlpha = glowAlpha;
    }
    return;
}

void DIMbossspit_init(int obj)
{
    u8* state = ((GameObject*)obj)->extra;

    *(void**)&((DIMbossspitState*)state)->light = objCreateLight(obj, 1);
    if (*(void**)&((DIMbossspitState*)state)->light != NULL)
    {
        modelLightStruct_setLightKind(((DIMbossspitState*)state)->light, MODEL_LIGHT_KIND_POINT);
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


void DIMbossspit_hitDetect(void)
{
}

void DIMbossspit_release(void)
{
}

void DIMbossspit_initialise(void)
{
}


int DIMbossspit_getExtraSize(void) { return 0x8; }
int DIMbossspit_getObjectTypeId(void) { return 0x0; }
