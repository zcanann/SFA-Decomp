/* DLL 0x0129 - campfire area objects [8018CD64-8018CDAC) */
#include "main/game_object.h"
extern int randomGetRange(int lo, int hi);
extern void objRenderFn_8003b8f4(f32);
extern f32 timeDelta;
#include "main/dll_000A_expgfx.h"
#include "main/sky_interface.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
extern void ModelLightStruct_free(void* effect);


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
extern f32 gCampfireSizeToScale;
extern f32 lbl_803E3D8C;
extern f32 lbl_803E3D90;
extern f32 lbl_803E3D94;
extern f32 lbl_803E3D98;

/* CampfireExtra - the per-class extra state block (GameObject.extra) for the
 * campfire object class; campfire_getExtraSize() returns 0x14. Single-owner;
 * offsets mirror the observed deref widths in this unit. */
typedef struct CampfireExtra {
    void *light;     /* 0x00 ModelLightStruct handle (objCreateLight result) */
    f32 dayTimer;    /* 0x04 flicker/sound timer used in the daytime branch */
    f32 nightTimer;  /* 0x08 timer used in the night branch */
    s16 gameBit;     /* 0x0C gamebit index (from spawn descriptor +0x18) */
    u8 unk0E[2];
    u8 unk10;        /* 0x10 (from spawn descriptor +0x1b) */
    u8 flags;        /* 0x11 bit0 = gamebit 0x8c set, bit2 = gameBit set */
    u8 sfxPlaying;   /* 0x12 looped-sound active flag */
    u8 unk13;
} CampfireExtra;

STATIC_ASSERT(offsetof(CampfireExtra, gameBit) == 0xC);
STATIC_ASSERT(sizeof(CampfireExtra) == 0x14);

void campfire_update(int obj)
{

    extern void Sfx_AddLoopedObjectSound(int obj, int sfxId);
    extern void* Obj_GetPlayerObject(void);
    CampfireExtra* state;
    int type;
    int mode;
    int flag;
    f32 sunTime;
    f32 params[3];

    state = ((GameObject*)obj)->extra;
    Obj_GetPlayerObject();
    if ((*gSkyInterface)->getSunPosition(&sunTime) != 0)
    {
        if (state->light != NULL)
        {
            modelLightStruct_setEnabled((int)state->light, 1, lbl_803E3D78);
        }
        ObjHits_SetHitVolumeSlot(obj, 0x1f, 1, 0);
        state->nightTimer -= timeDelta;
        if (state->nightTimer <= lbl_803E3D7C)
        {
            flag = 1;
            state->nightTimer += lbl_803E3D78;
        }
        else
        {
            flag = 0;
        }
        type = 2;
        mode = 0;
        if (state->sfxPlaying == 0)
        {
            Sfx_AddLoopedObjectSound(obj, SFXTRIG_forcecryslp11);
            state->sfxPlaying = 1;
        }
    }
    else
    {
        if (state->light != NULL)
        {
            modelLightStruct_setEnabled((int)state->light, 0, lbl_803E3D78);
        }
        ObjHits_ClearHitVolumes(obj);
        state->dayTimer -= timeDelta;
        if (state->dayTimer <= lbl_803E3D7C)
        {
            mode = 3;
            state->dayTimer += lbl_803E3D80;
        }
        else
        {
            mode = 0;
        }
        type = 0;
        flag = 0;
        if (state->sfxPlaying != 0)
        {
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_forcecryslp11);
            state->sfxPlaying = 0;
        }
    }
    params[0] = lbl_803E3D7C;
    params[1] = lbl_803E3D80;
    params[2] = lbl_803E3D7C;
    fn_80098B18(obj, lbl_803E3D84 * ((GameObject*)obj)->anim.rootMotionScale, type, mode, flag, params);
    {
        u8* light = state->light;
        if (light != NULL && light[0x2f8] != 0 && light[0x4c] != 0)
        {
            int rnd;
            u8* l2;
            s16 v;
            rnd = randomGetRange(-0x19, 0x19);
            l2 = state->light;
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
            *(u8*)((int)state->light + 0x2f9) = v;
        }
    }
}

void campfire_init(int obj, int p2)
{
    CampfireExtra* state;
    f32 sunTime;
    u32 size;
    s16 bit;

    state = ((GameObject*)obj)->extra;
    size = *(u8*)(p2 + 0x1a);
    if (size != 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = gCampfireSizeToScale * size;
    }
    if (GameBit_Get(0x8c) != 0)
    {
        state->flags |= 1;
    }
    state->gameBit = *(s16*)(p2 + 0x18);
    bit = state->gameBit;
    if (bit != -1 && GameBit_Get(bit) != 0)
    {
        state->flags |= 4;
    }
    state->unk10 = *(u8*)(p2 + 0x1b);
    {
        f32 scale = ((GameObject*)obj)->anim.rootMotionScale / ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
        int m = *(int*)&((GameObject*)obj)->anim.hitReactState;
        ObjHitbox_SetCapsuleBounds(obj,
                                   (int)((f32)((ObjHitsPriorityState*)m)->primaryRadius * scale),
                                   (int)((f32)((ObjHitsPriorityState*)m)->primaryCapsuleOffsetA * scale),
                                   (int)((f32)((ObjHitsPriorityState*)m)->primaryCapsuleOffsetB * scale));
    }
    state->dayTimer = lbl_803E3D80;
    state->nightTimer = lbl_803E3D78;
    if (state->light == NULL)
    {
        state->light = (void*)objCreateLight(obj, 1);
    }
    if (state->light != NULL)
    {
        int atten;
        modelLightStruct_setLightKind((int)state->light, 2);
        modelLightStruct_setDiffuseColor((int)state->light, 0xff, 0x7f, 0, 0xff);
        modelLightStruct_setSpecularColor((int)state->light, 0xff, 0x7f, 0, 0xff);
        atten = (int)(lbl_803E3D8C * ((GameObject*)obj)->anim.rootMotionScale);
        modelLightStruct_setDistanceAttenuation((int)state->light, atten, lbl_803E3D90 + atten);
        if ((*gSkyInterface)->getSunPosition(&sunTime) != 0)
        {
            modelLightStruct_setEnabled((int)state->light, 1, lbl_803E3D7C);
        }
        else
        {
            modelLightStruct_setEnabled((int)state->light, 0, lbl_803E3D7C);
        }
        modelLightStruct_setPosition((int)state->light, lbl_803E3D7C, lbl_803E3D94, *(f32*)&lbl_803E3D7C);
        modelLightStruct_startColorFade((int)state->light, 1, 3);
        modelLightStruct_setDiffuseTargetColor((int)state->light, 0xff, 0x5c, 0, 0xff);
        modelLightStruct_setupGlow((int)state->light, 0, 0xff, 0x7f, 0, 0x87,
                                   lbl_803E3D98 * ((GameObject*)obj)->anim.rootMotionScale);
        modelLightStruct_setGlowProjectionRadius((int)state->light, lbl_803E3D90);
    }
}

void campfire_free(int obj)
{
    CampfireExtra* state;
    void* effect;

    state = ((GameObject*)obj)->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    effect = state->light;
    if (effect != 0)
    {
        ModelLightStruct_free(effect);
    }
}

void campfire_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    CampfireExtra* state;
    void* effect;
    s32 isVisible;

    state = ((GameObject*)obj)->extra;
    isVisible = visible;
    if (isVisible != 0)
    {
        objRenderFn_8003b8f4(lbl_803E3D78);
        effect = state->light;
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
