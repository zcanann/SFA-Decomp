/*
 * dimlogfire (DLL 0x1C0) - DIM log-fire hazard; the burning log drives a
 * flicker/douse state machine, spawns particles and a point light, handles
 * a sequence callback for animation events, and tracks a hit-strength counter
 * that douses the flame when depleted.
 */
#include "main/audio/sfx_ids.h"
#include "main/vecmath.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/linklevcontrolstate_struct.h"
#include "main/dll/lavaball1bfstate_struct.h"
#include "main/dll/imspacethrusterstate_struct.h"
#include "main/dll/lavaball1bestate_struct.h"
#include "main/dll/imanimspacecraftstate_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/objfx.h"
#include "main/dll/DIM/DIMcannon.h"
#include "main/dll/DIM/dimlogfire.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/dll/DIM/DIMboulder.h"

typedef struct DimlogfirePlacement
{
    u8 pad0[0x1E - 0x0];
    s16 douseGameBit;
    u8 pad20[0x68 - 0x20];
    void* linkedObjPtr; /* 0x68 pointer to an object; its vtable[0x28/4] method is invoked */
    u8 pad6C[0x70 - 0x6C];
} DimlogfirePlacement;

typedef struct DimlogfireObjectDef
{
    u8 pad0[0x1A - 0x0];
    s16 initMode;
    s16 strengthInit;
    s16 douseGameBit;
} DimlogfireObjectDef;

STATIC_ASSERT(sizeof(ImAnimSpacecraftState) == 0x4);

STATIC_ASSERT(sizeof(ImSpaceThrusterState) == 0xC);

STATIC_ASSERT(sizeof(LinkLevControlState) == 0x10);

STATIC_ASSERT(sizeof(Lavaball1beState) == 0x14);

STATIC_ASSERT(sizeof(Lavaball1bfState) == 0x1C);

#define DIMLOGFIRE_OBJFLAG_HITDETECT_DISABLED 0x2000
#define DIMLOGFIRE_HIT_VOLUME_SLOT            0x1f
/* smoke particle emitted while the smoke-toggle phase is active */
#define DIMLOGFIRE_PARTFX_SMOKE 215
#define MODEL_LIGHT_KIND_POINT  2

/* DimLogFireState.mode flame state machine */
#define DIMLOGFIRE_MODE_LIT       1 /* burning: point light on, flicker + smoke particles */
#define DIMLOGFIRE_MODE_UNLIT     2 /* doused: light off, waiting on the tricky/strength gate */
#define DIMLOGFIRE_MODE_ANIM_HELD 4 /* frozen by anim event 3 (SeqFn triggerCommand) */

#define DIMLOGFIRE_GROUP 0x31


extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern f32 timeDelta;
extern void ModelLightStruct_free(void* light);
extern void Sfx_StopObjectChannel(int* obj, int channel);
extern void queueGlowRender(int* obj);
extern f32 lbl_803E4820;
extern void ObjGroup_AddObject(u32 obj, int group);
extern void modelLightStruct_setSpecularColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setEnabled(int light, int mode, f32 value);
extern void modelLightStruct_setPosition(int light, f32 x, f32 y, f32 z);
extern void modelLightStruct_startColorFade(int light, int a, int b);
extern void modelLightStruct_setDiffuseTargetColor(int light, int r, int g, int b, int a);
extern f32 lbl_803E4824;
extern f32 lbl_803E4828;
extern f32 lbl_803E482C;
extern f32 lbl_803E4830;
extern f32 lbl_803E4834;
extern f32 lbl_803E4838;
extern f32 lbl_803E483C;

int DIMLogFire_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern int Sfx_PlayFromObject(int* obj, int sfxId);
    DimLogFireState* state = ((GameObject*)obj)->extra;
    if (state->mode == DIMLOGFIRE_MODE_LIT)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_mushdizzylp12);
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
        mainSetBits(46, 1);
        break;
    case 3:
        state->mode = DIMLOGFIRE_MODE_ANIM_HELD;
        break;
    }
    if (state->smokeToggle != 0)
    {
        (*gPartfxInterface)->spawnObject(obj, DIMLOGFIRE_PARTFX_SMOKE, NULL, 0, -1, NULL);
        Sfx_StopObjectChannel(obj, 5);
    }
    else
    {
        Sfx_StopObjectChannel(obj, 1);
    }
    animUpdate->triggerCommand = 0;
    return 0;
}

int fn_801B0784(GameObject* obj, int delta)
{
    DimLogFireState* inner = obj->extra;
    inner->strengthInit = (s8)(inner->strengthInit - delta);
    return inner->strengthInit <= 0;
}

int DIMLogFire_getExtraSize(void)
{
    return 0x24;
}
int DIMLogFire_getObjectTypeId(void)
{
    return 0x1;
}

void DIMLogFire_free(int* obj, int mode)
{
    extern void Obj_FreeObject(void* o);
    DimLogFireState* inner = ((GameObject*)obj)->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    if ((void*)inner->subObj != NULL && mode == 0)
    {
        Obj_FreeObject((int*)inner->subObj);
    }
    ObjGroup_RemoveObject(obj, DIMLOGFIRE_GROUP);
    if ((void*)inner->light != NULL)
    {
        ModelLightStruct_free((void*)inner->light);
    }
}

void DIMLogFire_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
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
            ((void (*)(int*, int, int, int, int, f32))objRenderModelAndHitVolumes)((int*)state->subObj, p2, p3, p4, p5,
                                                                                   lbl_803E4820);
        }
        ((void (*)(int*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E4820);
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

void DIMLogFire_update(GameObject* obj)
{
    extern int getTrickyObject(void);
    extern void Sfx_PlayFromObject(int obj, int sfxId);
    int flickerFlagA;
    int flickerFlagB;
    int rand;
    s16 alpha;
    u32 light;
    int tricky;
    DimLogFireState* state;
    struct
    {
        f32 x, y, z;
    } vec;

    state = (obj)->extra;
    tricky = *(int*)&(obj)->anim.placementData;
    (obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    switch (state->mode)
    {
    case DIMLOGFIRE_MODE_LIT:
        if (*(int**)&state->light != NULL)
        {
            modelLightStruct_setEnabled(state->light, 1, lbl_803E4824);
        }
        Sfx_PlayFromObject((int)obj, SFXTRIG_mushdizzylp12);
        state->flickerTimerA = state->flickerTimerA - timeDelta;
        if (state->flickerTimerA <= lbl_803E4828)
        {
            flickerFlagA = 7;
            state->flickerTimerA = state->flickerTimerA + lbl_803E482C;
        }
        else
        {
            flickerFlagA = 0;
        }
        state->flickerTimerB = state->flickerTimerB - timeDelta;
        if (state->flickerTimerB <= lbl_803E4828)
        {
            flickerFlagB = 1;
            state->flickerTimerB = state->flickerTimerB + lbl_803E4820;
        }
        else
        {
            flickerFlagB = 0;
        }
        vec.x = lbl_803E4828;
        vec.y = lbl_803E482C;
        vec.z = lbl_803E4828;
        fn_80098B18Legacy((int)obj, (obj)->anim.rootMotionScale, 2, flickerFlagA, flickerFlagB, (int)&vec);
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DIMLOGFIRE_HIT_VOLUME_SLOT, 1, 0);
        break;
    case DIMLOGFIRE_MODE_UNLIT:
        if (*(int**)&state->light != NULL)
        {
            modelLightStruct_setEnabled(state->light, 0, lbl_803E4824);
        }
        if (state->strengthInit <= 0)
        {
            ObjHits_DisableObject((int)obj);
            state->mode = DIMLOGFIRE_MODE_LIT;
            state->dousedLatch = 1;
            mainSetBits(((DimlogfirePlacement*)tricky)->douseGameBit, 1);
        }
        tricky = getTrickyObject();
        if ((u32)tricky != 0)
        {
            if (((obj)->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)
            {
                (*(void (**)(int, int, int, int))(**(int**)&((DimlogfirePlacement*)tricky)->linkedObjPtr + 0x28))(
                    tricky, (int)obj, 1, 4);
            }
            (obj)->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        }
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, 0, 0, 0);
        break;
    case DIMLOGFIRE_MODE_ANIM_HELD:
        break;
    default:
        if (state->initMode == 0)
        {
            state->mode = DIMLOGFIRE_MODE_LIT;
            state->dousedLatch = 1;
        }
        else
        {
            state->mode = DIMLOGFIRE_MODE_UNLIT;
        }
        break;
    }
    if ((s8)state->dousedLatch != 0)
    {
        state->dousedLatch = 0;
    }
    light = state->light;
    if (light != 0 && *(u8*)(light + 0x2f8) != 0 && *(u8*)(light + 0x4c) != 0)
    {
        rand = randomGetRange(-0x19, 0x19);
        light = state->light;
        alpha = *(u8*)(light + 0x2f9) + *(s8*)(light + 0x2fa) + rand;
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

void DIMLogFire_init(int obj, int def)
{
    extern void modelLightStruct_setGlowProjectionRadius(int light, f32 radius);
    extern void modelLightStruct_setupGlow(int light, int mode, int r, int g, int b, int a, f32 radius);
    extern void modelLightStruct_setDistanceAttenuation(int light, f32 near, f32 far);
    extern void modelLightStruct_setDiffuseColor(int light, int r, int g, int b, int a);
    extern void modelLightStruct_setLightKind(int light, int value);
    extern int objCreateLight(int obj, int mode);
    int radius;
    DimLogFireState* state;

    ((GameObject*)obj)->animEventCallback = DIMLogFire_SeqFn;
    ObjGroup_AddObject(obj, DIMLOGFIRE_GROUP);
    state = ((GameObject*)obj)->extra;
    state->unk20 = 0;
    state->initMode = ((DimlogfireObjectDef*)def)->initMode;
    state->strengthInit = (s8)((DimlogfireObjectDef*)def)->strengthInit;
    state->strength = *(u8*)&state->strengthInit;
    if (mainGetBit(((DimlogfireObjectDef*)def)->douseGameBit) != 0)
    {
        state->mode = DIMLOGFIRE_MODE_LIT;
        state->dousedLatch = 1;
    }
    ((GameObject*)obj)->objectFlags |= DIMLOGFIRE_OBJFLAG_HITDETECT_DISABLED;
    state->flickerTimerA = lbl_803E482C;
    state->flickerTimerB = lbl_803E4820;
    if (*(int**)&state->light == NULL)
    {
        state->light = objCreateLight(obj, 1);
    }
    if (*(int**)&state->light != NULL)
    {
        modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setDiffuseColor(state->light, 0xff, 0x7f, 0, 0xff);
        modelLightStruct_setSpecularColor(state->light, 0xff, 0x7f, 0, 0xff);
        radius = (int)(lbl_803E4830 * ((GameObject*)obj)->anim.rootMotionScale);
        modelLightStruct_setDistanceAttenuation(state->light, radius, lbl_803E4834 + radius);
        modelLightStruct_setEnabled(state->light, 1, lbl_803E4828);
        modelLightStruct_setPosition(state->light, lbl_803E4828, lbl_803E4838, *(f32*)&lbl_803E4828);
        modelLightStruct_startColorFade(state->light, 1, 3);
        modelLightStruct_setDiffuseTargetColor(state->light, 0xff, 0x5c, 0, 0xff);
        modelLightStruct_setupGlow(state->light, 0, 0xff, 0x7f, 0, 0x87,
                                   lbl_803E483C * ((GameObject*)obj)->anim.rootMotionScale);
        modelLightStruct_setGlowProjectionRadius(state->light, lbl_803E4834);
    }
}
