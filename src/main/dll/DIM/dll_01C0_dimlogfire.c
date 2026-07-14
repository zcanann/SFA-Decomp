/*
 * dimlogfire (DLL 0x1C0) - DIM log-fire hazard; the burning log drives a
 * flicker/douse state machine, spawns particles and a point light, handles
 * a sequence callback for animation events, and tracks a hit-strength counter
 * that douses the flame when depleted.
 */
#include "main/dll/partfx_interface.h"
#include "main/audio/sfx_ids.h"
#include "main/object.h"
#include "main/vecmath.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/linklevcontrolstate_struct.h"
#include "main/dll/lavaball1bfstate_struct.h"
#include "main/dll/imspacethrusterstate_struct.h"
#include "main/dll/lavaball1bestate_struct.h"
#include "main/dll/imanimspacecraftstate_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/game_object.h"
#include "main/object_render_legacy.h"
#include "main/model_light.h"
#include "main/objfx.h"
#include "main/dll/DIM/dimlogfire.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/obj_group.h"
#include "main/object_descriptor.h"

STATIC_ASSERT(sizeof(ImAnimSpacecraftState) == 0x4);

STATIC_ASSERT(sizeof(ImSpaceThrusterState) == 0xC);

STATIC_ASSERT(sizeof(LinkLevControlState) == 0x10);

STATIC_ASSERT(sizeof(Lavaball1beState) == 0x14);

STATIC_ASSERT(sizeof(Lavaball1bfState) == 0x1C);

#define DIMLOGFIRE_OBJFLAG_HITDETECT_DISABLED 0x2000
#define DIMLOGFIRE_HIT_VOLUME_SLOT            0x1f
/* smoke particle emitted while the smoke-toggle phase is active */
#define DIMLOGFIRE_PARTFX_SMOKE 215

/* DimLogFireState.mode flame state machine */
#define DIMLOGFIRE_MODE_LIT       1 /* burning: point light on, flicker + smoke particles */
#define DIMLOGFIRE_MODE_UNLIT     2 /* doused: light off, waiting on the tricky/strength gate */
#define DIMLOGFIRE_MODE_ANIM_HELD 4 /* frozen by anim event 3 (SeqFn triggerCommand) */

#define DIMLOGFIRE_GROUP 0x31


#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E4820 = 1.0f;
__declspec(section ".sdata2") f32 lbl_803E4824 = 2.0f;
__declspec(section ".sdata2") f32 lbl_803E4828 = 0.0f;
__declspec(section ".sdata2") f32 lbl_803E482C = 10.0f;
__declspec(section ".sdata2") f32 lbl_803E4830 = 20.0f;
__declspec(section ".sdata2") f32 lbl_803E4834 = 30.0f;
__declspec(section ".sdata2") f32 lbl_803E4838 = 12.0f;
__declspec(section ".sdata2") f32 lbl_803E483C = 40.0f;
#pragma explicit_zero_data off

int DIMLogFire_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    DimLogFireState* state = obj->extra;
    if (state->mode == DIMLOGFIRE_MODE_LIT)
    {
        Sfx_PlayFromObject((u32)obj, SFXTRIG_mushdizzylp12);
    }
    else
    {
        Sfx_StopObjectChannel((u32)obj, 64);
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
        Sfx_StopObjectChannel((u32)obj, 5);
    }
    else
    {
        Sfx_StopObjectChannel((u32)obj, 1);
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

void DIMLogFire_free(GameObject* obj, int mode)
{
    DimLogFireState* inner = obj->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    if ((void*)inner->subObj != NULL && mode == 0)
    {
        Obj_FreeObject((GameObject*)inner->subObj);
    }
    ObjGroup_RemoveObject((int)obj, DIMLOGFIRE_GROUP);
    if (inner->light != NULL)
    {
        ModelLightStruct_free(inner->light);
    }
}

void DIMLogFire_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    DimLogFireState* state;
    int* subobj;
    if ((s32)visible != 0)
    {
        state = obj->extra;
        subobj = (int*)state->subObj;
        if (subobj != NULL)
        {
            int* q = (int*)((ObjAnimComponent*)subobj)->banks[((ObjAnimComponent*)subobj)->bankIndex];
            *(u16*)((char*)q + 0x18) = (u16)(*(u16*)((char*)q + 0x18) & ~0x8);
            *(u8*)((char*)(int*)state->subObj + 0x37) = *(u8*)((char*)obj + 0x37);
            ((void (*)(GameObject*, int, int, int, int, f32))objRenderModelAndHitVolumes)(
                (GameObject*)state->subObj, p2, p3, p4, p5, lbl_803E4820);
        }
        ((void (*)(GameObject*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5,
                                                                                     lbl_803E4820);
        if (state->light != NULL)
        {
            if (state->light->glowType != 0)
            {
                if (state->light->enabled != 0)
                {
                    queueGlowRender(state->light);
                }
            }
        }
    }
}

void DIMLogFire_update(GameObject* obj)
{
    int flickerFlagA;
    int flickerFlagB;
    int rand;
    s16 alpha;
    ModelLightStruct* light;
    GameObject* tricky;
    DimlogfirePlacement* placement;
    DimLogFireState* state;
    struct
    {
        f32 x, y, z;
    } vec;

    state = (obj)->extra;
    placement = (DimlogfirePlacement*)obj->anim.placementData;
    (obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    switch (state->mode)
    {
    case DIMLOGFIRE_MODE_LIT:
        if (state->light != NULL)
        {
            modelLightStruct_setEnabled(state->light, 1, lbl_803E4824);
        }
        Sfx_PlayFromObject((u32)obj, SFXTRIG_mushdizzylp12);
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
        if (state->light != NULL)
        {
            modelLightStruct_setEnabled(state->light, 0, lbl_803E4824);
        }
        if (state->strengthInit <= 0)
        {
            ObjHits_DisableObject((int)obj);
            state->mode = DIMLOGFIRE_MODE_LIT;
            state->dousedLatch = 1;
            mainSetBits(placement->douseGameBit, 1);
        }
        tricky = (GameObject*)getTrickyObject();
        if (tricky != NULL)
        {
            if (((obj)->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)
            {
                (*(void (**)(GameObject*, GameObject*, int, int))((u8*)*tricky->anim.dll + 0x28))(tricky, obj, 1, 4);
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
    if (light != NULL && light->glowType != 0 && light->enabled != 0)
    {
        rand = randomGetRange(-0x19, 0x19);
        light = state->light;
        alpha = light->glowAlpha + light->glowAlphaStep + rand;
        if (alpha < 0)
        {
            alpha = 0;
            light->glowAlphaStep = 0;
        }
        else if (alpha > 0xff)
        {
            alpha = 0xff;
            light->glowAlphaStep = 0;
        }
        state->light->glowAlpha = alpha;
    }
}

void DIMLogFire_init(int obj, DimlogfireObjectDef* def)
{
    int radius;
    DimLogFireState* state;

    ((GameObject*)obj)->animEventCallback = DIMLogFire_SeqFn;
    ObjGroup_AddObject(obj, DIMLOGFIRE_GROUP);
    state = ((GameObject*)obj)->extra;
    state->unk20 = 0;
    state->initMode = def->initMode;
    state->strengthInit = (s8)def->strengthInit;
    state->strength = *(u8*)&state->strengthInit;
    if (mainGetBit(def->douseGameBit) != 0)
    {
        state->mode = DIMLOGFIRE_MODE_LIT;
        state->dousedLatch = 1;
    }
    ((GameObject*)obj)->objectFlags |= DIMLOGFIRE_OBJFLAG_HITDETECT_DISABLED;
    state->flickerTimerA = lbl_803E482C;
    state->flickerTimerB = lbl_803E4820;
    if (state->light == NULL)
    {
        state->light = objCreateLight((GameObject*)obj, 1);
    }
    if (state->light != NULL)
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

ObjectDescriptor gDIMLogFireObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)DIMLogFire_init,
    (ObjectDescriptorCallback)DIMLogFire_update,
    0,
    (ObjectDescriptorCallback)DIMLogFire_render,
    (ObjectDescriptorCallback)DIMLogFire_free,
    (ObjectDescriptorCallback)DIMLogFire_getObjectTypeId,
    DIMLogFire_getExtraSize,
};
