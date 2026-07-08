/*
 * flammablevine (DLL 0xE7) - a burnable vine obstacle.
 *
 * Lives in object group 0x31. A flame hit (ObjHits priority-hit type
 * 0x1a) ignites it: the placement's "burned" game bit (def->burnedBit)
 * is set, a sfx plays, and a burn timer starts. While burning, update()
 * fades the model out, drives the burn anim progress, plays the looped
 * lift sound, and finally removes the object from the update list and
 * disables its hits.
 *
 * When def->gateBit is valid it must be set AND the Tricky companion
 * must be present AND game bit 0x245 (use-vine enabled) must be set;
 * when def->gateBit is -1 the vine is always usable. If the burned bit
 * is already set at init the vine spawns already-consumed (hidden,
 * hits off).
 */
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/dll/VF/vf_shared.h"
#include "main/audio/sfx.h"
#include "sfa_light_decls.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_00E7_flammablevine.h"

#define FLAMMABLEVINE_HIT_VOLUME_SLOT 9

/* object group this object joins while active */
#define FLAMMABLEVINE_OBJGROUP 0x31

extern void ObjHitbox_SetCapsuleBounds();
extern void ObjHits_DisableObject();
extern void ObjGroup_RemoveObject(u32 obj, int group);
extern void ObjGroup_AddObject(u32 obj, int group);
extern void Obj_RemoveFromUpdateList(int obj);
extern void fn_80098B18(int obj, f32 scale, int type, int a, int b, int c);
extern void* getTrickyObject(void);

int FlammableVine_getExtraSize(void)
{
    return 0x14;
}

int FlammableVine_getObjectTypeId(void)
{
    return 0x0;
}

void FlammableVine_free(int obj)
{
    ObjGroup_RemoveObject(obj, FLAMMABLEVINE_OBJGROUP);
}

void FlammableVine_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, 1.0f);
}

void FlammableVine_hitDetect(int obj)
{
    FlammablevineState* state;
    u8* def;
    int hitObj;

    state = ((GameObject*)obj)->extra;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if ((state->flags & 3) == 0)
    {
        if (ObjHits_GetPriorityHit(obj, 0, 0, &hitObj) == 0x1a)
        {
            if (((FlammablevineObjectDef*)def)->burnedBit != -1)
            {
                mainSetBits(((FlammablevineObjectDef*)def)->burnedBit, 1);
                Sfx_PlayFromObject(0, SFXTRIG_sc_menuups16k_409);
            }
            state->burnTimer = 240.0f;
            state->flags = state->flags | 1;
        }
    }
}

void FlammableVine_update(int obj)
{
    FlammablevineState* state;
    u8* def;
    void* tricky;
    u8 canUse;
    f32 burnTimer;
    f32 zero;
    int pulseStyle;
    u32 fadeAlpha;

    state = ((GameObject*)obj)->extra;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    tricky = getTrickyObject();

    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED;
    if (((FlammablevineObjectDef*)def)->gateBit == -1)
    {
        goto can_use_vine;
    }
    if (mainGetBit(((FlammablevineObjectDef*)def)->gateBit) == 0)
    {
        goto cant_use_vine;
    }
    if (tricky == NULL)
    {
        goto cant_use_vine;
    }
    if (mainGetBit(GAMEBIT_ITEM_TrickyFlame_Got) == 0)
    {
        goto cant_use_vine;
    }
can_use_vine:
    canUse = 1;
    goto checked_vine_use;
cant_use_vine:
    canUse = 0;
checked_vine_use:

    if ((state->flags & 3) == 0)
    {
        if (state->setupParam == 0)
        {
            ObjHits_SetHitVolumeSlot(obj, FLAMMABLEVINE_HIT_VOLUME_SLOT, 1, 0);
        }
        ObjHits_EnableObject(obj);

        if (((GameObject*)obj)->anim.seqId == 0x102)
        {
            if (cMenuGetSelectedItem() == -1)
            {
                ((GameObject*)obj)->anim.modelInstance->hitVolumes[0].priority = 0;
            }
            else
            {
                ((GameObject*)obj)->anim.modelInstance->hitVolumes[0].priority = 0x10;
            }
        }

        if (tricky != NULL && canUse != 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED;
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0)
            {
                TrickyIface* iface = *(TrickyIface**)((u8*)tricky + 0x68);
                iface->vtbl->slot28(tricky, obj, 1, 4);
            }
        }
    }

    burnTimer = state->burnTimer;
    zero = 0.0f;
    if (burnTimer > zero)
    {
        state->burnTimer = burnTimer - timeDelta;
        if (state->burnTimer <= zero)
        {
            ((GameObject*)obj)->anim.alpha = 0;
            state->burnTimer = zero;
            state->flags = state->flags & ~1;
            state->flags = state->flags | 2;
            Obj_RemoveFromUpdateList(obj);
            ObjHits_DisableObject(obj);
        }
    }

    if ((state->flags & 1) != 0)
    {
        if (state->burnTimer < 120.0f)
        {
            state->burnIntensity = 1.0f;
        }
        else
        {
            state->burnIntensity = 1.0f - ((state->burnTimer - 120.0f) / 120.0f);
        }

        if (state->burnTimer < 180.0f && state->burnTimer > 120.0f)
        {
            ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)((ObjAnimComponent*)obj,
                                                                       1.0f - ((state->burnTimer - 120.0f) / 60.0f));
        }

        if (state->burnTimer < 150.0f)
        {
            if (state->burnTimer < 120.0f)
            {
                ((GameObject*)obj)->anim.alpha = 0;
            }
            else
            {
                fadeAlpha = (u8)(255.0f * ((state->burnTimer - 120.0f) / 30.0f));
                ((GameObject*)obj)->anim.alpha = fadeAlpha;
            }
        }

        state->pulseTimer = state->pulseTimer - timeDelta;
        if (state->pulseTimer <= 0.0f)
        {
            pulseStyle = 3;
            state->pulseTimer += 1.0f;
        }
        else
        {
            pulseStyle = 0;
        }
        fn_80098B18(obj, 0.65f * (state->burnIntensity * ((GameObject*)obj)->anim.rootMotionScale), 3, 0, pulseStyle,
                    0);
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_forcecryslp11);
    }
}

void FlammableVine_init(int obj, int def)
{
    FlammablevineState* state;
    f32 scale;

    state = ((GameObject*)obj)->extra;
    ObjGroup_AddObject(obj, FLAMMABLEVINE_OBJGROUP);
    ((GameObject*)obj)->anim.rotX = (s16)(((FlammablevineObjectDef*)def)->rotXByte << 8);

    ((GameObject*)obj)->anim.rootMotionScale = 5.0f * ((f32)((FlammablevineObjectDef*)def)->scaleParam / 32767.0f);
    if (((GameObject*)obj)->anim.rootMotionScale <= 0.05f)
    {
        ((GameObject*)obj)->anim.rootMotionScale = 0.05f;
    }

    scale = ((GameObject*)obj)->anim.rootMotionScale;
    ObjHitbox_SetCapsuleBounds(obj, (s16)(14.0f * scale), 0, (s16)(25.0f * scale));
    state->burnIntensity = 0.001f;
    ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)((ObjAnimComponent*)obj, 0.0f);

    if (((FlammablevineObjectDef*)def)->burnedBit != -1 && mainGetBit(((FlammablevineObjectDef*)def)->burnedBit) != 0)
    {
        Obj_RemoveFromUpdateList(obj);
        ObjHits_DisableObject(obj);
        ((GameObject*)obj)->anim.alpha = 0;
        state->flags = state->flags | 2;
    }

    state->setupParam = ((FlammablevineObjectDef*)def)->setupParam;
    if (state->setupParam == 1)
    {
        ObjHits_MarkObjectPositionDirty(obj);
    }
}

void FlammableVine_release(void)
{
}

void FlammableVine_initialise(void)
{
}
