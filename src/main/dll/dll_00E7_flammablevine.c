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

/* object group this object joins while active */
#define FLAMMABLEVINE_OBJGROUP 0x31

typedef struct FlammablevineObjectDef
{
    u8 pad0[0x14 - 0x0];
    s32 objId;      /* 0x14 */
    s8 rotXByte;    /* 0x18: rotX in 1/256 turns */
    u8 setupParam;  /* 0x19: copied to state, 1 = position-dirty */
    s16 scaleParam; /* 0x1A: drives rootMotionScale */
    s16 unk1C;
    s16 burnedBit;  /* 0x1E: game bit set when burned; -1 = none */
    s16 gateBit;    /* 0x20: game bit gating use; -1 = none */
    u8 pad22[0x28 - 0x22];
} FlammablevineObjectDef;

typedef struct TrickyIfaceVtbl
{
    u8 pad0[0x28 - 0x0];
    void (*slot28)(void* iface, int obj, int a, int b); /* 0x28 */
} TrickyIfaceVtbl;

typedef struct TrickyIface
{
    TrickyIfaceVtbl* vtbl; /* 0x0 */
} TrickyIface;

typedef struct FlammablevineState
{
    u8 flags;             /* 0x0: bit0 burning, bit1 consumed */
    u8 setupParam;        /* 0x1: copied from def+0x19 */
    u8 pad2[0x4 - 0x2];
    f32 burnTimer;        /* 0x4 */
    u8 pad8[0xc - 0x8];
    f32 pulseTimer;       /* 0xc */
    f32 burnIntensity;    /* 0x10 */
} FlammablevineState;

extern void ObjHitbox_SetCapsuleBounds();
extern void ObjHits_DisableObject();
extern void ObjGroup_RemoveObject(u32 obj, int group);
extern void ObjGroup_AddObject(u32 obj, int group);

extern void Obj_RemoveFromUpdateList(int obj);

extern void fn_80098B18(int obj, f32 scale, int type, int a, int b, int c);

extern void* getTrickyObject(void);
extern f32 lbl_803E3AF8;
extern f32 gFlammableVineBurnDuration;
extern f32 lbl_803E3B00;
extern f32 lbl_803E3B04;
extern f32 lbl_803E3B08;
extern f32 lbl_803E3B0C;
extern f32 lbl_803E3B10;
extern f32 gFlammableVineMaxAlpha;
extern f32 lbl_803E3B18;
extern f32 lbl_803E3B1C;
extern f32 lbl_803E3B20;
extern f32 gFlammableVineScaleParamNormalize;
extern f32 gFlammableVineMinScale;
extern f32 lbl_803E3B2C;
extern f32 lbl_803E3B30;
extern f32 lbl_803E3B34;

void flammablevine_release(void)
{
}

void flammablevine_initialise(void)
{
}

int flammablevine_getExtraSize(void) { return 0x14; }
int flammablevine_getObjectTypeId(void) { return 0x0; }

void flammablevine_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E3AF8);
}

void flammablevine_free(int x) { ObjGroup_RemoveObject(x, FLAMMABLEVINE_OBJGROUP); }

void flammablevine_hitDetect(int obj)
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
                GameBit_Set(((FlammablevineObjectDef*)def)->burnedBit, 1);
                Sfx_PlayFromObject(0, SFXTRIG_sc_menuups16k_409);
            }
            state->burnTimer = gFlammableVineBurnDuration;
            state->flags = state->flags | 1;
        }
    }
}

void flammablevine_init(int obj, int def)
{
    FlammablevineState* state;
    f32 scale;

    state = ((GameObject*)obj)->extra;
    ObjGroup_AddObject(obj, FLAMMABLEVINE_OBJGROUP);
    ((GameObject*)obj)->anim.rotX = (s16)(((FlammablevineObjectDef*)def)->rotXByte << 8);

    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3B20 * ((f32)((FlammablevineObjectDef*)def)->scaleParam /
        gFlammableVineScaleParamNormalize);
    if (((GameObject*)obj)->anim.rootMotionScale <= *(f32*)&gFlammableVineMinScale)
    {
        ((GameObject*)obj)->anim.rootMotionScale = gFlammableVineMinScale;
    }

    scale = ((GameObject*)obj)->anim.rootMotionScale;
    ObjHitbox_SetCapsuleBounds(
        obj,
        (s16)(lbl_803E3B2C * scale),
        0,
        (s16)(lbl_803E3B30 * scale));
    state->burnIntensity = lbl_803E3B34;
    ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)((ObjAnimComponent*)obj, lbl_803E3B00);

    if (((FlammablevineObjectDef*)def)->burnedBit != -1 && GameBit_Get(((FlammablevineObjectDef*)def)->burnedBit) != 0)
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

void flammablevine_update(int obj)
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

    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED;
    if (((FlammablevineObjectDef*)def)->gateBit == -1)
    {
        goto can_use_vine;
    }
    if (GameBit_Get(((FlammablevineObjectDef*)def)->gateBit) == 0)
    {
        goto cant_use_vine;
    }
    if (tricky == NULL)
    {
        goto cant_use_vine;
    }
    if (GameBit_Get(0x245) == 0)
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
            ObjHits_SetHitVolumeSlot(obj, 9, 1, 0);
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
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED;
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0)
            {
                TrickyIface* iface = *(TrickyIface**)((u8*)tricky + 0x68);
                iface->vtbl->slot28(tricky, obj, 1, 4);
            }
        }
    }

    burnTimer = state->burnTimer;
    zero = lbl_803E3B00;
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
        if (state->burnTimer < lbl_803E3B04)
        {
            state->burnIntensity = lbl_803E3AF8;
        }
        else
        {
            state->burnIntensity = lbl_803E3AF8 - ((state->burnTimer - lbl_803E3B04) / lbl_803E3B04);
        }

        if (state->burnTimer < lbl_803E3B08 && state->burnTimer > lbl_803E3B04)
        {
            ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)(
                (ObjAnimComponent*)obj,
                lbl_803E3AF8 - ((state->burnTimer - lbl_803E3B04) / lbl_803E3B0C));
        }

        if (state->burnTimer < lbl_803E3B10)
        {
            if (state->burnTimer < lbl_803E3B04)
            {
                ((GameObject*)obj)->anim.alpha = 0;
            }
            else
            {
                fadeAlpha = (u8)(gFlammableVineMaxAlpha * ((state->burnTimer - lbl_803E3B04) / lbl_803E3B18));
                ((GameObject*)obj)->anim.alpha = fadeAlpha;
            }
        }

        state->pulseTimer = state->pulseTimer - timeDelta;
        if (state->pulseTimer <= lbl_803E3B00)
        {
            pulseStyle = 3;
            state->pulseTimer = state->pulseTimer + lbl_803E3AF8;
        }
        else
        {
            pulseStyle = 0;
        }
        fn_80098B18(obj, lbl_803E3B1C * (state->burnIntensity * ((GameObject*)obj)->anim.rootMotionScale), 3, 0,
                    pulseStyle, 0);
        Sfx_KeepAliveLoopedObjectSound(obj, SFXmv_liftloop);
    }
}
