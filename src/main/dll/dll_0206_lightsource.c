/*
 * DLL 0x0206 (lightsource) - a placeable point-light / flame object.
 *
 * init builds a ModelLightStruct (objCreateLight), sets its kind/colour
 * (from the gLightSourceColorTable colour table indexed by fxType), distance
 * attenuation, glow and projection radius, then primes the spark/fx
 * timers.  update toggles the lit state on a priority hit (mode 1),
 * latches the associated game bit, drives the per-frame particle fx
 * (fn_80098B18) and spark spawns, ramps the glow brightness byte at
 * light+0x2F9, and adds/removes the looping ambient sfx (0x72).  render
 * queues the glow and draws the object; free releases the light.
 *
 * seqId 0x705/0x712 select the Arwing-mounted variant (no looped sfx,
 * different light position and glow scale); seqId 0x717 takes the same
 * zero-Y-offset fx path in update.
 */
#include "main/dll_000A_expgfx.h"
#include "main/dll/LGT/dll_0206_lightsource.h"
#include "main/objhits.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"

#define MODEL_LIGHT_KIND_POINT 2

#define LIGHTSOURCE_OBJFLAG_HITDETECT_DISABLED 0x2000
#define LIGHTSOURCE_OBJFLAG_RENDERED 0x800

/* The glow-light object referenced by LightSourceState.light is a shared
   ModelLightStruct (see main/model_light.h).  Only the glow byte-fields used
   in render/update are declared here, to keep the rest of this DLL's call
   externs (void*-typed) intact for byte-matching. */
typedef struct LightGlow
{
    u8 pad0[0x4C - 0x0];
    u8 enabled;
    u8 pad4D[0x2F8 - 0x4D];
    u8 glowType;
    u8 glowAlpha;
    s8 glowAlphaStep;
    u8 pad2FB[0x300 - 0x2FB];
} LightGlow;

extern void queueGlowRender(void* light);
extern void ModelLightStruct_free(void* light);
extern void* objCreateLight(void* obj, int);
extern void modelLightStruct_setLightKind(void*, int);
extern void modelLightStruct_setPosition(void*, f32, f32, f32);
extern void modelLightStruct_setDiffuseColor(void*, u8, u8, u8, int);
extern void modelLightStruct_setSpecularColor(void*, u8, u8, u8, int);
extern void modelLightStruct_setDistanceAttenuation(u8* obj, f32 a, f32 b);
extern void modelLightStruct_setEnabled(void*, int, f32);
extern void modelLightStruct_startColorFade(void*, int, int);
extern void modelLightStruct_setDiffuseTargetColor(void*, int, int, int, int);
extern void lightSetField4D(void*, int);
extern void modelLightStruct_setupGlow(void*, int, u8, u8, u8, int, f32);
extern void modelLightStruct_setGlowProjectionRadius(void*, f32);
extern u8 gLightSourceColorTable[];

int lightsource_getExtraSize(void) { return 0x1c; }
int lightsource_getObjectTypeId(void) { return 0x1; }

void lightsource_free(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    if (((LightSourceState*)state)->light != 0)
    {
        ModelLightStruct_free(((LightSourceState*)state)->light);
    }
}

void lightsource_render(void* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    extern void objRenderModelAndHitVolumes(void* obj, int p1, int p2, int p3, int p4, f32 alpha);
    void* light = (*(LightSourceState**)&((GameObject*)obj)->extra)->light;
    if (light != NULL && ((LightGlow*)light)->glowType != 0 && ((LightGlow*)light)->enabled != 0)
    {
        queueGlowRender(light);
    }
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p1, p2, p3, p4, 1.0f);
    }
}

void lightsource_hitDetect(void)
{
}

#pragma opt_strength_reduction off

typedef struct LightSourceFlagByte
{
    u8 looped : 1;
} LightSourceFlagByte;

void lightsource_update(int obj)
{




    extern void fn_80098B18(int obj, f32 scale, u8 a, u8 b, int c, f32* vec);
    extern f32 timeDelta;
    LightSourceState* b;
    LightGlow* t;
    s16 sum;
    u8 sfxFlag;
    f32 vec[3];
    struct
    {
        u8 pad[8];
        f32 scale;
        u8 pad2[0xc];
    } fx;

    b = ((GameObject*)obj)->extra;
    switch (b->mode)
    {
    case LIGHTSOURCE_MODE_STATIC:
        break;
    case LIGHTSOURCE_MODE_INTERACTIVE:
        b->litPrev = b->lit;
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0)
        {
            b->lit = (u8)(1 - b->lit);
        }
        if (b->lit != b->litPrev)
        {
            if (b->lit != 0)
            {
                if (b->gameBit != -1 && GameBit_Get(b->gameBit) == 0)
                {
                    GameBit_Set(b->gameBit, 1);
                }
                Sfx_PlayFromObject(obj, SFXTRIG_cvdrip1c);
            }
            else
            {
                (*gExpgfxInterface)->freeSource(obj);
                if (b->gameBit != -1 && GameBit_Get(b->gameBit) != 0)
                {
                    GameBit_Set(b->gameBit, 0);
                }
            }
        }
        break;
    }
    if (b->lit != 0 && (((GameObject*)obj)->objectFlags & LIGHTSOURCE_OBJFLAG_RENDERED))
    {
        b->fxTimer = b->fxTimer - timeDelta;
        if (b->fxTimer <= 0.0f)
        {
            sfxFlag = b->fxArg;
            b->fxTimer += 15.0f;
        }
        else
        {
            sfxFlag = 0;
        }
        if (b->fxType != 0 || b->fxArg != 0)
        {
            vec[0] = 0.0f;
            if (((GameObject*)obj)->anim.seqId == 0x717)
            {
                vec[1] = vec[0];
            }
            else
            {
                vec[1] = 3.5f;
            }
            vec[2] = 0.0f;
            fn_80098B18(obj, 10.0f * ((GameObject*)obj)->anim.rootMotionScale, b->fxType, sfxFlag, 0, vec);
        }
        if (b->sparks != 0)
        {
            b->sparkSpawnTimer = b->sparkSpawnTimer - timeDelta;
            if (b->sparkSpawnTimer <= 0.0f)
            {
                fx.scale = 1.0f;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7cb, &fx, 2, -1, NULL);
                b->sparkSpawnTimer += 5.0f;
            }
        }
    }
    t = b->light;
    if (t != NULL && t->glowType != 0 && t->enabled != 0)
    {
        sum = (s16)(t->glowAlpha + t->glowAlphaStep);
        if (sum < 0)
        {
            sum = 0;
            t->glowAlphaStep = 0;
        }
        else if (sum > 255)
        {
            sum = 255;
            t->glowAlphaStep = 0;
        }
        ((LightGlow*)b->light)->glowAlpha = sum;
    }
    if (((GameObject*)obj)->anim.seqId != 0x705 && ((GameObject*)obj)->anim.seqId != 0x712)
    {
        if (b->lit != 0)
        {
            if (!((LightSourceFlagByte*)&b->loopFlags)->looped)
            {
                Sfx_AddLoopedObjectSound(obj, SFXTRIG_mushdizzylp12);
                ((LightSourceFlagByte*)&b->loopFlags)->looped = 1;
            }
        }
        else
        {
            if (((LightSourceFlagByte*)&b->loopFlags)->looped)
            {
                Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_mushdizzylp12);
                ((LightSourceFlagByte*)&b->loopFlags)->looped = 0;
            }
        }
    }
}

#pragma opt_strength_reduction reset

typedef struct LightColorTable
{
    u8 c[45];
} LightColorTable;

void lightsource_init(GameObject* obj, LightSourceSetup* setup)
{
    LightSourceState* state;
    LightColorTable colors;
    int flags;
    int range;
    int colorBase;

    state = obj->extra;
    colors = *(LightColorTable*)gLightSourceColorTable;
    obj->anim.rotX = (s16)(((int)setup->yaw & 0x3fU) << 10);
    range = setup->range;
    if (range > 0)
    {
        obj->anim.rootMotionScale = range / 8192.0f;
    }
    else
    {
        obj->anim.rootMotionScale = 0.1f;
    }

    state->mode = setup->mode;
    state->gameBit = setup->gameBit;
    state->fxType = 1;
    if (setup->flags & LIGHTSOURCE_FLAG_FX_ARG_ZERO)
    {
        state->fxArg = 0;
    }
    else
    {
        state->fxArg = 3;
    }
    if (setup->options & LIGHTSOURCE_OPTION_SPARKS)
    {
        state->sparks = 1;
    }
    else
    {
        state->sparks = 0;
    }

    switch (state->mode)
    {
    case LIGHTSOURCE_MODE_STATIC:
        state->lit = 1;
        flags = setup->flags;
        if (flags & LIGHTSOURCE_FLAG_FX_TYPE_4)
        {
            state->fxType = 4;
        }
        else if (flags & LIGHTSOURCE_FLAG_FX_TYPE_8)
        {
            state->fxType = 8;
        }
        else if (flags & LIGHTSOURCE_FLAG_FX_TYPE_6)
        {
            state->fxType = 6;
        }
        else if (flags & LIGHTSOURCE_FLAG_FX_ARG_6)
        {
            state->fxArg = 6;
        }
        break;
    }

    if (setup->flags & LIGHTSOURCE_FLAG_CREATE_LIGHT)
    {
        if (state->light == NULL)
        {
            state->light = objCreateLight(obj, 1);
            if (state->light != NULL)
            {
                modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
            }
        }
        if (state->light != NULL)
        {
            if (obj->anim.seqId == 0x705 || obj->anim.seqId == 0x712)
            {
                modelLightStruct_setPosition(state->light, 0.0f, 0.0f, 0.0f);
            }
            else
            {
                modelLightStruct_setPosition(state->light, 0.0f, 7.0f, 0.0f);
            }

            colorBase = state->fxType * 3;
            modelLightStruct_setDiffuseColor(state->light, colors.c[colorBase], colors.c[colorBase + 1],
                                             colors.c[colorBase + 2], 0xff);
            colorBase = state->fxType * 3;
            modelLightStruct_setSpecularColor(state->light, colors.c[colorBase], colors.c[colorBase + 1],
                                              colors.c[colorBase + 2], 0xff);
            modelLightStruct_setDistanceAttenuation(state->light, 40.0f, 65.0f);
            modelLightStruct_setEnabled(state->light, 1, 0.0f);
            modelLightStruct_startColorFade(state->light, 1, 3);

            colorBase = state->fxType * 3;
            modelLightStruct_setDiffuseTargetColor(state->light,
                                                   (int)(0.8f * (f32)(u32)colors.c[colorBase]),
                                                   (int)(0.8f * (f32)(u32)colors.c[colorBase + 1]),
                                                   (int)(0.8f * (f32)(u32)colors.c[colorBase + 2]),
                                                   0xff);
            lightSetField4D(state->light, 1);

            if (setup->flags & LIGHTSOURCE_FLAG_CREATE_GLOW)
            {
                if (obj->anim.seqId == 0x705 || obj->anim.seqId == 0x712)
                {
                    colorBase = state->fxType * 3;
                    modelLightStruct_setupGlow(state->light, 0, colors.c[colorBase], colors.c[colorBase + 1],
                                               colors.c[colorBase + 2],
                                               0x8c, 0.6f * (250.0f * obj->anim.rootMotionScale));
                }
                else
                {
                    colorBase = state->fxType * 3;
                    modelLightStruct_setupGlow(state->light, 0, colors.c[colorBase], colors.c[colorBase + 1],
                                               colors.c[colorBase + 2],
                                               0x8c, 250.0f * obj->anim.rootMotionScale);
                }
                modelLightStruct_setGlowProjectionRadius(state->light, 20.0f);
            }
        }
    }
    else
    {
        state->light = NULL;
    }

    if (setup->flags & LIGHTSOURCE_FLAG_DISABLE_FX_TYPE)
    {
        state->fxType = 0;
    }
    obj->objectFlags |= LIGHTSOURCE_OBJFLAG_HITDETECT_DISABLED;
    state->fxTimer = 15.0f;
    state->sparkTimer = 1.0f;
}

void lightsource_release(void)
{
}

void lightsource_initialise(void)
{
}
