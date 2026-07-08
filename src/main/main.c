#include "main/game_object.h"
#include "main/audio/sfx.h"
#include "main/dll_000A_expgfx.h"
#include "main/gamebits.h"
#include "main/main.h"
#include "main/objtexture.h"
#include "main/objlib.h"
#include "main/resource.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/sfx_ids.h"

#define MAIN_OBJFLAG_HIDDEN             0x4000
#define MAIN_OBJFLAG_HITDETECT_DISABLED 0x2000
#define MAIN_OBJFLAG_RENDERED           0x800

#define MAIN_LAVAPOOL_RESOURCE_ID 0xa6

#define MAIN_LAVAPOOL_PARTFX 0x3a2
#define MAIN_LAVASTAR_PARTFX 0x3a4

extern ModgfxInterface** gModgfxInterface;
extern f32 lbl_803DC074;
extern void* gVfpLavaPoolEffectResource;
extern void objRenderFn_80041018(int* obj);
extern void fn_8003B608(s16 a, s16 b, s16 c);
extern f32 lbl_803E6168;
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern f32 gVfpLavaPoolWaveSin;
extern f32 lbl_803E6158;
extern f32 lbl_803E6160;
extern f32 lbl_803E6164;
extern f32 lbl_803E616C;
extern f32 lbl_803E6170;
extern f32 gVfpLavaPoolPi;
extern f32 lbl_803E6178;
extern f32 lbl_803E617C;
extern f32 lbl_803E6180;
extern f32 lbl_803E6184;
extern f32 lbl_803E6188;
extern f32 lbl_803E618C;
extern f32 lbl_803E6190;
extern f32 lbl_803E6194;
extern f32 lbl_803E6198;
extern f32 lbl_803E61B0;
extern f32 lbl_803E61B4;
extern void* getTrickyObject(void);

void VFP_lavapool_free_nop(void)
{
}

void VFP_lavapool_hitDetect_nop(void)
{
}

void VFP_lavapool_release_nop(void)
{
}

void VFP_lavapool_initialise_nop(void)
{
}

void VFP_lavastar_render(void)
{
}

void VFP_lavastar_hitDetect(void)
{
}

void VFP_SpellPlace_free(void)
{
}

void VFP_SpellPlace_render(void)
{
}

void VFP_SpellPlace_hitDetect(void)
{
}

void VFP_SpellPlace_release(void)
{
}

void VFP_SpellPlace_initialise(void)
{
}

typedef struct
{
    s16 showGameBit;  /* 0x0 */
    s16 checkGameBit; /* 0x2 */
    s8 counter;       /* 0x4 */
    u8 done : 1;      /* 0x5 bit 7 */
    u8 noCheck : 1;   /* 0x5 bit 6 */
    u8 pad06[2];
} VfpFlamePointData;

typedef struct VfpLavaStarState
{
    f32 verticalVelocity;
    f32 delayRangeMin;
    f32 delayRangeMax;
    s16 gameBit;
    s16 effectTimer;
    u8 particleToggle;
    u8 pad11[3];
} VfpLavaStarState;

typedef struct VfpLavaStarMapData
{
    ObjPlacement base;
    u8 pad18[2];
    s16 heightOffset;
    u8 pad1C[2];
    s16 gameBit;
} VfpLavaStarMapData;

typedef struct VfpLavaPoolState
{
    u8 pad00[4];
    s16 timerA;      /* 0x04 (init 7000) */
    s16 timerB;      /* 0x06 (init 2000) */
    f32 amplitude;   /* 0x08 */
    f32 phase;       /* 0x0C */
    f32 speedFactor; /* 0x10 */
    u8 pad14[4];
} VfpLavaPoolState;

STATIC_ASSERT(sizeof(VfpFlamePointData) == 0x08);
STATIC_ASSERT(offsetof(VfpFlamePointData, showGameBit) == 0x00);
STATIC_ASSERT(offsetof(VfpFlamePointData, checkGameBit) == 0x02);
STATIC_ASSERT(offsetof(VfpFlamePointData, counter) == 0x04);
STATIC_ASSERT(sizeof(VfpLavaStarState) == 0x14);
STATIC_ASSERT(offsetof(VfpLavaStarState, verticalVelocity) == 0x00);
STATIC_ASSERT(offsetof(VfpLavaStarState, delayRangeMin) == 0x04);
STATIC_ASSERT(offsetof(VfpLavaStarState, delayRangeMax) == 0x08);
STATIC_ASSERT(offsetof(VfpLavaStarState, gameBit) == 0x0C);
STATIC_ASSERT(offsetof(VfpLavaStarState, effectTimer) == 0x0E);
STATIC_ASSERT(offsetof(VfpLavaStarState, particleToggle) == 0x10);
STATIC_ASSERT(offsetof(VfpLavaStarMapData, heightOffset) == 0x1A);
STATIC_ASSERT(offsetof(VfpLavaStarMapData, gameBit) == 0x1E);
STATIC_ASSERT(sizeof(VfpLavaPoolState) == 0x18);
STATIC_ASSERT(offsetof(VfpLavaPoolState, timerA) == 0x04);
STATIC_ASSERT(offsetof(VfpLavaPoolState, timerB) == 0x06);
STATIC_ASSERT(offsetof(VfpLavaPoolState, amplitude) == 0x08);
STATIC_ASSERT(offsetof(VfpLavaPoolState, phase) == 0x0C);
STATIC_ASSERT(offsetof(VfpLavaPoolState, speedFactor) == 0x10);

int VFP_flamepoint_getExtraSize(void)
{
    return sizeof(VfpFlamePointData);
}
int return1_801FDA08(void)
{
    return 0x1;
}
int VFP_lavapool_getExtraSize_ret_24(void)
{
    return 0x18;
}
int VFP_lavapool_getObjectTypeId(void)
{
    return 0x0;
}
int VFP_lavastar_getExtraSize(void)
{
    return sizeof(VfpLavaStarState);
}
int VFP_lavastar_getObjectTypeId(void)
{
    return 0x0;
}
int VFP_SpellPlace_getExtraSize(void)
{
    return sizeof(LaserState);
}
int VFP_SpellPlace_getObjectTypeId(void)
{
    return 0x0;
}

void VFP_lavapool_update(int obj)
{
    fn_801FD6B4(obj);
}

#pragma scheduling off
void VFP_lavastar_release(void)
{
    Resource_Release(gVfpLavaPoolEffectResource);
    gVfpLavaPoolEffectResource = NULL;
}

#pragma peephole off
int fn_801FD4A8(void* obj, int x)
{
    VfpFlamePointData* extra = ((GameObject*)obj)->extra;
    if (extra != NULL)
    {
        extra->counter -= x;
        return extra->counter <= 0;
    }
    return 0;
}
#pragma peephole on

void VFP_lavastar_initialise(void)
{
    gVfpLavaPoolEffectResource = NULL;
    gVfpLavaPoolEffectResource = Resource_Acquire(MAIN_LAVAPOOL_RESOURCE_ID, 1);
}

void VFP_lavastar_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
    (*gModgfxInterface)->freeSourceEffects((void*)obj);
}

#pragma peephole off
void VFP_lavapool_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    if (visible != 0)
    {
        fn_8003B608(0xff, 0xe6, 0xd7);
        ((void (*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p1, p2, p3, p4, lbl_803E6168);
    }
}

void VFP_flamepoint_init(int* obj, s8* def)
{
    VfpFlamePointData* d = (VfpFlamePointData*)((GameObject*)obj)->extra;
    d->counter = (s8) * (s16*)(def + 0x1a);
    d->noCheck = (u8) * (s16*)(def + 0x1c);
    d->showGameBit = *(s16*)(def + 0x1e);
    d->checkGameBit = *(s16*)(def + 0x20);
    ((GameObject*)obj)->objectFlags |= (MAIN_OBJFLAG_HIDDEN | MAIN_OBJFLAG_HITDETECT_DISABLED);
}

void VFP_flamepoint_update(int obj)
{
    VfpFlamePointData* d;
    void* tricky;

    d = ((GameObject*)obj)->extra;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    if (!d->done && (d->checkGameBit == -1 || mainGetBit(d->checkGameBit) != 0))
    {
        if (d->counter <= 0 && !d->done)
        {
            if (d->showGameBit != -1)
            {
                mainSetBits(d->showGameBit, 1);
                d->done = 1;
            }
        }
        else
        {
            tricky = getTrickyObject();
            if (tricky != NULL)
            {
                f32 dist = lbl_803E6158;
                if (d->noCheck || (void*)ObjGroup_FindNearestObject(5, obj, &dist) == NULL)
                {
                    if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE)
                    {
                        (*(void (*)(void*, int, int, int)) *
                         (int*)(*(int*)*(int*)((u8*)tricky + 0x68) + 0x28))(tricky, obj, 1, 4);
                    }
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
                    objRenderFn_80041018((void*)obj);
                }
            }
        }
    }
    else
    {
        u8 v = mainGetBit(d->showGameBit);
        if (!(d->done = v))
        {
            d->counter = (s8) * (s16*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x1a);
        }
    }
}

void fn_801FD6B4(int obj)
{
    VfpLavaPoolState* state;
    int def;
    f32 speed;
    f32 phase;
    ObjTextureRuntimeSlot* tex;
    f32 scrollT;
    f32 wave;
    struct
    {
        u8 pad[8];
        f32 value;
        f32 unused[2];
    } parm;

    state = ((GameObject*)obj)->extra;
    def = *(int*)&((GameObject*)obj)->anim.placementData;
    speed = (f32)(u32)((GameObject*)obj)->anim.alpha;
    state->phase += timeDelta * ((lbl_803E6160 * state->speedFactor) / lbl_803E6160);
    if (state->phase > lbl_803E6164)
    {
        state->speedFactor = (f32)(int)randomGetRange(0x32, 100);
        state->amplitude = lbl_803E6168 / ((f32)(int)*(s16*)(def + 0x1a) / (f32)(int)randomGetRange(0x15e, 800));
        state->phase = lbl_803E616C;
        Sfx_PlayFromObject((u32)obj, SFXsp_lfoot_treasure);
        speed = lbl_803E6170;
    }
    gVfpLavaPoolWaveSin = wave = mathSinf((gVfpLavaPoolPi * (f32)(s16)(int)state->phase) / lbl_803E6178);
    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E617C * state->amplitude + lbl_803E6180 * state->amplitude * wave;
    phase = state->phase;
    if (phase > lbl_803E6184 && phase < lbl_803E6188)
    {
        parm.value = state->amplitude;
        if (((GameObject*)obj)->objectFlags & MAIN_OBJFLAG_RENDERED)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, MAIN_LAVAPOOL_PARTFX, &parm, 2, -1, NULL);
        }
    }
    phase = state->phase;
    if (phase > lbl_803E618C)
    {
        speed = (f32)(s16)(int)(lbl_803E6170 * gVfpLavaPoolWaveSin);
    }
    if (phase < lbl_803E6190)
    {
        speed = lbl_803E6170 * (phase / lbl_803E6190);
    }
    ((GameObject*)obj)->anim.alpha =
        ((speed < lbl_803E616C) ? lbl_803E616C : ((speed > lbl_803E6170) ? lbl_803E6170 : speed));
    tex = objFindTexture((void*)obj, 0, 0);
    if (tex != NULL)
    {
        scrollT = (f32)(int)tex->offsetT + lbl_803E6160;
        if (scrollT >= lbl_803E6194)
        {
            scrollT -= lbl_803E6194;
        }
        tex->offsetT = (s16)scrollT;
    }
    tex = objFindTexture((void*)obj, 1, 0);
    if (tex != NULL)
    {
        scrollT = (f32)(int)tex->offsetT + lbl_803E6198;
        if (scrollT >= lbl_803E6194)
        {
            scrollT -= lbl_803E6194;
        }
        tex->offsetT = (s16)scrollT;
    }
}

void VFP_lavapool_init(int obj, int def)
{
    VfpLavaPoolState* state;

    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = return1_801FDA08;
    state->timerA = 7000;
    state->timerB = 2000;
    if (*(s16*)(def + 0x1a) == 0)
    {
        *(s16*)(def + 0x1a) = 500;
    }
    ((GameObject*)obj)->anim.rootMotionScale =
        lbl_803E6168 / ((f32)(int)*(s16*)(def + 0x1a) / (f32)(int)randomGetRange(600, 1000));
    state->amplitude = ((GameObject*)obj)->anim.rootMotionScale;
    state->speedFactor = (f32)(int)randomGetRange(0x32, 100);
}

void VFP_lavastar_update(int obj)
{
    VfpLavaStarMapData* mapData;
    VfpLavaStarState* state;

    mapData = (VfpLavaStarMapData*)*(int*)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.localPosY += timeDelta * state->verticalVelocity;
    if (((GameObject*)obj)->anim.localPosY > lbl_803E61B0 + mapData->base.posY)
    {
        state->verticalVelocity = lbl_803E61B4 * (f32)(int)randomGetRange(5, 0x14);
        ((GameObject*)obj)->anim.localPosY = mapData->base.posY;
    }
    state->effectTimer += (s16)timeDelta;
    if (gVfpLavaPoolEffectResource != 0 && state->effectTimer >= 0x28)
    {
        (*(void (*)(int, int, int, int, int, int)) * (int*)(*(int*)gVfpLavaPoolEffectResource + 4))(obj, 0, 0, 4, -1,
                                                                                                    0);
        state->effectTimer = 0;
    }
    if (state->particleToggle == 0)
    {
        (*gPartfxInterface)->spawnObject((void*)obj, MAIN_LAVASTAR_PARTFX, NULL, 2, -1, NULL);
    }
    state->particleToggle ^= 1;
}

void VFP_lavastar_init(int obj, int def)
{
    VfpLavaStarState* state;
    VfpLavaStarMapData* mapData;

    mapData = (VfpLavaStarMapData*)def;
    state = ((GameObject*)obj)->extra;
    state->gameBit = mapData->gameBit;
    state->verticalVelocity = lbl_803E61B4 * (f32)(int)randomGetRange(10, 0x19);
    state->effectTimer = 0x14;
    ((GameObject*)obj)->anim.localPosY = mapData->base.posY + (f32)(int)mapData->heightOffset;
    ((GameObject*)obj)->objectFlags |= MAIN_OBJFLAG_HITDETECT_DISABLED;
    state->delayRangeMin = (f32)(int)randomGetRange(0x1e, 0x3c);
    state->delayRangeMax = (f32)(int)randomGetRange(100, 200);
}

void VFP_SpellPlace_update(int obj)
{
    LaserObject* spellPlace;
    LaserState* state;
    u8 mode;

    spellPlace = (LaserObject*)obj;
    if (spellPlace->state->completionLatched == 0 && mainGetBit((int)spellPlace->state->activationGameBit) != 0)
    {
        spellPlace->statusFlags &= ~LASER_OBJECT_STATUS_DISABLED;
    }
    else
    {
        spellPlace->statusFlags |= LASER_OBJECT_STATUS_DISABLED;
    }
    objRenderFn_80041018((void*)obj);
    if (spellPlace->statusFlags & LASER_OBJECT_STATUS_ACTIVE)
    {
        mode = (*gMapEventInterface)->getMapAct((int)spellPlace->mapEventSlot);
        switch (mode)
        {
        case LASEROBJ_MODE_SEQUENCE_A:
            state = spellPlace->state;
            if ((*gGameUIInterface)->isEventReady(LASEROBJ_MAIN_SEQUENCE_A_EVENT) != 0)
            {
                mainSetBits(state->completionGameBit, 1);
                mainSetBits(state->activationGameBit, 0);
                state->completionLatched = 1;
                spellPlace->statusFlags |= LASER_OBJECT_STATUS_DISABLED;
            }
            break;
        case LASEROBJ_MODE_SEQUENCE_B:
            state = spellPlace->state;
            if ((*gGameUIInterface)->isEventReady(LASEROBJ_MAIN_SEQUENCE_B_EVENT) != 0)
            {
                mainSetBits(state->completionGameBit, 1);
                mainSetBits(state->activationGameBit, 0);
                state->completionLatched = 1;
                spellPlace->statusFlags |= LASER_OBJECT_STATUS_DISABLED;
            }
            break;
        }
    }
}

void VFP_SpellPlace_init(int obj, s8* def)
{
    LaserObject* spellPlace;
    LaserObjectMapData* mapData;
    LaserState* state;

    spellPlace = (LaserObject*)obj;
    mapData = (LaserObjectMapData*)def;
    state = spellPlace->state;
    state->completionGameBit = mapData->completionGameBit;
    state->activationGameBit = mapData->activationGameBit;
    state->completionLatched = 0;
    spellPlace->modeWord = (s16)(mapData->mapEventSlot << LASEROBJ_MODE_WORD_SHIFT);
    if (mainGetBit(state->completionGameBit) != 0)
    {
        state->completionLatched = 1;
        spellPlace->statusFlags |= LASER_OBJECT_STATUS_DISABLED;
    }
    spellPlace->objectFlags |= LASER_OBJECT_FLAGS_SEQUENCE_CONTROL;
}
