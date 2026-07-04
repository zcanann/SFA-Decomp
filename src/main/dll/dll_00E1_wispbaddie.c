/* DLL 0xE1 - wisp baddie / swarmbaddie / hagabon objects [8014F620-8014F9E8) */
#include "main/dll/rom_curve_interface.h"
#include "main/dll/swarmbaddiestate_struct.h"
#include "main/dll/hagabonstate_struct.h"
#include "main/dll/baddie_state.h"
#include "main/dll/baddie_setmove.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/dll_00E1_wispbaddie.h"
#include "main/objhits.h"
#include "main/objlib.h"
#include "main/mm.h"
#include "string.h"
#include "main/dll/objfsa.h"
#include "main/audio/sfx_trigger_ids.h"
#define WISPBADDIE_OBJFLAG_HITDETECT_DISABLED 0x2000
#define WISPBADDIE_OBJFLAG_PARENT_SLACK 0x1000
extern int ObjHits_GetPriorityHitWithPosition();

void hagabon_release(void);

void hagabon_initialise(void);

void swarmbaddie_hitDetect(void);

void swarmbaddie_release(void);

void swarmbaddie_initialise(void);

extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);
extern f32 lbl_803E26D0;
extern f32 lbl_803E26D4;
extern f32 lbl_803E26D8;
extern f32 gWispBaddiePi;
extern f32 lbl_803E26E0;
extern f32 lbl_803E26E4;
extern const f32 lbl_803E26E8;
extern f32 lbl_803E26EC;
extern f32 lbl_803E26F0;
extern f32 lbl_803E26F4;
extern f32 lbl_803E26F8;
extern f32 lbl_803E26FC;
extern int lbl_803DBC80;
extern int gWispBaddieLastSegmentEnd;
extern f32 timeDelta;
extern void* Obj_GetPlayerObject(void);

extern void objMove(int obj, f32 x, f32 y, f32 z);
extern f32 sqrtf(f32 x);
extern float mathSinf(float x);
STATIC_ASSERT(sizeof(HagabonState) == 0x28);
STATIC_ASSERT(offsetof(HagabonState, wavePhaseA) == 0x20);
STATIC_ASSERT(offsetof(HagabonState, flags) == 0x26);

typedef struct WispEventRow {
    f32 blend;    /* +0x0 */
    u32 flags;    /* +0x4 (low byte = move flags) */
    u8 moveId;    /* +0x8 */
    u8 pad9[3];
} WispEventRow;
STATIC_ASSERT(sizeof(WispEventRow) == 0xc);
STATIC_ASSERT(offsetof(WispEventRow, moveId) == 0x8);

extern int randomGetRange(int lo, int hi);
extern void Sfx_PlayAtPositionFromObject(int obj, f32 x, f32 y, f32 z, int sfxId);
extern void doRumble(f32 duration);
extern void CameraShake_ApplyRadial(f32 x, f32 y, f32 z, f32 radius, f32 magnitude);
extern void fn_801513AC(int obj, int state);
extern f32 lbl_803E2708;
extern f32 lbl_803E270C;
extern f32 lbl_803E2710;
extern f32 lbl_803E2714;
extern f32 lbl_803E2718;
extern f32 lbl_803E271C;
extern f32 lbl_803E2720;
extern const f32 lbl_803E2740;
extern f32 lbl_803E2744;
extern f32 lbl_803E2748;
extern f32 lbl_803E274C;
extern f32 lbl_803E2750;
extern f32 lbl_803E2754;
extern f32 lbl_803E2760;
extern f32 lbl_803E2764;
extern void* PTR_DAT_8031fdc4;
extern void fn_8014CF7C(int a, int b, f32 e, f32 f, int c, int d);
extern f32 lbl_803E2728;
extern f32 lbl_803E272C;
extern f32 lbl_803E2730;
extern f32 lbl_803E2734;
extern f32 lbl_803E2738;
extern f32 lbl_803E273C;
extern char lbl_8031F16C[];
extern u8 lbl_8031DD30[];

/*
 * HagabonAnimState - file-local overlay naming the PER-FAMILY anim-control
 * scratch that baddie_state.h leaves raw for the hagabon/swarmbaddie fighter
 * driven by FUN_8014ffa8 / fn_8014FFB4. moveEventFlags(0x2F8) is the u16
 * per-frame move-progress event bitmask read by fn_8015039C to fire SFX.
 */
typedef struct HagabonAnimState {
    u8 pad00[0x2F8];
    u16 moveEventFlags; /* 0x2F8 move-progress event bits (0x200/0x40/0x1000/1/0x80) */
} HagabonAnimState;

void wispbaddie_hitDetect(void)
{
}

void hagabon_hitDetect(int obj);

void swarmbaddie_free(int obj);

void wispbaddie_free(int obj)
{
    void** state = ((GameObject*)obj)->extra;
    ObjGroup_RemoveObject(obj, 3);
    if (*state != NULL)
    {
        mm_free(*state);
        *state = NULL;
    }
}

void hagabon_free(int obj);

void swarmbaddie_init(int obj, int data, int skip_alloc);

void hagabon_init(int obj, int data, int skip_alloc);

void hagabon_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

int hagabon_getExtraSize(void);
int hagabon_getObjectTypeId(void);
int swarmbaddie_getExtraSize(void);
int swarmbaddie_getObjectTypeId(void);
int wispbaddie_getExtraSize(void) { return 0x2c; }
int wispbaddie_getObjectTypeId(void) { return 0x9; }

void swarmbaddie_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void wispbaddie_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

void fn_8014EE8C(int obj, SwarmBaddieState* state);

void fn_8014F620(int obj, WispBaddieState* state)
{
    RomCurveWalker* curve;
    int done;
    f32 step;
    f32 wave;

    curve = state->curve;
    state->pathWavePhase += (s16)(lbl_803E26D0 * timeDelta);
    state->hoverWavePhase += (s16)(lbl_803E26D4 * timeDelta);

    wave = lbl_803E26D8 + mathSinf((gWispBaddiePi * (f32)state->pathWavePhase) / lbl_803E26E0);
    done = Curve_AdvanceAlongPath(curve, state->hitRadius * wave);
    if (((done != 0) || (curve->atSegmentEnd != gWispBaddieLastSegmentEnd)) &&
        ((*gRomCurveInterface)->goNextPoint((void*)curve) != 0) &&
        ((*gRomCurveInterface)->initCurve((void*)state->curve, (void*)obj, lbl_803E26E4,
                                          &lbl_803DBC80, -1) != 0))
    {
        state->flags = state->flags & ~1;
    }
    gWispBaddieLastSegmentEnd = curve->atSegmentEnd;

    if ((state->flags & 2) != 0)
    {
        ((GameObject*)obj)->anim.velocityX =
            lbl_803E26E8 * (state->playerObj->anim.localPosX - ((GameObject*)obj)->anim.localPosX) +
            ((GameObject*)obj)->anim.velocityX;

        wave = mathSinf((gWispBaddiePi * (f32)state->hoverWavePhase) / lbl_803E26E0);
        wave = (lbl_803E26F0 * wave + (lbl_803E26EC + state->playerObj->anim.localPosY)) -
                ((GameObject*)obj)->anim.localPosY;
        ((GameObject*)obj)->anim.velocityY =
            lbl_803E26E8 * wave +
            ((GameObject*)obj)->anim.velocityY;
        ((GameObject*)obj)->anim.velocityZ =
            lbl_803E26E8 * (state->playerObj->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ) +
            ((GameObject*)obj)->anim.velocityZ;
    }
    else
    {
        ((GameObject*)obj)->anim.velocityX = lbl_803E26E8 * (((RomCurveWalker*)curve)->posX - ((GameObject*)obj)->anim.localPosX)
            +
            ((GameObject*)obj)->anim.velocityX;

        wave = mathSinf((gWispBaddiePi * (f32)state->hoverWavePhase) / lbl_803E26E0);
        wave = (lbl_803E26F0 * wave + ((RomCurveWalker*)curve)->posY) - ((GameObject*)obj)->anim.localPosY;
        ((GameObject*)obj)->anim.velocityY =
            lbl_803E26E8 * wave +
            ((GameObject*)obj)->anim.velocityY;
        ((GameObject*)obj)->anim.velocityZ = lbl_803E26E8 * (((RomCurveWalker*)curve)->posZ - ((GameObject*)obj)->anim.localPosZ)
            +
            ((GameObject*)obj)->anim.velocityZ;
    }

    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (step = lbl_803E26F4);
    ((GameObject*)obj)->anim.velocityY *= step;
    ((GameObject*)obj)->anim.velocityZ *= step;

    if (((GameObject*)obj)->anim.velocityX > *(f32*)&lbl_803E26F8)
    {
        ((GameObject*)obj)->anim.velocityX = lbl_803E26F8;
    }
    if (((GameObject*)obj)->anim.velocityY > *(f32*)&lbl_803E26F8)
    {
        ((GameObject*)obj)->anim.velocityY = lbl_803E26F8;
    }
    if (((GameObject*)obj)->anim.velocityZ > *(f32*)&lbl_803E26F8)
    {
        ((GameObject*)obj)->anim.velocityZ = lbl_803E26F8;
    }
    if (((GameObject*)obj)->anim.velocityX < *(f32*)&lbl_803E26FC)
    {
        ((GameObject*)obj)->anim.velocityX = lbl_803E26FC;
    }
    if (((GameObject*)obj)->anim.velocityY < *(f32*)&lbl_803E26FC)
    {
        ((GameObject*)obj)->anim.velocityY = lbl_803E26FC;
    }
    if (((GameObject*)obj)->anim.velocityZ < *(f32*)&lbl_803E26FC)
    {
        ((GameObject*)obj)->anim.velocityZ = lbl_803E26FC;
    }

    objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
            ((GameObject*)obj)->anim.velocityZ * timeDelta);
}

void swarmbaddie_update(int obj);

void hagabon_update(int obj);

ObjectDescriptor gHagabonObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)hagabon_initialise,
    (ObjectDescriptorCallback)hagabon_release,
    0,
    (ObjectDescriptorCallback)hagabon_init,
    (ObjectDescriptorCallback)hagabon_update,
    (ObjectDescriptorCallback)hagabon_hitDetect,
    (ObjectDescriptorCallback)hagabon_render,
    (ObjectDescriptorCallback)hagabon_free,
    (ObjectDescriptorCallback)hagabon_getObjectTypeId,
    hagabon_getExtraSize,
};

ObjectDescriptor gSwarmBaddieObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)swarmbaddie_initialise,
    (ObjectDescriptorCallback)swarmbaddie_release,
    0,
    (ObjectDescriptorCallback)swarmbaddie_init,
    (ObjectDescriptorCallback)swarmbaddie_update,
    (ObjectDescriptorCallback)swarmbaddie_hitDetect,
    (ObjectDescriptorCallback)swarmbaddie_render,
    (ObjectDescriptorCallback)swarmbaddie_free,
    (ObjectDescriptorCallback)swarmbaddie_getObjectTypeId,
    swarmbaddie_getExtraSize,
};

/* segment pragma-stack balance (re-split): */

void wispbaddie_update(int obj)
{
    WispBaddieState* state;
    RomCurveWalker* curve;
    int hit;
    f32 dx;
    f32 hitZ;
    f32 dy;
    f32 dz;
    f32 hitX;
    f32 hitY;
    f32 d[3];
    int particleParam;
    u8 f;
    void* dAlias = (void*)d;

    state = ((GameObject*)obj)->extra;
    curve = state->curve;
    hit = ObjHits_GetPriorityHitWithPosition(obj, &dx, &hitX, &hitY, &hitZ, &dy, &dz);
    if (hit != 0)
    {
        state->hitRadius = lbl_803E2708;
        f = state->flags;
        if ((f & 2) != 0)
        {
            state->flags = (u8)(f & ~2);
            state->flags = (u8)(state->flags | 4);
        }
        Sfx_PlayAtPositionFromObject(obj, hitZ, dy, dz, SFXTRIG_robolaser16);
    }

    particleParam = 4;
    (*gPartfxInterface)->spawnObject((void*)obj, state->particleId, NULL, 1, -1,
                                     &particleParam);
    particleParam = 3;
    (*gPartfxInterface)->spawnObject((void*)obj, state->particleId, NULL, 2, -1,
                                     &particleParam);

    if (state->hitRadius < state->maxHitRadius)
    {
        state->hitRadius += lbl_803E270C;
        ObjHits_DisableObject(obj);
    }
    else
    {
        state->hitRadius = state->maxHitRadius;
        particleParam = 2;
        (*gPartfxInterface)->spawnObject((void*)obj, state->particleId, NULL, 2, -1,
                                         &particleParam);
        particleParam = 0;
        (*gPartfxInterface)->spawnObject((void*)obj, state->particleId, NULL, 2, -1,
                                         &particleParam);
        ObjHits_SetHitVolumeSlot(obj, 10, 1, 0);
        ObjHits_EnableObject(obj);
    }

    particleParam = 1;
    (*gPartfxInterface)->spawnObject((void*)obj, state->particleId, NULL, 2, -1,
                                     &particleParam);
    state->playerObj = Obj_GetPlayerObject();
    if (state->playerObj != NULL)
    {
        d[0] = state->playerObj->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
        d[1] = state->playerObj->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
        d[2] = state->playerObj->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
        state->playerDistance = sqrtf(d[2] * d[2] + (d[0] * d[0] + d[1] * d[1]));
    }
    if (curve != 0)
    {
        d[0] = ((RomCurveWalker*)curve)->posX - ((GameObject*)obj)->anim.worldPosX;
        d[1] = ((RomCurveWalker*)curve)->posY - ((GameObject*)obj)->anim.worldPosY;
        d[2] = ((RomCurveWalker*)curve)->posZ - ((GameObject*)obj)->anim.worldPosZ;
        state->curveDistance = sqrtf(d[2] * d[2] + (d[0] * d[0] + d[1] * d[1]));
    }

    f = state->flags;
    if ((f & 2) != 0)
    {
        if (state->curveDistance > lbl_803E2710)
        {
            state->flags = (u8)(f & ~2);
            state->flags = (u8)(state->flags | 4);
        }
        state->cryTimer -= timeDelta;
        if (state->cryTimer < lbl_803E2714)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_fball2_c);
            state->cryTimer = (f32)(int)randomGetRange(0x3c, 0x78);
        }
        state->particleId = 0x338;
    }
    f = state->flags;
    if ((f & 4) != 0)
    {
        if (state->curveDistance < lbl_803E2718)
        {
            state->flags = (u8)(f & ~4);
        }
        state->particleId = 0x337;
    }
    if ((state->flags & 6) == 0)
    {
        if ((state->hitRadius >= state->maxHitRadius) && (state->playerObj != 0) &&
            (state->playerDistance < state->triggerDistance))
        {
            state->flags = (u8)(state->flags | 2);
        }
        state->particleId = 0x337;
    }
    fn_8014F620(obj, state);
}

void wispbaddie_init(int obj, int setup, int initialised)
{
    WispBaddieState* state;
    f32 value;

    state = ((GameObject*)obj)->extra;
    value = (f32) * (s16*)(setup + 0x1a) / lbl_803E271C;
    state->maxHitRadius = value;
    state->hitRadius = value;
    state->triggerDistance = lbl_803E2720 * (f32) * (s8*)(setup + 0x19);
    state->particleId = 0x337;

    if (initialised == 0)
    {
        state->curve = (RomCurveWalker*)mmAlloc(0x108, 0x1a, 0);
        if ((void*)state->curve != NULL)
        {
            memset((void*)state->curve, 0, 0x108);
        }
        if ((*gRomCurveInterface)->initCurve((void*)state->curve, (void*)obj, state->triggerDistance,
                                             &lbl_803DBC80, -1) == 0)
        {
            state->flags = (u8)(state->flags | 1);
        }
        Sfx_PlayFromObject(obj, 0x23b);
    }
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | WISPBADDIE_OBJFLAG_HITDETECT_DISABLED);
}

#pragma scheduling on
#pragma peephole on
#pragma scheduling off
#pragma peephole off
void wispbaddie_release(void)
{
}

void wispbaddie_initialise(void)
{
}

ObjectDescriptor gWispBaddieObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)wispbaddie_initialise,
    (ObjectDescriptorCallback)wispbaddie_release,
    0,
    (ObjectDescriptorCallback)wispbaddie_init,
    (ObjectDescriptorCallback)wispbaddie_update,
    (ObjectDescriptorCallback)wispbaddie_hitDetect,
    (ObjectDescriptorCallback)wispbaddie_render,
    (ObjectDescriptorCallback)wispbaddie_free,
    (ObjectDescriptorCallback)wispbaddie_getObjectTypeId,
    wispbaddie_getExtraSize,
};

void fn_8014FF20(void)
{
}

void fn_8014FEF8(int p1, int* p2, int p3, int code)
{
    if (code == 0x10)
    {
        ((BaddieState*)p2)->reactionFlags |= 0x20;
    }
    else
    {
        ((BaddieState*)p2)->reactionFlags |= 0x8;
    }
}

void fn_8014FF24(int a, int b)
{
    f32* p = (f32*)((BaddieState*)b)->trackedObj;
    fn_8014CF7C(a, b, p[3], p[5], 0xf, 0);
}

void fn_8014FF58(int unused, char* p)
{
    f32 v1c;
    ((BaddieState*)p)->speedScale = lbl_803E2728;
    ((BaddieState*)p)->unk2E4 = 1;
    ((BaddieState*)p)->unk2E4 |= 0x80;
    ((BaddieState*)p)->unk308 = lbl_803E272C;
    ((BaddieState*)p)->animDeltaScale = lbl_803E2730;
    ((BaddieState*)p)->unk304 = lbl_803E2734;
    ((BaddieState*)p)->unk320 = 0;
    v1c = lbl_803E2738;
    *(f32*)&((BaddieState*)p)->eventFlags = v1c;
    ((BaddieState*)p)->unk321 = 0;
    ((BaddieState*)p)->unk318 = lbl_803E273C;
    ((BaddieState*)p)->unk322 = 0;
    ((BaddieState*)p)->unk31C = v1c;
}

u32 fn_8014FFB4(int obj, int state, u32 allowNewEvent)
{
    u8* base = lbl_8031DD30;
    WispEventRow* eventRows;
    u8 eventIndex;
    int ei;
    int flag20;
    u8 sequenceIndex;
    u32 stateFlags;
    u8 eventFlags;
    f32 blendScale;
    f32 blendTimer;
    int eventTableIndex;
    WispEventRow* row;
    u32 sf2;

    sequenceIndex = ((BaddieState*)state)->inWhirlpoolGroup;
    eventRows = *(WispEventRow**)(base + sequenceIndex * 0x28 + 0x1444);
    stateFlags = ((BaddieState*)state)->controlFlags;
    if ((stateFlags & 0x4000) != 0)
    {
        return 0;
    }
    if (*(f32*)(state + 0x328) != *(f32*)&lbl_803E2740 && *(u16*)(state + 0x338) != 0)
    {
        return 0;
    }
    eventFlags = *(u8*)(state + 0x2f1);
    ei = eventFlags & 0x1f;
    eventIndex = ei;
    if ((ei & 0x10) != 0)
    {
        eventIndex = ei & ~0x8;
    }
    if (eventIndex > 0x18)
    {
        eventIndex = 0;
    }
    flag20 = eventFlags & 0x20;
    if (flag20 != 0)
    {
        blendScale = lbl_803E2744;
        eventIndex = 0;
    }
    else
    {
        blendScale = lbl_803E2748;
    }
    if ((u8)allowNewEvent != 0)
    {
        if ((eventFlags != 0 || *(f32*)(state + 0x324) != lbl_803E2740) &&
            (stateFlags & 0x40) == 0 && flag20 == 0)
        {
            if (*(f32*)(state + 0x324) != lbl_803E2740)
            {
                *(f32*)(state + 0x324) = *(f32*)(state + 0x324) - timeDelta;
                if (*(f32*)(state + 0x324) <= lbl_803E2740)
                {
                    *(f32*)(state + 0x324) = lbl_803E2740;
                }
                else
                {
                    return 0;
                }
            }
            else
            {
                eventTableIndex = sequenceIndex * 2;
                *(f32*)(state + 0x324) = *(f32*)(state + 0x334) +
                    (f32)(int)
                randomGetRange(base[eventTableIndex + 0x152c],
                               base[eventTableIndex + 0x152d]);
                *(f32*)(state + 0x334) = lbl_803E2740;
                return 0;
            }
        }
    }
    if ((((u8)allowNewEvent != 0 && *(u8*)(state + 0x2f1) != 0 &&
                eventRows[eventIndex].moveId != 0) ||
            (*(u8*)(state + 0x2f1) & 0x20) != 0) &&
        !(*(u8*)(state + 0x33c) == eventIndex && lbl_803E2740 != *(f32*)(state + 0x32c)))
    {
        sf2 = ((BaddieState*)state)->controlFlags;
        if ((sf2 & 0x800080) != 0 || (*(u8*)(state + 0x2f1) & 0x20) != 0)
        {
            blendTimer = lbl_803E274C *
                (blendScale * (row = &eventRows[eventIndex])->blend);
            *(f32*)(state + 0x330) = blendTimer;
            *(f32*)(state + 0x32c) = blendTimer;
            ((BaddieState*)state)->controlFlags = ((BaddieState*)state)->controlFlags | 0x40;
            *(u8*)(state + 0x2f2) = *(u8*)(state + 0x2f2) | 0x80;
            *(u8*)(state + 0x2f3) = 0;
            *(u8*)(state + 0x2f4) = 0;
            Baddie_SetMove(obj, state, row->moveId, blendScale * row->blend, 0, row->flags & 0xff);
            ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)(
                (ObjAnimComponent*)obj, *(f32*)(base + row->moveId * 4));
            *(u8*)(state + 0x33c) = eventIndex;
            return 1;
        }
        if ((sf2 & 0x40000000) != 0)
        {
            fn_801513AC(obj, state);
        }
        return 0;
    }
    if (*(f32*)(state + 0x32c) != lbl_803E2740)
    {
        int pos = *(int*)&((BaddieState*)state)->trackedObj;
        fn_8014CF7C(obj, state, *(f32*)(pos + 0xc), *(f32*)(pos + 0x14), 0xf, 0);
        if (((BaddieState*)state)->unk308 > lbl_803E2750)
        {
            ((BaddieState*)state)->unk308 = ((BaddieState*)state)->unk308 - lbl_803E2754;
        }
        if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
        {
            eventTableIndex = *(u8*)(state + 0x33c);
            Baddie_SetMove(obj, state, eventRows[eventTableIndex].moveId,
                        eventRows[*(u8*)(state + 0x33c)].blend, 0,
                        eventRows[eventTableIndex].flags & 0xff);
            ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)(
                (ObjAnimComponent*)obj,
                *(f32*)(base + eventRows[*(u8*)(state + 0x33c)].moveId * 4));
        }
        *(f32*)(state + 0x32c) = *(f32*)(state + 0x32c) - timeDelta;
        if (*(f32*)(state + 0x32c) <= *(f32*)&lbl_803E2740)
        {
            *(f32*)(state + 0x32c) = lbl_803E2740;
            ((BaddieState*)state)->controlFlags =
                ((BaddieState*)state)->controlFlags & ~0x40;
            ((BaddieState*)state)->controlFlags =
                ((BaddieState*)state)->controlFlags | 0x40000000LL;
            *(u8*)(state + 0x2f2) = *(u8*)(state + 0x2f2) & ~0x80;
            *(u8*)(state + 0x33c) = 0;
            return 0;
        }
        else
        {
            return 1;
        }
    }
    return 0;
}

void fn_8015039C(int obj, int animState)
{
    extern f32 Vec_distance(f32* a, f32* b); /* #57 */
    GameObject* player;
    f32 distance;
    f32 rumbleFalloff;

    if ((((HagabonAnimState*)animState)->moveEventFlags & 0x200) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_sml_trex_snap3);
        player = Obj_GetPlayerObject();
        if ((player->objectFlags & WISPBADDIE_OBJFLAG_PARENT_SLACK) == 0)
        {
            distance = Vec_distance(&((GameObject*)obj)->anim.worldPosX, &player->anim.worldPosX);
            if (distance <= lbl_803E2760)
            {
                rumbleFalloff = lbl_803E2748 - distance / lbl_803E2760;
                rumbleFalloff = lbl_803E2744 * rumbleFalloff;
                doRumble(rumbleFalloff);
            }
            CameraShake_ApplyRadial(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                    ((GameObject*)obj)->anim.localPosZ, lbl_803E2760,
                                    lbl_803E2764);
        }
    }
    if ((((HagabonAnimState*)animState)->moveEventFlags & 0x40) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_spotfox01);
    }
    if ((((HagabonAnimState*)animState)->moveEventFlags & 0x1000) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_scream1);
    }
    if ((((HagabonAnimState*)animState)->moveEventFlags & 1) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_pullup2);
    }
    if ((((HagabonAnimState*)animState)->moveEventFlags & 0x80) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_death01);
    }
}

#pragma optimization_level 2
void fn_801504BC(int obj, int delta)
{
    u8* inner = ((GameObject*)obj)->extra;
    u8* tbl = (u8*)lbl_8031F16C;
    u8* ptr = *(u8**)(tbl + inner[0x33b] * 0x28 + 4);
    inner[0x33d] = (u8)(delta + (u32)ptr[8] + 1);
    inner[0x33e] = 1;
}
#pragma optimization_level reset
