/* DLL 0xE1 - wisp baddie / swarmbaddie / hagabon objects [8014F620-8014F9E8) */
#include "main/dll/partfx_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/pad_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_position_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/vecmath.h"
#include "main/dll/swarmbaddiestate_struct.h"
#include "main/dll/hagabonstate_struct.h"
#include "main/dll/baddie_state.h"
#include "main/dll/baddie_setmove.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/dll/dll_00E1_wispbaddie.h"
#include "main/objhits.h"
#include "main/obj_group.h"
#include "main/mm.h"
#include "string.h"
#include "main/dll/objfsa.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx_ids.h"
#include "main/frame_timing.h"
#include "main/camera_shake_api.h"
#include "main/dll/seqobj11d_ext.h"

int lbl_803DBC80[2] = {2, 3};
#define WISPBADDIE_HIT_VOLUME_SLOT 10

/* object group this object belongs to */
#define WISPBADDIE_OBJGROUP                   3
#define WISPBADDIE_OBJFLAG_HITDETECT_DISABLED 0x2000
#define WISPBADDIE_OBJFLAG_PARENT_SLACK       0x1000

/*
 * WispBaddieState.flags (u8 at +0x24). Same path/chase pair as the sibling
 * swarmbaddie: the wisp follows its ROM curve until the player comes within
 * range, then CHASE_PLAYER steers velocity toward the player; straying too
 * far from the path sets CHASE_LOCKOUT to block re-chase until it returns.
 */
#define WISPBADDIE_FLAG_PATH_NEEDS_LINK 0x01
#define WISPBADDIE_FLAG_CHASE_PLAYER    0x02
#define WISPBADDIE_FLAG_CHASE_LOCKOUT   0x04 /* strayed too far; block re-chase until back near path */
#define WISPBADDIE_FLAG_CHASE_MASK      0x06
int gWispBaddieLastSegmentEnd;

STATIC_ASSERT(sizeof(HagabonState) == 0x28);
STATIC_ASSERT(offsetof(HagabonState, wavePhaseA) == 0x20);
STATIC_ASSERT(offsetof(HagabonState, flags) == 0x26);

typedef struct WispEventRow
{
    f32 blend; /* +0x0 */
    u32 flags; /* +0x4 (low byte = move flags) */
    u8 moveId; /* +0x8 */
    u8 pad9[3];
} WispEventRow;
STATIC_ASSERT(sizeof(WispEventRow) == 0xc);
STATIC_ASSERT(offsetof(WispEventRow, moveId) == 0x8);

/*
 * HagabonAnimState - file-local overlay naming the PER-FAMILY anim-control
 * scratch that baddie_state.h leaves raw for the hagabon/swarmbaddie fighter
 * driven by FUN_8014ffa8 / fn_8014FFB4. moveEventFlags(0x2F8) is the u16
 * per-frame move-progress event bitmask read by fn_8015039C to fire SFX.
 */
typedef struct HagabonAnimState
{
    u8 pad00[0x2F8];
    u16 moveEventFlags; /* 0x2F8 move-progress event bits (0x200/0x40/0x1000/1/0x80) */
} HagabonAnimState;

void fn_8014F620(GameObject* obj, WispBaddieState* state)
{
    RomCurveWalker* curve;
    int done;
    f32 step;
    f32 wave;

    curve = state->curve;
    state->pathWavePhase += (s16)(512.0f * timeDelta);
    state->hoverWavePhase += (s16)(2048.0f * timeDelta);

    wave = 1.0f + mathSinf((3.1415927f * (f32)state->pathWavePhase) / 32768.0f);
    done = Curve_AdvanceAlongPath(&curve->curve, state->hitRadius * wave);
    if (((done != 0) || (curve->atSegmentEnd != gWispBaddieLastSegmentEnd)) &&
        ((*gRomCurveInterface)->goNextPoint((void*)curve) != 0) &&
        ((*gRomCurveInterface)->initCurve((void*)state->curve, (void*)obj, 400.0f, lbl_803DBC80, -1) != 0))
    {
        state->flags = state->flags & ~WISPBADDIE_FLAG_PATH_NEEDS_LINK;
    }
    gWispBaddieLastSegmentEnd = curve->atSegmentEnd;

    if ((state->flags & WISPBADDIE_FLAG_CHASE_PLAYER) != 0)
    {
        (obj)->anim.velocityX =
            0.006f * (state->playerObj->anim.localPosX - (obj)->anim.localPosX) + (obj)->anim.velocityX;

        wave = mathSinf((3.1415927f * (f32)state->hoverWavePhase) / 32768.0f);
        wave = ((30.0f + state->playerObj->anim.localPosY) + 40.0f * wave) - (obj)->anim.localPosY;
        (obj)->anim.velocityY = 0.006f * wave + (obj)->anim.velocityY;
        (obj)->anim.velocityZ =
            0.006f * (state->playerObj->anim.localPosZ - (obj)->anim.localPosZ) + (obj)->anim.velocityZ;
    }
    else
    {
        (obj)->anim.velocityX =
            0.006f * (((RomCurveWalker*)curve)->posX - (obj)->anim.localPosX) + (obj)->anim.velocityX;

        wave = mathSinf((3.1415927f * (f32)state->hoverWavePhase) / 32768.0f);
        wave = (40.0f * wave + ((RomCurveWalker*)curve)->posY) - (obj)->anim.localPosY;
        (obj)->anim.velocityY = 0.006f * wave + (obj)->anim.velocityY;
        (obj)->anim.velocityZ =
            0.006f * (((RomCurveWalker*)curve)->posZ - (obj)->anim.localPosZ) + (obj)->anim.velocityZ;
    }

    (obj)->anim.velocityX = (obj)->anim.velocityX * (step = 0.9f);
    (obj)->anim.velocityY *= step;
    (obj)->anim.velocityZ *= step;

    if ((obj)->anim.velocityX > 2.1f)
    {
        (obj)->anim.velocityX = 2.1f;
    }
    if ((obj)->anim.velocityY > 2.1f)
    {
        (obj)->anim.velocityY = 2.1f;
    }
    if ((obj)->anim.velocityZ > 2.1f)
    {
        (obj)->anim.velocityZ = 2.1f;
    }
    if ((obj)->anim.velocityX < -2.1f)
    {
        (obj)->anim.velocityX = -2.1f;
    }
    if ((obj)->anim.velocityY < -2.1f)
    {
        (obj)->anim.velocityY = -2.1f;
    }
    if ((obj)->anim.velocityZ < -2.1f)
    {
        (obj)->anim.velocityZ = -2.1f;
    }

    objMove((GameObject*)obj, (obj)->anim.velocityX * timeDelta, (obj)->anim.velocityY * timeDelta,
            (obj)->anim.velocityZ * timeDelta);
}

int wispbaddie_getExtraSize(void)
{
    return 0x2c;
}
int wispbaddie_getObjectTypeId(void)
{
    return 0x9;
}

void wispbaddie_free(GameObject* obj)
{
    void** state = (obj)->extra;
    ObjGroup_RemoveObject((int)obj, WISPBADDIE_OBJGROUP);
    if (*state != NULL)
    {
        mm_free(*state);
        *state = NULL;
    }
}

void wispbaddie_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible == 0)
        return;
}

void wispbaddie_hitDetect(void)
{
}

void wispbaddie_update(GameObject* obj)
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
    u8 flags;
    void* dAlias = (void*)d;

    state = (obj)->extra;
    curve = state->curve;
    hit = ObjHits_GetPriorityHitWithPosition(obj, (int*)&dx, (int*)&hitX, (u32*)&hitY, &hitZ, &dy, &dz);
    if (hit != 0)
    {
        state->hitRadius = 0.01f;
        flags = state->flags;
        if ((flags & WISPBADDIE_FLAG_CHASE_PLAYER) != 0)
        {
            state->flags = (u8)(flags & ~WISPBADDIE_FLAG_CHASE_PLAYER);
            state->flags = (u8)(state->flags | WISPBADDIE_FLAG_CHASE_LOCKOUT);
        }
        Sfx_PlayAtPositionFromObject((int)obj, hitZ, dy, dz, SFXTRIG_robolaser16);
    }

    particleParam = 4;
    (*gPartfxInterface)->spawnObject((void*)obj, state->particleId, NULL, 1, -1, &particleParam);
    particleParam = 3;
    (*gPartfxInterface)->spawnObject((void*)obj, state->particleId, NULL, 2, -1, &particleParam);

    if (state->hitRadius < state->maxHitRadius)
    {
        state->hitRadius += 0.005f;
        ObjHits_DisableObject(obj);
    }
    else
    {
        state->hitRadius = state->maxHitRadius;
        particleParam = 2;
        (*gPartfxInterface)->spawnObject((void*)obj, state->particleId, NULL, 2, -1, &particleParam);
        particleParam = 0;
        (*gPartfxInterface)->spawnObject((void*)obj, state->particleId, NULL, 2, -1, &particleParam);
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, WISPBADDIE_HIT_VOLUME_SLOT, 1, 0);
        ObjHits_EnableObject(obj);
    }

    particleParam = 1;
    (*gPartfxInterface)->spawnObject((void*)obj, state->particleId, NULL, 2, -1, &particleParam);
    state->playerObj = Obj_GetPlayerObject();
    if (state->playerObj != NULL)
    {
        d[0] = state->playerObj->anim.worldPosX - (obj)->anim.worldPosX;
        d[1] = state->playerObj->anim.worldPosY - (obj)->anim.worldPosY;
        d[2] = state->playerObj->anim.worldPosZ - (obj)->anim.worldPosZ;
        state->playerDistance = sqrtf(d[2] * d[2] + (d[0] * d[0] + d[1] * d[1]));
    }
    if (curve != 0)
    {
        d[0] = ((RomCurveWalker*)curve)->posX - (obj)->anim.worldPosX;
        d[1] = ((RomCurveWalker*)curve)->posY - (obj)->anim.worldPosY;
        d[2] = ((RomCurveWalker*)curve)->posZ - (obj)->anim.worldPosZ;
        state->curveDistance = sqrtf(d[2] * d[2] + (d[0] * d[0] + d[1] * d[1]));
    }

    flags = state->flags;
    if ((flags & WISPBADDIE_FLAG_CHASE_PLAYER) != 0)
    {
        if (state->curveDistance > 250.0f)
        {
            state->flags = (u8)(flags & ~WISPBADDIE_FLAG_CHASE_PLAYER);
            state->flags = (u8)(state->flags | WISPBADDIE_FLAG_CHASE_LOCKOUT);
        }
        state->cryTimer -= timeDelta;
        if (state->cryTimer < 0.0f)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_fball2_c);
            state->cryTimer = (f32)(int)randomGetRange(0x3c, 0x78);
        }
        state->particleId = 0x338;
    }
    flags = state->flags;
    if ((flags & WISPBADDIE_FLAG_CHASE_LOCKOUT) != 0)
    {
        if (state->curveDistance < 60.0f)
        {
            state->flags = (u8)(flags & ~WISPBADDIE_FLAG_CHASE_LOCKOUT);
        }
        state->particleId = 0x337;
    }
    if ((state->flags & WISPBADDIE_FLAG_CHASE_MASK) == 0)
    {
        if ((state->hitRadius >= state->maxHitRadius) && (state->playerObj != 0) &&
            (state->playerDistance < state->triggerDistance))
        {
            state->flags = (u8)(state->flags | WISPBADDIE_FLAG_CHASE_PLAYER);
        }
        state->particleId = 0x337;
    }
    fn_8014F620((GameObject*)obj, state);
}

void wispbaddie_init(GameObject* obj, int setup, int initialised)
{
    WispBaddieState* state;
    f32 value;

    state = (obj)->extra;
    value = (f32) * (s16*)(setup + 0x1a) / 25.0f;
    state->maxHitRadius = value;
    state->hitRadius = value;
    state->triggerDistance = 4.0f * (f32) * (s8*)(setup + 0x19);
    state->particleId = 0x337;

    if (initialised == 0)
    {
        state->curve = (RomCurveWalker*)mmAlloc(0x108, 0x1a, 0);
        if ((void*)state->curve != NULL)
        {
            memset((void*)state->curve, 0, 0x108);
        }
        if ((*gRomCurveInterface)
                ->initCurve((void*)state->curve, (void*)obj, state->triggerDistance, lbl_803DBC80, -1) == 0)
        {
            state->flags = (u8)(state->flags | WISPBADDIE_FLAG_PATH_NEEDS_LINK);
        }
        Sfx_PlayFromObject((int)obj, SFXTRIG_id_23b);
    }
    (obj)->objectFlags = (u16)((obj)->objectFlags | WISPBADDIE_OBJFLAG_HITDETECT_DISABLED);
}

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

void battleDroidUpdateWhileFrozen(int obj, int* state, int arg, int code, int wpad0, int wpad1, void* wpad2, int wpad3)
{
    if (code == 0x10)
    {
        ((BaddieState*)state)->reactionFlags |= 0x20;
    }
    else
    {
        ((BaddieState*)state)->reactionFlags |= 0x8;
    }
}

void battleDroidUpdate(int obj, int state)
{
}

void battleDroidUpdateAttack(int obj, int state)
{
    f32* pos = (f32*)((BaddieState*)state)->trackedObj;
    baddieTurnTowardPoint((GameObject*)obj, state, pos[3], pos[5], 0xf, 0);
}

void battleDroidInit(int unused, char* p)
{
    f32 v1c;
    ((BaddieState*)p)->speedScale = 60.0f;
    ((BaddieState*)p)->unk2E4 = 1;
    ((BaddieState*)p)->unk2E4 |= 0x80;
    ((BaddieState*)p)->unk308 = 0.005f;
    ((BaddieState*)p)->animDeltaScale = 0.17f;
    ((BaddieState*)p)->unk304 = 0.97f;
    ((BaddieState*)p)->unk320 = 0;
    v1c = 3.0f;
    *(f32*)&((BaddieState*)p)->eventFlags = v1c;
    ((BaddieState*)p)->unk321 = 0;
    ((BaddieState*)p)->unk318 = 1.25f;
    ((BaddieState*)p)->unk322 = 0;
    ((BaddieState*)p)->unk31C = v1c;
}

/* .data pointer table + baddie-variant data blobs (referenced via extern here and by seqobj units) */
u8 lbl_8031DD30[288] = {
    0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,  0,  0,  0,   0,  0, 0, 0,  0,   0,   0,  0, 0, 0, 0, 0,  0,
    0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,  0,  0,  0,   0,  0, 0, 0,  0,   0,   0,  0, 0, 0, 0, 0,  0,
    0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,  0,  0,  0,   0,  0, 0, 0,  0,   0,   0,  0, 0, 0, 0, 0,  0,
    0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,  0,  0,  0,   0,  0, 0, 0,  0,   0,   0,  0, 0, 0, 0, 0,  0,
    0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,  0,  0,  0,   0,  0, 0, 0,  0,   0,   0,  0, 0, 0, 0, 0,  0,
    0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,  0,  0,  0,   0,  0, 0, 61, 163, 215, 10, 0, 0, 0, 0, 61, 163,
    215, 10,  61, 204, 204, 205, 61, 204, 204, 205, 0,  0,  0,  0,   0,  0, 0, 0,  0,   0,   0,  0, 0, 0, 0, 0,  61,
    163, 215, 10, 61,  163, 215, 10, 61,  35,  215, 10, 61, 35, 215, 10, 0, 0, 0,  0,   0,   0,  0, 0, 0, 0, 0,  0,
    0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,  0,  0,  0,   0,  0, 0, 0,  0,   0,   0,  0, 0, 0, 0, 0,  0,
    0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,  0,  0,  0,   0,  0, 0, 0,  0,   0,   0,  0, 0, 0, 0, 0,  0,
    0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,  0,  0,  0,   0,  0, 0, 0};
u8 lbl_8031DE50[48] = {60, 35, 215, 10, 0, 0, 0, 0, 0,  0, 0, 0, 60, 35, 215, 10, 0, 0, 0, 0, 11, 0, 0, 0,
                       60, 35, 215, 10, 0, 0, 0, 0, 15, 0, 0, 0, 60, 35, 215, 10, 0, 0, 0, 0, 12, 0, 0, 0};
u8 lbl_8031DE80[324] = {
    0,  0,  0,  0,  0, 0, 0,  0,  13, 0,  0, 0, 64, 64,  0,  0,  0, 0, 0,  0,  0,  0,  0, 0, 64, 64,  0,  0,  0, 0,
    0,  0,  0,  0,  0, 0, 64, 64, 0,  0,  0, 0, 0,  0,   0,  0,  0, 0, 64, 64, 0,  0,  0, 0, 0,  0,   0,  0,  0, 0,
    64, 64, 0,  0,  0, 0, 0,  0,  0,  0,  0, 0, 64, 64,  0,  0,  0, 0, 0,  0,  0,  0,  0, 0, 64, 64,  0,  0,  0, 0,
    0,  0,  0,  0,  0, 0, 64, 64, 0,  0,  0, 0, 0,  0,   0,  0,  0, 0, 64, 64, 0,  0,  0, 0, 0,  0,   3,  0,  0, 0,
    64, 64, 0,  0,  0, 0, 0,  0,  3,  0,  0, 0, 64, 64,  0,  0,  0, 0, 0,  0,  6,  0,  0, 0, 64, 64,  0,  0,  0, 0,
    0,  0,  4,  0,  0, 0, 64, 64, 0,  0,  0, 0, 0,  0,   5,  0,  0, 0, 64, 64, 0,  0,  0, 0, 0,  0,   22, 25, 0, 0,
    64, 64, 0,  0,  0, 0, 0,  0,  6,  25, 0, 0, 63, 192, 0,  0,  0, 0, 0,  0,  24, 25, 0, 0, 63, 192, 0,  0,  0, 0,
    0,  0,  45, 25, 0, 0, 64, 64, 0,  0,  0, 0, 0,  0,   27, 26, 0, 0, 64, 64, 0,  0,  0, 0, 0,  0,   3,  25, 0, 0,
    64, 64, 0,  0,  0, 0, 0,  0,  7,  25, 0, 0, 64, 160, 0,  0,  0, 0, 0,  0,  26, 25, 0, 0, 64, 64,  0,  0,  0, 0,
    0,  0,  8,  25, 0, 0, 64, 0,  0,  0,  0, 0, 0,  0,   23, 25, 0, 0, 64, 64, 0,  0,  0, 0, 0,  0,   3,  25, 0, 0,
    64, 0,  0,  0,  0, 0, 0,  1,  11, 0,  0, 0, 64, 128, 0,  0,  0, 0, 0,  0,  30, 25, 0, 0};
u8 lbl_8031DFC4[300] = {
    63, 128, 0,  0, 0, 0, 0,  11,  64, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  60, 0, 0, 0, 63, 128, 0,  0, 0, 0,
    0,  11,  61, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  61, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  62, 0, 0, 0,
    63, 128, 0,  0, 0, 0, 0,  11,  62, 0, 0, 0, 0,  0,   0,  0, 0, 0, 0,  0,   0,  0, 0, 0, 0,  0,   0,  0, 0, 0,
    0,  0,   0,  0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  64, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  63, 0, 0, 0,
    63, 128, 0,  0, 0, 0, 0,  11,  61, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  61, 0, 0, 0, 63, 128, 0,  0, 0, 0,
    0,  11,  62, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  62, 0, 0, 0, 0,  0,   0,  0, 0, 0, 0,  0,   0,  0, 0, 0,
    0,  0,   0,  0, 0, 0, 0,  0,   0,  0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  64, 0, 0, 0, 63, 128, 0,  0, 0, 0,
    0,  11,  60, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  61, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  61, 0, 0, 0,
    63, 128, 0,  0, 0, 0, 0,  11,  62, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  62, 0, 0, 0, 0,  0,   0,  0, 0, 0,
    0,  11,  0,  0, 0, 0, 0,  0,   0,  0, 0, 0, 0,  0,   0,  0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  64, 0, 0, 0};
u8 lbl_8031E0F0[300] = {62, 148, 122, 225, 0, 0, 0, 11, 69, 2, 2, 0, 62, 148, 122, 225, 0, 0, 0, 11, 65, 2, 2, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 66, 2, 2, 0, 62, 148, 122, 225, 0, 0, 0, 11, 66, 2, 2, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 67, 2, 2, 0, 62, 148, 122, 225, 0, 0, 0, 11, 67, 2, 2, 0,
                        0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 69, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 68, 2, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 66, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 66, 2, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 67, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 67, 2, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 69, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 65, 2, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 66, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 66, 2, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 67, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 67, 2, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 69, 2, 0, 0};
u8 lbl_8031E21C[36] = {0, 0,  0,  0, 0, 0, 0, 11, 24, 1, 0, 0, 0, 0,  0,  0, 0, 0,
                       0, 12, 25, 1, 0, 0, 0, 0,  0,  0, 0, 0, 0, 10, 16, 1, 0, 0};
u8 lbl_8031E240[96] = {63, 128, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 63, 128, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0,
                       63, 0,   0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 0,  0,   0, 0, 0, 0, 0, 0, 0,  0, 0, 0,
                       0,  0,   0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 63, 0,   0, 0, 0, 0, 0, 0, 21, 0, 0, 0,
                       63, 128, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0, 63, 128, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0};
u8 lbl_8031E2A0[300] = {63, 0,   0,   0,   0, 0, 0, 0,  40, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 38, 0, 0, 0,
                        63, 76,  204, 205, 0, 0, 0, 1,  53, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 47, 0, 0, 0,
                        63, 76,  204, 205, 0, 0, 0, 1,  54, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 48, 0, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0, 0,  0, 0, 0,
                        63, 192, 0,   0,   0, 0, 0, 0,  57, 7, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 38, 9, 0, 0,
                        64, 0,   0,   0,   0, 0, 0, 1,  32, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 49, 9, 0, 0,
                        63, 0,   0,   0,   0, 0, 0, 0,  57, 7, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 50, 9, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0, 0,  0, 0, 0,
                        63, 76,  204, 205, 0, 0, 0, 0,  39, 3, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 57, 7, 0, 0,
                        63, 153, 153, 154, 0, 0, 0, 0,  42, 1, 0, 0, 63, 153, 153, 154, 0, 0, 0, 0, 42, 1, 0, 0,
                        63, 153, 153, 154, 0, 0, 0, 0,  41, 2, 0, 0, 63, 153, 153, 154, 0, 0, 0, 0, 41, 2, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0, 0,  0, 0, 0,
                        63, 192, 0,   0,   0, 0, 0, 11, 28, 3, 0, 0};
u8 lbl_8031E3CC[208] = {
    0,  0,   0,  0,  0, 0, 0, 0,  0,  0, 0, 0,  0, 0, 0, 0,  63, 192, 0,  0,  0, 0, 0, 11, 56, 1, 5, 10, 0, 0, 0, 64,
    63, 192, 0,  0,  0, 0, 0, 11, 55, 2, 6, 11, 0, 0, 0, 64, 63, 192, 0,  0,  0, 0, 0, 11, 29, 0, 0, 0,  0, 0, 0, 0,
    63, 192, 0,  0,  0, 0, 0, 3,  46, 0, 0, 0,  0, 0, 0, 0,  63, 192, 0,  0,  0, 0, 0, 11, 51, 0, 0, 0,  0, 0, 0, 0,
    63, 192, 0,  0,  0, 0, 0, 11, 52, 0, 0, 0,  0, 0, 0, 0,  63, 192, 0,  0,  0, 0, 0, 11, 59, 7, 8, 12, 0, 0, 0, 64,
    63, 64,  0,  0,  0, 0, 0, 11, 58, 0, 0, 0,  0, 0, 0, 0,  63, 128, 0,  0,  0, 0, 0, 11, 36, 0, 0, 0,  0, 0, 0, 0,
    63, 51,  51, 51, 0, 0, 0, 11, 70, 0, 0, 0,  0, 0, 0, 0,  63, 51,  51, 51, 0, 0, 0, 11, 70, 0, 0, 0,  0, 0, 0, 0,
    63, 51,  51, 51, 0, 0, 0, 11, 71, 0, 0, 0,  0, 0, 0, 0};
u8 lbl_8031E49C[432] = {
    0,  0,   0,   0,   0, 0, 0, 0, 21, 0, 0, 0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 36, 0, 0,  0,   0, 0, 0, 0,
    63, 128, 0,   0,   0, 0, 0, 0, 24, 0, 5, 230, 1, 0, 0, 0, 63, 166, 102, 102, 0, 0, 0, 0, 25, 0, 9,  230, 1, 0, 0, 0,
    63, 128, 0,   0,   0, 0, 0, 0, 36, 0, 0, 0,   0, 0, 0, 0, 63, 166, 102, 102, 0, 0, 0, 0, 25, 0, 9,  230, 1, 0, 0, 0,
    64, 0,   0,   0,   0, 0, 0, 0, 7,  0, 0, 0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 36, 0, 0,  0,   0, 0, 0, 0,
    63, 128, 0,   0,   0, 0, 0, 0, 24, 0, 5, 230, 1, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 24, 0, 5,  230, 1, 0, 0, 0,
    63, 38,  102, 102, 0, 4, 0, 0, 17, 0, 0, 0,   0, 0, 0, 0, 63, 38,  102, 102, 0, 2, 0, 0, 18, 0, 0,  0,   0, 0, 0, 0,
    63, 38,  102, 102, 0, 2, 0, 0, 18, 0, 0, 0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 2,  0, 0,  0,   0, 0, 0, 0,
    63, 166, 102, 102, 0, 0, 0, 0, 25, 0, 9, 230, 1, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 24, 0, 5,  230, 1, 0, 0, 0,
    63, 38,  102, 102, 0, 8, 0, 0, 19, 0, 0, 0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 1, 0, 0, 16, 0, 33, 230, 2, 0, 0, 0,
    63, 38,  102, 102, 0, 8, 0, 0, 19, 0, 0, 0,   0, 0, 0, 0, 63, 166, 102, 102, 0, 0, 0, 0, 25, 0, 9,  230, 1, 0, 0, 0,
    63, 128, 0,   0,   0, 0, 0, 0, 24, 0, 5, 230, 1, 0, 0, 0, 63, 38,  102, 102, 0, 2, 0, 0, 18, 0, 0,  0,   0, 0, 0, 0,
    63, 38,  102, 102, 0, 4, 0, 0, 17, 0, 0, 0,   0, 0, 0, 0, 63, 140, 204, 205, 0, 1, 0, 0, 16, 0, 33, 230, 2, 0, 0, 0,
    63, 12,  204, 205, 0, 1, 0, 0, 12, 0, 0, 0,   0, 0, 0, 0, 63, 38,  102, 102, 0, 8, 0, 0, 19, 0, 0,  0,   0, 0, 0, 0,
    63, 38,  102, 102, 0, 2, 0, 0, 18, 0, 0, 0,   0, 0, 0, 0};
u8 lbl_8031E64C[24] = {0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0};
u8 lbl_8031E664[432] = {0,  0,   0,   0,   0, 0, 0, 0, 21, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0,
                        36, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1, 0, 0, 0,
                        63, 166, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1, 0, 0, 0, 63, 128, 0,   0,   0, 1, 0, 0,
                        16, 0,   33,  230, 2, 0, 0, 0, 63, 166, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1, 0, 0, 0,
                        63, 128, 0,   0,   0, 1, 0, 0, 16, 0,   33,  230, 2, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0,
                        36, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1, 0, 0, 0,
                        63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1, 0, 0, 0, 63, 38,  102, 102, 0, 4, 0, 0,
                        17, 0,   0,   0,   0, 0, 0, 0, 63, 166, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1, 0, 0, 0,
                        63, 38,  102, 102, 0, 2, 0, 0, 18, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0,
                        2,  0,   0,   0,   0, 0, 0, 0, 63, 166, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1, 0, 0, 0,
                        63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1, 0, 0, 0, 63, 38,  102, 102, 0, 8, 0, 0,
                        19, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 1, 0, 0, 16, 0,   33,  230, 2, 0, 0, 0,
                        63, 38,  102, 102, 0, 8, 0, 0, 19, 0,   0,   0,   0, 0, 0, 0, 63, 166, 102, 102, 0, 0, 0, 0,
                        25, 0,   9,   230, 1, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1, 0, 0, 0,
                        63, 38,  102, 102, 0, 2, 0, 0, 18, 0,   0,   0,   0, 0, 0, 0, 63, 38,  102, 102, 0, 4, 0, 0,
                        17, 0,   0,   0,   0, 0, 0, 0, 63, 140, 204, 205, 0, 1, 0, 0, 16, 0,   33,  230, 2, 0, 0, 0,
                        63, 12,  204, 205, 0, 1, 0, 0, 12, 0,   0,   0,   0, 0, 0, 0, 63, 38,  102, 102, 0, 8, 0, 0,
                        19, 0,   0,   0,   0, 0, 0, 0, 63, 38,  102, 102, 0, 2, 0, 0, 18, 0,   0,   0,   0, 0, 0, 0};
u8 lbl_8031E814[24] = {0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0};
u8 lbl_8031E82C[36] = {0, 0,  0,  0, 0, 0, 0, 11, 24, 2, 0, 0, 0, 0,  0,  0, 0, 0,
                       0, 10, 25, 2, 0, 0, 0, 0,  0,  0, 0, 0, 0, 24, 16, 4, 0, 0};
u8 lbl_8031E850[432] = {0,  0,   0,   0,   0, 0, 0, 0, 21, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0,
                        36, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1, 0, 0, 0,
                        63, 102, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1, 0, 0, 0, 63, 128, 0,   0,   0, 1, 0, 0,
                        16, 0,   33,  230, 2, 0, 0, 0, 63, 102, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1, 0, 0, 0,
                        63, 128, 0,   0,   0, 1, 0, 0, 16, 0,   33,  230, 2, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0,
                        36, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1, 0, 0, 0,
                        63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1, 0, 0, 0, 63, 38,  102, 102, 0, 4, 0, 0,
                        17, 0,   0,   0,   0, 0, 0, 0, 63, 102, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1, 0, 0, 0,
                        63, 38,  102, 102, 0, 2, 0, 0, 18, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0,
                        2,  0,   0,   0,   0, 0, 0, 0, 63, 102, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1, 0, 0, 0,
                        63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1, 0, 0, 0, 63, 38,  102, 102, 0, 8, 0, 0,
                        19, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 1, 0, 0, 16, 0,   33,  230, 2, 0, 0, 0,
                        63, 38,  102, 102, 0, 8, 0, 0, 19, 0,   0,   0,   0, 0, 0, 0, 63, 102, 102, 102, 0, 0, 0, 0,
                        25, 0,   9,   230, 1, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1, 0, 0, 0,
                        63, 38,  102, 102, 0, 2, 0, 0, 18, 0,   0,   0,   0, 0, 0, 0, 63, 38,  102, 102, 0, 4, 0, 0,
                        17, 0,   0,   0,   0, 0, 0, 0, 63, 140, 204, 205, 0, 1, 0, 0, 16, 0,   33,  230, 2, 0, 0, 0,
                        63, 12,  204, 205, 0, 1, 0, 0, 12, 0,   0,   0,   0, 0, 0, 0, 63, 38,  102, 102, 0, 8, 0, 0,
                        19, 0,   0,   0,   0, 0, 0, 0, 63, 38,  102, 102, 0, 2, 0, 0, 18, 0,   0,   0,   0, 0, 0, 0};
u8 lbl_8031EA00[24] = {1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0};
u8 lbl_8031EA18[468] = {0,  0,   0,   0,   0, 0, 0, 0,  21, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0,  0, 0, 0,
                        36, 0,   0,   0,   0, 0, 0, 0,  63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1,  0, 0, 0,
                        63, 166, 102, 102, 0, 0, 0, 0,  25, 0,   9,   230, 1, 0, 0, 0, 63, 128, 0,   0,   0,  1, 0, 0,
                        16, 0,   33,  230, 2, 0, 0, 0,  63, 166, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1,  0, 0, 0,
                        63, 128, 0,   0,   0, 1, 0, 0,  16, 0,   33,  230, 2, 0, 0, 0, 63, 38,  102, 102, 0,  8, 0, 0,
                        19, 0,   0,   0,   0, 0, 0, 0,  63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1,  0, 0, 0,
                        63, 128, 0,   0,   0, 0, 0, 0,  24, 0,   5,   230, 1, 0, 0, 0, 63, 38,  102, 102, 0,  4, 0, 0,
                        17, 0,   0,   0,   0, 0, 0, 0,  63, 166, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1,  0, 0, 0,
                        63, 38,  102, 102, 0, 2, 0, 0,  18, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0,  0, 0, 0,
                        2,  0,   0,   0,   0, 0, 0, 0,  63, 166, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1,  0, 0, 0,
                        63, 128, 0,   0,   0, 1, 0, 0,  16, 0,   33,  230, 2, 0, 0, 0, 63, 128, 0,   0,   0,  0, 0, 0,
                        24, 0,   5,   230, 1, 0, 0, 0,  63, 128, 0,   0,   0, 1, 0, 0, 16, 0,   33,  230, 2,  0, 0, 0,
                        63, 38,  102, 102, 0, 8, 0, 0,  19, 0,   0,   0,   0, 0, 0, 0, 63, 166, 102, 102, 0,  0, 0, 0,
                        25, 0,   9,   230, 1, 0, 0, 0,  63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1,  0, 0, 0,
                        63, 38,  102, 102, 0, 2, 0, 0,  18, 0,   0,   0,   0, 0, 0, 0, 63, 38,  102, 102, 0,  4, 0, 0,
                        17, 0,   0,   0,   0, 0, 0, 0,  63, 140, 204, 205, 0, 1, 0, 0, 16, 0,   33,  230, 2,  0, 0, 0,
                        63, 12,  204, 205, 0, 1, 0, 0,  12, 0,   0,   0,   0, 0, 0, 0, 63, 38,  102, 102, 0,  8, 0, 0,
                        19, 0,   0,   0,   0, 0, 0, 0,  63, 38,  102, 102, 0, 2, 0, 0, 18, 0,   0,   0,   0,  0, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 11, 24, 1,   0,   0,   0, 0, 0, 0, 0,  0,   0,   12,  25, 1, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 10, 16, 2,   0,   0};
u8 lbl_8031EBEC[24] = {0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0};
u8 lbl_8031EC04[48] = {60, 35, 215, 10, 0, 0, 0, 0, 0, 0, 0, 0, 60, 35, 215, 10, 0, 0, 0, 0, 1, 0, 0, 0,
                       60, 35, 215, 10, 0, 0, 0, 0, 2, 0, 0, 0, 60, 35, 215, 10, 0, 0, 0, 0, 1, 0, 0, 0};
u8 lbl_8031EC34[24] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 64, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
u8 lbl_8031EC4C[300] = {
    63, 128, 0,  0, 0, 0, 0,  11,  20, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  16, 0, 0, 0, 63, 128, 0,  0, 0, 0,
    0,  11,  18, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  18, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  19, 0, 0, 0,
    63, 128, 0,  0, 0, 0, 0,  11,  19, 0, 0, 0, 0,  0,   0,  0, 0, 0, 0,  0,   0,  0, 0, 0, 0,  0,   0,  0, 0, 0,
    0,  0,   0,  0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  20, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  17, 0, 0, 0,
    63, 128, 0,  0, 0, 0, 0,  11,  18, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  18, 0, 0, 0, 63, 128, 0,  0, 0, 0,
    0,  11,  19, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  19, 0, 0, 0, 0,  0,   0,  0, 0, 0, 0,  0,   0,  0, 0, 0,
    0,  0,   0,  0, 0, 0, 0,  0,   0,  0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  20, 0, 0, 0, 63, 128, 0,  0, 0, 0,
    0,  11,  16, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  18, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  18, 0, 0, 0,
    63, 128, 0,  0, 0, 0, 0,  11,  19, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  19, 0, 0, 0, 0,  0,   0,  0, 0, 0,
    0,  11,  0,  0, 0, 0, 0,  0,   0,  0, 0, 0, 0,  0,   0,  0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  20, 0, 0, 0};
u8 lbl_8031ED78[300] = {62, 148, 122, 225, 0, 0, 0, 11, 20, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 16, 2, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 18, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 18, 2, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 19, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 19, 2, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 20, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 17, 2, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 18, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 18, 2, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 19, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 19, 2, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 20, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 16, 2, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 18, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 18, 2, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 19, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 19, 2, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 20, 2, 0, 0};
u8 lbl_8031EEA4[36] = {0, 0,  0, 0, 0, 0, 0, 11, 0, 1, 0, 0, 0, 0,  0, 0, 0, 0,
                       0, 12, 0, 1, 0, 0, 0, 0,  0, 0, 0, 0, 0, 10, 0, 1, 0, 0};
u8 lbl_8031EEC8[96] = {63, 128, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 63, 128, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0,
                       63, 0,   0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0,  0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0,  0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 63, 0,   0, 0, 0, 0, 0, 0, 7, 0, 0, 0,
                       63, 128, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 63, 128, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0};
u8 lbl_8031EF28[300] = {63, 0,   0,   0,   0, 0, 0, 0, 15, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 12, 0, 0, 0,
                        63, 76,  204, 205, 0, 0, 0, 0, 14, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 14, 0, 0, 0,
                        63, 76,  204, 205, 0, 0, 0, 0, 13, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 13, 0, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0, 0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0, 0,  0, 0, 0,
                        63, 192, 0,   0,   0, 0, 0, 0, 15, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 12, 0, 0, 0,
                        64, 0,   0,   0,   0, 0, 0, 0, 14, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 14, 0, 0, 0,
                        63, 0,   0,   0,   0, 0, 0, 0, 13, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 13, 0, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0, 0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0, 0,  0, 0, 0,
                        63, 76,  204, 205, 0, 0, 0, 0, 15, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 12, 0, 0, 0,
                        63, 153, 153, 154, 0, 0, 0, 0, 14, 0, 0, 0, 63, 153, 153, 154, 0, 0, 0, 0, 14, 0, 0, 0,
                        63, 153, 153, 154, 0, 0, 0, 0, 13, 0, 0, 0, 63, 153, 153, 154, 0, 0, 0, 0, 13, 0, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0, 0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0, 0,  0, 0, 0,
                        63, 192, 0,   0,   0, 0, 0, 0, 15, 0, 0, 0};
u8 lbl_8031F054[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
u8 lbl_8031F064[240] = {
    0,  0,   0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 64, 0,   0, 0, 0, 0, 0, 0, 0, 0, 0,  0,   0, 0, 0, 0,
    63, 128, 0, 0, 0, 8, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 63, 128, 0, 0, 0, 1, 0, 0, 1, 0, 0,  0,   0, 0, 0, 0,
    64, 0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 63, 128, 0, 0, 0, 4, 0, 0, 3, 0, 0,  0,   0, 0, 0, 0,
    63, 128, 0, 0, 0, 2, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 63, 128, 0, 0, 0, 8, 0, 0, 5, 0, 0,  0,   0, 0, 0, 0,
    64, 0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 63, 128, 0, 0, 0, 2, 0, 0, 6, 0, 0,  0,   0, 0, 0, 0,
    63, 128, 0, 0, 0, 4, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 63, 128, 0, 0, 0, 1, 0, 0, 1, 0, 33, 230, 2, 0, 0, 0,
    63, 128, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 63, 128, 0, 0, 0, 8, 0, 0, 5, 0, 0,  0,   0, 0, 0, 0,
    63, 128, 0, 0, 0, 2, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0};
u8 lbl_8031F154[24] = {0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0};
void* lbl_8031F16C[69] = {
    lbl_8031DE50,      lbl_8031DE80,      lbl_8031DFC4,      lbl_8031E49C,      lbl_8031E2A0,      lbl_8031E21C,
    lbl_8031E240,      lbl_8031E3CC,      lbl_8031E64C,      lbl_8031E0F0,      lbl_8031DE50,      lbl_8031DE80,
    lbl_8031DFC4,      lbl_8031E49C,      lbl_8031E2A0,      lbl_8031E21C,      lbl_8031E240,      lbl_8031E3CC,
    lbl_8031E64C,      lbl_8031E0F0,      lbl_8031DE50,      lbl_8031DE80,      lbl_8031DFC4,      lbl_8031E664,
    lbl_8031E2A0,      lbl_8031E21C,      lbl_8031E240,      lbl_8031E3CC,      lbl_8031E814,      lbl_8031E0F0,
    lbl_8031DE50,      lbl_8031DE80,      lbl_8031DFC4,      lbl_8031E850,      lbl_8031E2A0,      lbl_8031E82C,
    lbl_8031E240,      lbl_8031E3CC,      lbl_8031EA00,      lbl_8031E0F0,      lbl_8031DE50,      lbl_8031DE80,
    lbl_8031DFC4,      lbl_8031EA18,      lbl_8031E2A0,      lbl_8031E21C,      lbl_8031E240,      lbl_8031E3CC,
    lbl_8031EBEC,      lbl_8031E0F0,      lbl_8031EC04,      lbl_8031EC34,      lbl_8031EC4C,      lbl_8031F064,
    lbl_8031EF28,      lbl_8031EEA4,      lbl_8031EEC8,      lbl_8031F054,      lbl_8031F154,      lbl_8031ED78,
    (void*)0x0F3C0A32, (void*)0x07140514, (void*)0x030F030F, (void*)0x3F000000, (void*)0x3F000000, (void*)0x3F333333,
    (void*)0x3F19999A, (void*)0x3FC00000, (void*)0x3FC00000};
u8 lbl_8031F280[16] = {0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8, 0, 0, 0, 9};
