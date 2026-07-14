/*
 * DragonRock Palace target block (DLL 0x235; "DFP_TargetBlock") - a block
 * the player knocks along a path: it raycasts for hits, snaps to stored
 * path points, plays impact/loop sfx and reports completion.
 */
#include "main/dll/partfx_interface.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_pointer_u16_legacy_api.h"
#include "main/audio/sfx_ids.h"
#include "main/object_render_legacy.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/game_object.h"
#include "main/track_bbox_api.h"
#include "main/objhits.h"
#include "main/objfx.h"
#include "main/dll/fruit.h"
#include "main/mapEvent.h"
#include "main/model.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/dll_0235_dfptargetblock.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"

#pragma force_active on
union TargetBlockConstF32 { f32 f; };
#pragma force_active reset
extern const union TargetBlockConstF32 lbl_803E6488;
extern const union TargetBlockConstF32 lbl_803E6490;
extern const union TargetBlockConstF32 lbl_803E6494;
extern const union TargetBlockConstF32 lbl_803E6498;
extern const union TargetBlockConstF32 lbl_803E649C;
extern const union TargetBlockConstF32 lbl_803E64A0;
extern const union TargetBlockConstF32 lbl_803E64A4;
extern const union TargetBlockConstF32 lbl_803E64AC;
extern const union TargetBlockConstF32 lbl_803E64B0;
extern const union TargetBlockConstF32 lbl_803E64B4;
extern const union TargetBlockConstF32 lbl_803E64B8;
extern const union TargetBlockConstF32 lbl_803E64BC;
extern const union TargetBlockConstF32 lbl_803E64C0;
extern const union TargetBlockConstF32 lbl_803E64C4;
extern const union TargetBlockConstF32 lbl_803E64C8;
extern const union TargetBlockConstF32 gTargetBlockMinVertexYSeed;
extern const union TargetBlockConstF32 lbl_803E64D0;
extern const union TargetBlockConstF32 lbl_803E64D4;
extern f32 lbl_803E64A8;

typedef struct DfpTargetBlockPartfxArgs
{
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    s16 pad06;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} DfpTargetBlockPartfxArgs;

#define DFPTARGETBLOCK_OBJFLAG_HIDDEN 0x4000

#define DFPTARGETBLOCK_POINT_OFFSET_X 0x04
#define DFPTARGETBLOCK_POINT_OFFSET_Y 0x08
#define DFPTARGETBLOCK_POINT_OFFSET_Z 0x0C
#define DFPTARGETBLOCK_POINT_STRIDE   0x0C

extern const f32 lbl_803E648C;
f32 gTargetBlockHomeZ;
f32 gTargetBlockHomeX;
extern s32 gTargetBlockHomePos[];

int dfptargetblock_getExtraSize(void)
{
    return 0x6c;
}

int dfptargetblock_getObjectTypeId(void)
{
    return 0;
}

void dfptargetblock_free(void)
{
}

void dfptargetblock_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    DfpTargetBlockAudioState* state;

    state = ((GameObject*)obj)->extra;
    if (state->completionSfxReady != 0)
        return;
    if (state->stateSfxReady == 0 || state->mode == DFPTARGETBLOCK_AUDIO_MODE_SETTLED)
        return;
    ((void (*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E6490.f);
}

static inline void dfptargetblock_resetToHome(DfpTargetBlockObject* obj, DfpTargetBlockHome* home,
                                              DfpTargetBlockAudioState* state)
{
    f32 zero;

    obj->x = home->x;
    obj->z = home->z;
    zero = lbl_803E648C;
    obj->velX = zero;
    obj->velZ = zero;
    state->mode = DFPTARGETBLOCK_AUDIO_MODE_RESETTING;
    obj->y = home->y - lbl_803E64AC.f;
    Sfx_PlayFromObject(obj, DFPTARGETBLOCK_RESET_SFX);
}

static inline void dfptargetblock_checkSettled(DfpTargetBlockObject* obj, DfpTargetBlockAudioState* state,
                                               const f32* threshold)
{
    f32 dx;
    f32 dz;

    dx = obj->x - gTargetBlockHomeX;
    dz = obj->z - gTargetBlockHomeZ;
    if (!((*(const f32*)&lbl_803E648C == dx) && (lbl_803E648C == dz)))
    {
        if (sqrtf(dx * dx + dz * dz) < *threshold)
        {
            state->mode = DFPTARGETBLOCK_AUDIO_MODE_LOWERING;
        }
    }
    else
    {
        state->mode = DFPTARGETBLOCK_AUDIO_MODE_LOWERING;
    }
}

#pragma force_active on
__declspec(section ".sdata2") const union TargetBlockConstF32 lbl_803E6488 = { 0.5f };
#pragma force_active reset

void dfptargetblock_hitDetect(DfpTargetBlockObject* obj)
{
    int i;
    DfpTargetBlockAudioState* state;
    DfpTargetBlockHome* home;
    DfpTargetBlockObject* hitObj;
    DfpTargetBlockPartfxArgs effect;
    int priority;
    int hitType;
    s16 mode;
    f32 velX;
    f32 velZ;
    f32 dx;
    f32 dz;

    priority = -1;
    state = obj->state;
    home = obj->home;

    if (obj->objectType == DFPTARGETBLOCK_HOME_OBJECT_TYPE)
    {
        gTargetBlockHomeX = obj->x;
        gTargetBlockHomeZ = obj->z;
        return;
    }

    if ((state->completionSfxReady != 0) || (state->stateSfxReady == 0) ||
        (state->mode == DFPTARGETBLOCK_AUDIO_MODE_SETTLED) || (state->mode == DFPTARGETBLOCK_AUDIO_MODE_LOWERING))
    {
        return;
    }

    obj->prevX = obj->x;
    obj->prevY = obj->y;
    obj->prevZ = obj->z;

    hitObj = NULL;
    hitType = ObjHits_GetPriorityHit((GameObject*)(obj), (int*)&hitObj, &priority, 0);
    if ((hitType != 0) && (hitObj != NULL) && (hitType == DFPTARGETBLOCK_HIT_TYPE_PUSH) &&
        (hitType == DFPTARGETBLOCK_HIT_TYPE_PUSH))
    {
        Sfx_PlayFromObject(obj, DFPTARGETBLOCK_IMPACT_SFX);
        velX = hitObj->velX;
        velZ = hitObj->velZ;
        if (velX < 0.0f)
        {
            velX *= lbl_803E6494.f;
        }
        if (velZ < 0.0f)
        {
            velZ *= lbl_803E6494.f;
        }
        if (velX > velZ)
        {
            hitObj->velZ = 0.0f;
        }
        else
        {
            hitObj->velX = 0.0f;
        }
        obj->velX = hitObj->velX * lbl_803E6498.f;
        obj->velZ = hitObj->velZ * lbl_803E6498.f;
    }

    obj->x = obj->velX * timeDelta + obj->x;
    obj->z = obj->velZ * timeDelta + obj->z;

    if (lbl_803E648C != obj->velX)
    {
        Sfx_KeepAliveLoopedObjectSoundPtrU16Legacy(obj, DFPTARGETBLOCK_LOOP_SFX);
        velX = obj->velX;
        if (velX < lbl_803E648C)
        {
            if (velX >= lbl_803E648C)
            {
                obj->velX = lbl_803E648C;
            }
        }
        else if ((velX > lbl_803E648C) && (velX <= lbl_803E648C))
        {
            obj->velX = lbl_803E648C;
        }
    }

    if (lbl_803E648C != obj->velZ)
    {
        Sfx_KeepAliveLoopedObjectSoundPtrU16Legacy(obj, DFPTARGETBLOCK_LOOP_SFX);
        velZ = obj->velZ;
        if (velZ < lbl_803E648C)
        {
            if (velZ >= lbl_803E648C)
            {
                obj->velZ = lbl_803E648C;
            }
        }
        else if ((velZ > lbl_803E648C) && (velZ <= lbl_803E648C))
        {
            obj->velZ = lbl_803E648C;
        }
    }

    dfptargetblock_resolveCollisionPoints(obj, (DfpTargetBlockCollisionPoints*)state);

    dx = home->x - obj->x;
    dz = home->z - obj->z;
    mode = (*gMapEventInterface)->getMapAct(obj->mapId);

    if (mode == 1)
    {
        if ((dx > lbl_803E649C.f) || (dx < lbl_803E64A0.f) || (dz < lbl_803E64A4.f) || (dz > lbl_803E64A8))
        {
            dfptargetblock_resetToHome(obj, home, state);
        }
        dfptargetblock_checkSettled(obj, state, &lbl_803E64B0.f);
    }
    else if (mode == 2)
    {
        if ((dx > lbl_803E64B4.f) || (dx < lbl_803E64B8.f) || (dz < lbl_803E64A4.f) || (dz > lbl_803E64BC.f))
        {
            dfptargetblock_resetToHome(obj, home, state);

            effect.x = obj->x;
            effect.y = obj->y;
            effect.z = obj->z;
            effect.scale = lbl_803E6490.f;
            effect.rotZ = 0;
            effect.rotY = 0;
            effect.rotX = 0;

            for (i = DFPTARGETBLOCK_RESET_PARTICLE_COUNT; i != 0; i--)
            {
                (*gPartfxInterface)
                    ->spawnObject(obj, DFPTARGETBLOCK_RESET_PARTICLE_ID, &effect, DFPTARGETBLOCK_RESET_PARTICLE_MODE,
                                  -1, NULL);
            }
        }
        dfptargetblock_checkSettled(obj, state, &lbl_803E64C0.f);
    }
}

static inline int* ZBomb_GetActiveModel(DfpTargetBlockObject* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

#pragma force_active on
__declspec(section ".sdata2") const union TargetBlockConstF32 lbl_803E6490 = { 1.0f };
__declspec(section ".sdata2") const union TargetBlockConstF32 lbl_803E6494 = { -1.0f };
__declspec(section ".sdata2") const union TargetBlockConstF32 lbl_803E6498 = { 0.25f };
__declspec(section ".sdata2") const union TargetBlockConstF32 lbl_803E649C = { 261.0f };
__declspec(section ".sdata2") const union TargetBlockConstF32 lbl_803E64A0 = { -11.0f };
__declspec(section ".sdata2") const union TargetBlockConstF32 lbl_803E64A4 = { -195.0f };
__declspec(section ".sdata2") f32 lbl_803E64A8 = 16.0f;
__declspec(section ".sdata2") const union TargetBlockConstF32 lbl_803E64AC = { 80.0f };
__declspec(section ".sdata2") const union TargetBlockConstF32 lbl_803E64B0 = { 10.0f };
__declspec(section ".sdata2") const union TargetBlockConstF32 lbl_803E64B4 = { 30.0f };
__declspec(section ".sdata2") const union TargetBlockConstF32 lbl_803E64B8 = { -242.0f };
__declspec(section ".sdata2") const union TargetBlockConstF32 lbl_803E64BC = { 6.0f };
__declspec(section ".sdata2") const union TargetBlockConstF32 lbl_803E64C0 = { 20.0f };
__declspec(section ".sdata2") const union TargetBlockConstF32 lbl_803E64C4 = { 12.0f };
__declspec(section ".sdata2") const union TargetBlockConstF32 lbl_803E64C8 = { 0.75f };
__declspec(section ".sdata2") const union TargetBlockConstF32 gTargetBlockMinVertexYSeed = { 10000.0f };
__declspec(section ".sdata2") const union TargetBlockConstF32 lbl_803E64D0 = { 219.0f };
__declspec(section ".sdata2") const union TargetBlockConstF32 lbl_803E64D4 = { -158.0f };
#pragma force_active reset

void dfptargetblock_update(DfpTargetBlockObject* obj)
{
    u8 mode;
    u8 bitVal;
    DfpTargetBlockState* state;
    DfpTargetBlockHome* home;
    float buf[6];

    state = (DfpTargetBlockState*)obj->state;
    home = obj->home;
    if (obj->objectType == DFPTARGETBLOCK_HOME_OBJECT_TYPE)
    {
        buf[3] = lbl_803E648C;
        buf[4] = lbl_803E64C4.f;
        buf[5] = lbl_803E648C;
        objfx_spawnArcedBurstLegacy((int)obj, 5, lbl_803E64C8.f, 1, 2, 0x32, lbl_803E64C4.f, lbl_803E64C4.f,
                                   lbl_803E64B0.f, buf, 0);
    }
    else
    {
        if (state->completionSfxReady == '\0')
        {
            bitVal = mainGetBit((int)state->completionSfxId);
            state->completionSfxReady = bitVal;
        }
        if (state->stateSfxReady == '\0')
        {
            bitVal = mainGetBit((int)state->stateSfxId);
            state->stateSfxReady = bitVal;
        }
        if ((state->completionSfxReady != '\0') || (state->stateSfxReady == '\0') ||
            (mode = state->mode, mode == DFPTARGETBLOCK_MODE_SETTLED))
        {
            return;
        }
        if ((mode == DFPTARGETBLOCK_MODE_RAISING) || (mode == DFPTARGETBLOCK_MODE_RESETTING))
        {
            if (obj->y <= home->y)
            {
                obj->y = obj->y + timeDelta;
                if (obj->y >= home->y)
                {
                    obj->y = home->y;
                    state->mode = DFPTARGETBLOCK_MODE_ACTIVE;
                }
            }
        }
        else if (mode == DFPTARGETBLOCK_MODE_LOWERING)
        {
            if (obj->y >= home->y - lbl_803E64AC.f)
            {
                obj->y = lbl_803E6494.f * timeDelta + obj->y;
                if (obj->y <= home->y - lbl_803E64AC.f)
                {
                    obj->y = home->y - lbl_803E64AC.f;
                    state->mode = DFPTARGETBLOCK_MODE_SETTLED;
                    mainSetBits((int)state->completionSfxId, 1);
                }
            }
        }
        else if (state->pathState != NULL)
        {
            (*gPathControlInterface)->update(obj, state->pathState, timeDelta);
            (*gPathControlInterface)->apply(obj, state->pathState);
            (*gPathControlInterface)->advance(obj, state->pathState, timeDelta);
        }
    }
    return;
}

void dfptargetblock_init(DfpTargetBlockObject* obj, int placementData)
{
    int j;
    bool found;
    u8 bitVal;
    int i;
    DfpTargetBlockState* state;
    ModelFileHeader* model;
    double fconv;
    DfpTargetBlockPoint point;

    state = (DfpTargetBlockState*)obj->state;
    model = (ModelFileHeader*)*ZBomb_GetActiveModel(obj);
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | DFPTARGETBLOCK_OBJFLAG_HIDDEN;
    if (obj->objectType == DFPTARGETBLOCK_HOME_OBJECT_TYPE)
    {
        gTargetBlockHomePos[0] = obj->x;
        gTargetBlockHomePos[1] = obj->y;
        gTargetBlockHomePos[2] = obj->z;
    }
    else
    {
        fconv = (double)gTargetBlockMinVertexYSeed.f;
        for (i = 0; i < (int)(u32)model->vertexCount; i = i + 1)
        {
            Model_GetVertexPosition(model, i, &point.x);
            if ((double)point.y < fconv)
            {
                fconv = (double)point.y;
            }
        }
        for (i = 0; i < (int)(u32)model->vertexCount; i = i + 1)
        {
            Model_GetVertexPosition(model, i, &point.x);
            if ((double)point.y == fconv)
            {
                found = false;
                for (j = 0; j < state->floorPointCount; j = j + 1)
                {
                    if ((point.x == state->floorPoints[j].x) && (point.z == state->floorPoints[j].z))
                    {
                        found = true;
                        j = state->floorPointCount;
                    }
                }
                if (!found)
                {
                    state->floorPoints[state->floorPointCount].x = *(f32*)&point.x;
                    state->floorPoints[state->floorPointCount].y = point.y;
                    state->floorPoints[state->floorPointCount].z = point.z;
                    state->floorPointCount++;
                }
            }
        }
        state->mode = DFPTARGETBLOCK_MODE_RAISING;
        obj->y = obj->y - lbl_803E64AC.f;
        state->completionSfxId = ((DfpTargetBlockPlacement*)placementData)->completionSfxId;
        state->stateSfxId = ((DfpTargetBlockPlacement*)placementData)->stateSfxId;
        bitVal = mainGetBit((int)state->completionSfxId);
        state->completionSfxReady = bitVal;
        bitVal = mainGetBit((int)state->stateSfxId);
        state->stateSfxReady = bitVal;
        if (state->completionSfxReady != '\0')
        {
            obj->x = obj->x + lbl_803E64D0.f;
            obj->z = obj->z + lbl_803E64D4.f;
            state->mode = DFPTARGETBLOCK_MODE_SETTLED;
        }
    }
    return;
}

void dfptargetblock_release(void)
{
}

void dfptargetblock_initialise(void)
{
}

s32 gTargetBlockHomePos[] = {0, 0, 0};

ObjectDescriptor10WithPadding gDfptargetblockObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)dfptargetblock_initialise,
        (ObjectDescriptorCallback)dfptargetblock_release,
        0,
        (ObjectDescriptorCallback)dfptargetblock_init,
        (ObjectDescriptorCallback)dfptargetblock_update,
        (ObjectDescriptorCallback)dfptargetblock_hitDetect,
        (ObjectDescriptorCallback)dfptargetblock_render,
        (ObjectDescriptorCallback)dfptargetblock_free,
        (ObjectDescriptorCallback)dfptargetblock_getObjectTypeId,
        dfptargetblock_getExtraSize,
    },
    0,
};

void dfptargetblock_resolveCollisionPoints(DfpTargetBlockObject* obj, DfpTargetBlockCollisionPoints* collisionPoints)
{
    u8* point;
    f32 probe[3];
    TrackBBoxHit hit;
    f32 originalX;
    f32 originalZ;
    f32 deltaX;
    f32 deltaZ;
    int i;

    i = 0;
    point = collisionPoints->pointData;
    while (i < collisionPoints->count)
    {
        probe[0] = *(f32*)(point + DFPTARGETBLOCK_POINT_OFFSET_X) + obj->x;
        originalX = probe[0];
        probe[1] = *(f32*)(point + DFPTARGETBLOCK_POINT_OFFSET_Y) + obj->y;
        probe[2] = *(f32*)(point + DFPTARGETBLOCK_POINT_OFFSET_Z) + obj->z;
        originalZ = probe[2];
        if (objBboxFn_800640cc(&obj->x, probe, lbl_803E6488.f, 1, &hit, (GameObject*)obj, 8, -1, 0, 0) != 0)
        {
            deltaX = probe[0] - originalX;
            deltaZ = probe[2] - originalZ;
            if (lbl_803E648C != obj->velX)
            {
                obj->x = obj->x + deltaX;
            }
            if (lbl_803E648C != obj->velZ)
            {
                obj->z = obj->z + deltaZ;
            }
            {
                f32 zero = lbl_803E648C;
                obj->velX = zero;
                obj->velY = zero;
                obj->velZ = zero;
            }
            Sfx_PlayFromObject(obj, SFXTRIG_mv_bflconc1_1d0);
            return;
        }
        point += DFPTARGETBLOCK_POINT_STRIDE;
        i++;
    }
}
