/*
 * DragonRock Palace target block (DLL 0x235; "DFP_TargetBlock") - a block
 * the player knocks along a path: it raycasts for hits, snaps to stored
 * path points, plays impact/loop sfx and reports completion.
 */
#include "main/dll/partfx_interface.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"
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

f32 gTargetBlockHomeZ;
f32 gTargetBlockHomeX;
extern s32 gTargetBlockHomePos[];
void dfptargetblock_resolveCollisionPoints(DfpTargetBlockObject* obj, DfpTargetBlockCollisionPoints* collisionPoints);


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
        if (objBboxFn_800640cc(&obj->x, probe, (0.5f), 1, &hit, (GameObject*)obj, 8, -1, 0, 0) != 0)
        {
            deltaX = probe[0] - originalX;
            deltaZ = probe[2] - originalZ;
            if (0.0f != obj->velX)
            {
                obj->x = obj->x + deltaX;
            }
            if (0.0f != obj->velZ)
            {
                obj->z = obj->z + deltaZ;
            }
            {
                f32 zero = 0.0f;
                obj->velX = zero;
                obj->velY = zero;
                obj->velZ = zero;
            }
            Sfx_PlayFromObject((u32)obj, SFXTRIG_mv_bflconc1_1d0);
            return;
        }
        point += DFPTARGETBLOCK_POINT_STRIDE;
        i++;
    }
}

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
    ((void (*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, (1.0f));
}

static inline void dfptargetblock_resetToHome(DfpTargetBlockObject* obj, DfpTargetBlockHome* home,
                                              DfpTargetBlockAudioState* state)
{
    f32 zero;

    obj->x = home->x;
    obj->z = home->z;
    zero = 0.0f;
    obj->velX = zero;
    obj->velZ = zero;
    state->mode = DFPTARGETBLOCK_AUDIO_MODE_RESETTING;
    obj->y = home->y - (80.0f);
    Sfx_PlayFromObject((u32)obj, DFPTARGETBLOCK_RESET_SFX);
}
static inline void dfptargetblock_checkSettled(DfpTargetBlockObject* obj, DfpTargetBlockAudioState* state,
                                               f32 threshold)
{
    f32 dx;
    f32 dz;

    dx = obj->x - gTargetBlockHomeX;
    dz = obj->z - gTargetBlockHomeZ;
    if (!((0.0f == dx) && (0.0f == dz)))
    {
        if (sqrtf(dx * dx + dz * dz) < threshold)
        {
            state->mode = DFPTARGETBLOCK_AUDIO_MODE_LOWERING;
        }
    }
    else
    {
        state->mode = DFPTARGETBLOCK_AUDIO_MODE_LOWERING;
    }
}

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
        Sfx_PlayFromObject((u32)obj, DFPTARGETBLOCK_IMPACT_SFX);
        velX = hitObj->velX;
        velZ = hitObj->velZ;
        if (velX < 0.0f)
        {
            velX *= (-1.0f);
        }
        if (velZ < 0.0f)
        {
            velZ *= (-1.0f);
        }
        if (velX > velZ)
        {
            hitObj->velZ = 0.0f;
        }
        else
        {
            hitObj->velX = 0.0f;
        }
        {
            f32 scale = 0.25f;
            obj->velX = hitObj->velX * scale;
            obj->velZ = hitObj->velZ * scale;
        }
    }

    obj->x = obj->velX * timeDelta + obj->x;
    obj->z = obj->velZ * timeDelta + obj->z;

    if (0.0f != obj->velX)
    {
        Sfx_KeepAliveLoopedObjectSound((int)obj, DFPTARGETBLOCK_LOOP_SFX);
        velX = obj->velX;
        if (velX < 0.0f)
        {
            if (velX >= 0.0f)
            {
                obj->velX = 0.0f;
            }
        }
        else if ((velX > 0.0f) && (velX <= 0.0f))
        {
            obj->velX = 0.0f;
        }
    }

    if (0.0f != obj->velZ)
    {
        Sfx_KeepAliveLoopedObjectSound((int)obj, DFPTARGETBLOCK_LOOP_SFX);
        velZ = obj->velZ;
        if (velZ < 0.0f)
        {
            if (velZ >= 0.0f)
            {
                obj->velZ = 0.0f;
            }
        }
        else if ((velZ > 0.0f) && (velZ <= 0.0f))
        {
            obj->velZ = 0.0f;
        }
    }

    dfptargetblock_resolveCollisionPoints(obj, (DfpTargetBlockCollisionPoints*)state);

    dx = home->x - obj->x;
    dz = home->z - obj->z;
    mode = (*gMapEventInterface)->getMapAct(obj->mapId);

    if (mode == 1)
    {
        if ((dx > (261.0f)) || (dx < (-11.0f)) || (dz < (-195.0f)) || (dz > (16.0f)))
        {
            dfptargetblock_resetToHome(obj, home, state);
        }
        dfptargetblock_checkSettled(obj, state, 10.0f);
    }
    else if (mode == 2)
    {
        if ((dx > (30.0f)) || (dx < (-242.0f)) || (dz < (-195.0f)) || (dz > (6.0f)))
        {
            dfptargetblock_resetToHome(obj, home, state);

            effect.x = obj->x;
            effect.y = obj->y;
            effect.z = obj->z;
            effect.scale = (1.0f);
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
        dfptargetblock_checkSettled(obj, state, 20.0f);
    }
}



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
        buf[3] = 0.0f;
        buf[4] = (12.0f);
        buf[5] = 0.0f;
        objfx_spawnArcedBurstLegacy((int)obj, 5, (0.75f), 1, 2, 0x32, (12.0f), (12.0f),
                                   10.0f, buf, 0);
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
            if (obj->y >= home->y - (80.0f))
            {
                obj->y = (-1.0f) * timeDelta + obj->y;
                if (obj->y <= home->y - (80.0f))
                {
                    obj->y = home->y - (80.0f);
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

static inline int* ZBomb_GetActiveModel(DfpTargetBlockObject* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

void dfptargetblock_init(DfpTargetBlockObject* obj, int placementData)
{
    int j;
    bool found;
    u8 bitVal;
    int i;
    DfpTargetBlockState* state;
    ModelFileHeader* model;
    f32 fconv;
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
        fconv = 10000.0f;
        for (i = 0; i < (int)(u32)model->vertexCount; i = i + 1)
        {
            Model_GetVertexPosition(model, i, &point.x);
            if (point.y < fconv)
            {
                fconv = point.y;
            }
        }
        for (i = 0; i < (int)(u32)model->vertexCount; i = i + 1)
        {
            Model_GetVertexPosition(model, i, &point.x);
            if (point.y == fconv)
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
        obj->y = obj->y - (80.0f);
        state->completionSfxId = ((DfpTargetBlockPlacement*)placementData)->completionSfxId;
        state->stateSfxId = ((DfpTargetBlockPlacement*)placementData)->stateSfxId;
        bitVal = mainGetBit((int)state->completionSfxId);
        state->completionSfxReady = bitVal;
        bitVal = mainGetBit((int)state->stateSfxId);
        state->stateSfxReady = bitVal;
        if (state->completionSfxReady != '\0')
        {
            obj->x += 219.0f;
            obj->z += -158.0f;
            state->mode = DFPTARGETBLOCK_MODE_SETTLED;
        }
    }
    return;
}

void dfptargetblock_release(void)
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
void dfptargetblock_initialise(void)
{
}
