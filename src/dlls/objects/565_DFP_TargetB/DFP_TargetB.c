/*
 * DragonRock Palace target block. The player knocks it along a path; it
 * raycasts for hits, snaps to stored path points, plays impact/loop SFX,
 * and reports completion.
 */
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/partfx_interface.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/objhits.h"
#include "main/track_bbox_api.h"
#include "main/objfx.h"
#include "main/mapEvent.h"
#include "main/model.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/dll_0235_dfptargetblock.h"
#include "main/vecmath.h"
#include "main/frame_timing.h"
#include "main/mapEventTypes.h"

#define DFPTARGETBLOCK_POINT_OFFSET_X 0x04
#define DFPTARGETBLOCK_POINT_OFFSET_Y 0x08
#define DFPTARGETBLOCK_POINT_OFFSET_Z 0x0C
#define DFPTARGETBLOCK_POINT_STRIDE   0x0C

f32 gTargetBlockHomeZ;
f32 gTargetBlockHomeX;
s32 gTargetBlockHomePos[] = {0, 0, 0};

void dfptargetblock_resolveCollisionPoints(GameObject* obj, DfpTargetBlockCollisionPoints* collisionPoints)
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
        probe[0] = *(f32*)(point + DFPTARGETBLOCK_POINT_OFFSET_X) + obj->anim.localPosX;
        originalX = probe[0];
        probe[1] = *(f32*)(point + DFPTARGETBLOCK_POINT_OFFSET_Y) + obj->anim.localPosY;
        probe[2] = *(f32*)(point + DFPTARGETBLOCK_POINT_OFFSET_Z) + obj->anim.localPosZ;
        originalZ = probe[2];
        if (trackGetLineIntersect(&obj->anim.localPosX, probe, (0.5f), 1, &hit, obj, 8, -1, 0, 0) != 0)
        {
            deltaX = probe[0] - originalX;
            deltaZ = probe[2] - originalZ;
            if (obj->anim.velocityX != 0.0f)
            {
                obj->anim.localPosX = obj->anim.localPosX + deltaX;
            }
            if (obj->anim.velocityZ != 0.0f)
            {
                obj->anim.localPosZ = obj->anim.localPosZ + deltaZ;
            }
            {
                f32 zero = 0.0f;
                obj->anim.velocityX = zero;
                obj->anim.velocityY = zero;
                obj->anim.velocityZ = zero;
            }
            Sfx_PlayFromObject(obj, SFXTRIG_mv_bflconc1_1d0);
            return;
        }
        point += DFPTARGETBLOCK_POINT_STRIDE;
        i++;
    }
}

int dfptargetblock_getExtraSize(void)
{
    return sizeof(DfpTargetBlockState);
}

int dfptargetblock_getObjectTypeId(void)
{
    return 0;
}

void dfptargetblock_free(GameObject* obj)
{
}

void dfptargetblock_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    DfpTargetBlockState* state;

    state = obj->extra;
    if (state->completionSfxReady != 0)
        return;
    if (state->stateSfxReady == 0 || state->mode == DFPTARGETBLOCK_MODE_SETTLED)
        return;
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

static inline void dfptargetblock_resetToHome(GameObject* obj, ObjPlacement* home,
                                              DfpTargetBlockState* state)
{
    f32 zero;

    obj->anim.localPosX = home->posX;
    obj->anim.localPosZ = home->posZ;
    zero = 0.0f;
    obj->anim.velocityX = zero;
    obj->anim.velocityZ = zero;
    state->mode = DFPTARGETBLOCK_MODE_RESETTING;
    obj->anim.localPosY = home->posY - (80.0f);
    Sfx_PlayFromObject(obj, DFPTARGETBLOCK_RESET_SFX);
}
static inline void dfptargetblock_checkSettled(GameObject* obj, DfpTargetBlockState* state,
                                               f32 threshold)
{
    f32 dx;
    f32 dz;

    dx = obj->anim.localPosX - gTargetBlockHomeX;
    dz = obj->anim.localPosZ - gTargetBlockHomeZ;
    if (!((dx == 0.0f) && (dz == 0.0f)))
    {
        if (sqrtf(dx * dx + dz * dz) < threshold)
        {
            state->mode = DFPTARGETBLOCK_MODE_LOWERING;
        }
    }
    else
    {
        state->mode = DFPTARGETBLOCK_MODE_LOWERING;
    }
}

void dfptargetblock_hitDetect(GameObject* obj)
{
    int i;
    DfpTargetBlockState* state;
    ObjPlacement* home;
    GameObject* hitObj;
    MatrixTransform effect;
    int priority;
    int hitType;
    s16 mode;
    f32 velX;
    f32 velZ;
    f32 dx;
    f32 dz;

    priority = -1;
    state = obj->extra;
    home = (ObjPlacement*)obj->anim.placementData;

    if (obj->anim.romDefNo == DFPTARGETBLOCK_HOME_OBJECT_TYPE)
    {
        gTargetBlockHomeX = obj->anim.localPosX;
        gTargetBlockHomeZ = obj->anim.localPosZ;
        return;
    }

    if ((state->completionSfxReady != 0) || (state->stateSfxReady == 0) ||
        (state->mode == DFPTARGETBLOCK_MODE_SETTLED) || (state->mode == DFPTARGETBLOCK_MODE_LOWERING))
    {
        return;
    }

    obj->anim.previousLocalPosX = obj->anim.localPosX;
    obj->anim.previousLocalPosY = obj->anim.localPosY;
    obj->anim.previousLocalPosZ = obj->anim.localPosZ;

    hitObj = NULL;
    hitType = ObjHits_GetPriorityHit(obj, &hitObj, &priority, 0);
    if ((hitType != 0) && (hitObj != NULL) && (hitType == DFPTARGETBLOCK_HIT_TYPE_PUSH) &&
        (hitType == DFPTARGETBLOCK_HIT_TYPE_PUSH))
    {
        Sfx_PlayFromObject(obj, DFPTARGETBLOCK_IMPACT_SFX);
        velX = hitObj->anim.velocityX;
        velZ = hitObj->anim.velocityZ;
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
            hitObj->anim.velocityZ = 0.0f;
        }
        else
        {
            hitObj->anim.velocityX = 0.0f;
        }
        {
            f32 scale = 0.25f;
            obj->anim.velocityX = hitObj->anim.velocityX * scale;
            obj->anim.velocityZ = hitObj->anim.velocityZ * scale;
        }
    }

    obj->anim.localPosX = obj->anim.velocityX * timeDelta + obj->anim.localPosX;
    obj->anim.localPosZ = obj->anim.velocityZ * timeDelta + obj->anim.localPosZ;

    if (obj->anim.velocityX != 0.0f)
    {
        Sfx_KeepAliveLoopedObjectSound(obj, DFPTARGETBLOCK_LOOP_SFX);
        velX = obj->anim.velocityX;
        if (velX < 0.0f)
        {
            if (velX >= 0.0f)
            {
                obj->anim.velocityX = 0.0f;
            }
        }
        else if ((velX > 0.0f) && (velX <= 0.0f))
        {
            obj->anim.velocityX = 0.0f;
        }
    }

    if (obj->anim.velocityZ != 0.0f)
    {
        Sfx_KeepAliveLoopedObjectSound(obj, DFPTARGETBLOCK_LOOP_SFX);
        velZ = obj->anim.velocityZ;
        if (velZ < 0.0f)
        {
            if (velZ >= 0.0f)
            {
                obj->anim.velocityZ = 0.0f;
            }
        }
        else if ((velZ > 0.0f) && (velZ <= 0.0f))
        {
            obj->anim.velocityZ = 0.0f;
        }
    }

    dfptargetblock_resolveCollisionPoints(obj, (DfpTargetBlockCollisionPoints*)state);

    dx = home->posX - obj->anim.localPosX;
    dz = home->posZ - obj->anim.localPosZ;
    mode = (*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot);

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

            effect.x = obj->anim.localPosX;
            effect.y = obj->anim.localPosY;
            effect.z = obj->anim.localPosZ;
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

void dfptargetblock_update(GameObject* obj)
{
    u8 mode;
    u8 bitVal;
    DfpTargetBlockState* state;
    ObjPlacement* home;
    PartFxSpawnParams burstOrigin;

    state = obj->extra;
    home = (ObjPlacement*)obj->anim.placementData;
    if (obj->anim.romDefNo == DFPTARGETBLOCK_HOME_OBJECT_TYPE)
    {
        burstOrigin.posX = 0.0f;
        burstOrigin.posY = (12.0f);
        burstOrigin.posZ = 0.0f;
        objfx_spawnArcedBurst(obj, 5, (0.75f), 1, 2, 0x32, (12.0f), (12.0f), 10.0f, &burstOrigin, 0);
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
            if (obj->anim.localPosY <= home->posY)
            {
                obj->anim.localPosY = obj->anim.localPosY + timeDelta;
                if (obj->anim.localPosY >= home->posY)
                {
                    obj->anim.localPosY = home->posY;
                    state->mode = DFPTARGETBLOCK_MODE_ACTIVE;
                }
            }
        }
        else if (mode == DFPTARGETBLOCK_MODE_LOWERING)
        {
            if (obj->anim.localPosY >= home->posY - (80.0f))
            {
                obj->anim.localPosY = (-1.0f) * timeDelta + obj->anim.localPosY;
                if (obj->anim.localPosY <= home->posY - (80.0f))
                {
                    obj->anim.localPosY = home->posY - (80.0f);
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

static inline int* ZBomb_GetActiveModel(GameObject* obj)
{
    ObjAnimComponent* objAnim = &obj->anim;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

void dfptargetblock_init(GameObject* obj, DfpTargetBlockPlacement* placement)
{
    int j;
    bool found;
    u8 bitVal;
    int i;
    DfpTargetBlockState* state;
    ModelFileHeader* model;
    f32 fconv;
    Vec3f point;

    state = obj->extra;
    model = (ModelFileHeader*)*ZBomb_GetActiveModel(obj);
    obj->objectFlags = obj->objectFlags | OBJECT_OBJFLAG_HIDDEN;
    if (obj->anim.romDefNo == DFPTARGETBLOCK_HOME_OBJECT_TYPE)
    {
        gTargetBlockHomePos[0] = obj->anim.localPosX;
        gTargetBlockHomePos[1] = obj->anim.localPosY;
        gTargetBlockHomePos[2] = obj->anim.localPosZ;
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
        obj->anim.localPosY = obj->anim.localPosY - (80.0f);
        state->completionSfxId = placement->completionSfxId;
        state->stateSfxId = placement->stateSfxId;
        bitVal = mainGetBit((int)state->completionSfxId);
        state->completionSfxReady = bitVal;
        bitVal = mainGetBit((int)state->stateSfxId);
        state->stateSfxReady = bitVal;
        if (state->completionSfxReady != '\0')
        {
            obj->anim.localPosX += 219.0f;
            obj->anim.localPosZ += -158.0f;
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
