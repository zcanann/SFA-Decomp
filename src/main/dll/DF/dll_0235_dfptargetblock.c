/*
 * DragonRock Palace target block (DLL 0x235; "DFP_TargetBlock") - a block
 * the player knocks along a path: it raycasts for hits, snaps to stored
 * path points, plays impact/loop sfx and reports completion.
 */
#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/dll/fruit.h"
#include "main/mapEvent.h"
#include "main/effect_interfaces.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/dll_0235_dfptargetblock.h"
#include "main/gamebits.h"

#define DFPTARGETBLOCK_OBJFLAG_HIDDEN 0x4000
extern int objBboxFn_800640cc(f32* from, f32* to, f32 radius, int mode, void* hit,
                              DfpTargetBlockObject* obj, int flags, int mask, int arg9, int arg10);
extern void Sfx_PlayFromObject(DfpTargetBlockObject* obj, u16 sfxId);
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern const f32 lbl_803E6488;
extern const f32 lbl_803E648C;
extern const f32 lbl_803E6490;

#define DFPTARGETBLOCK_POINT_OFFSET_X 0x04
#define DFPTARGETBLOCK_POINT_OFFSET_Y 0x08
#define DFPTARGETBLOCK_POINT_OFFSET_Z 0x0C
#define DFPTARGETBLOCK_POINT_STRIDE 0x0C

extern int ObjHits_GetPriorityHit(DfpTargetBlockObject* obj, DfpTargetBlockObject** hitObj,
                                  int* priority, int flags);
extern void Sfx_KeepAliveLoopedObjectSound(DfpTargetBlockObject* obj, u16 sfxId);
extern f32 sqrtf(f32 value);
extern f32 timeDelta;
extern f32 gTargetBlockHomeX;
extern f32 gTargetBlockHomeZ;
extern const f32 lbl_803E6494;
extern const f32 lbl_803E6498;
extern const f32 lbl_803E649C;
extern const f32 lbl_803E64A0;
extern const f32 lbl_803E64A4;
extern f32 lbl_803E64A8;
extern const f32 lbl_803E64AC;
extern const f32 lbl_803E64B0;
extern const f32 lbl_803E64B4;
extern const f32 lbl_803E64B8;
extern const f32 lbl_803E64BC;
extern const f32 lbl_803E64C0;
extern void Model_GetVertexPosition(int modelData, int vertexIndex, float* outPosition);
extern void objfx_spawnArcedBurst(int obj, int enabled, f32 radius, int particleKind,
                                  int particleId, int lifetime, f32 scaleX, f32 scaleY,
                                  f32 scaleZ, void* args, int arg9);
extern s32 gTargetBlockHomePos[];
extern const f32 lbl_803E64C4;
extern const f32 lbl_803E64C8;
extern const f32 gTargetBlockMinVertexYSeed;
extern const f32 lbl_803E64D0;
extern const f32 lbl_803E64D4;

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
    if (state->completionSfxReady != 0) return;
    if (state->stateSfxReady == 0 || state->mode == DFPTARGETBLOCK_AUDIO_MODE_SETTLED) return;
    ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E6490);
}

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
    obj->y = home->y - lbl_803E64AC;
    Sfx_PlayFromObject(obj, DFPTARGETBLOCK_RESET_SFX);
}

static inline void dfptargetblock_checkSettled(DfpTargetBlockObject* obj,
                                               DfpTargetBlockAudioState* state, const f32* threshold)
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
        (state->mode == DFPTARGETBLOCK_AUDIO_MODE_SETTLED) ||
        (state->mode == DFPTARGETBLOCK_AUDIO_MODE_LOWERING))
    {
        return;
    }

    obj->prevX = obj->x;
    obj->prevY = obj->y;
    obj->prevZ = obj->z;

    hitObj = NULL;
    hitType = ObjHits_GetPriorityHit(obj, &hitObj, &priority, 0);
    if ((hitType != 0) && (hitObj != NULL) && (hitType == DFPTARGETBLOCK_HIT_TYPE_PUSH) &&
        (hitType == DFPTARGETBLOCK_HIT_TYPE_PUSH))
    {
        Sfx_PlayFromObject(obj, DFPTARGETBLOCK_IMPACT_SFX);
        velX = hitObj->velX;
        velZ = hitObj->velZ;
        if (velX < 0.0f)
        {
            velX *= lbl_803E6494;
        }
        if (velZ < 0.0f)
        {
            velZ *= lbl_803E6494;
        }
        if (velX > velZ)
        {
            hitObj->velZ = 0.0f;
        }
        else
        {
            hitObj->velX = 0.0f;
        }
        obj->velX = hitObj->velX * lbl_803E6498;
        obj->velZ = hitObj->velZ * lbl_803E6498;
    }

    obj->x = obj->velX * timeDelta + obj->x;
    obj->z = obj->velZ * timeDelta + obj->z;

    if (lbl_803E648C != obj->velX)
    {
        Sfx_KeepAliveLoopedObjectSound(obj, DFPTARGETBLOCK_LOOP_SFX);
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
        Sfx_KeepAliveLoopedObjectSound(obj, DFPTARGETBLOCK_LOOP_SFX);
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
        if ((dx > lbl_803E649C) || (dx < lbl_803E64A0) || (dz < lbl_803E64A4) ||
            (dz > lbl_803E64A8))
        {
            dfptargetblock_resetToHome(obj, home, state);
        }
        dfptargetblock_checkSettled(obj, state, &lbl_803E64B0);
    }
    else if (mode == 2)
    {
        if ((dx > lbl_803E64B4) || (dx < lbl_803E64B8) || (dz < lbl_803E64A4) ||
            (dz > lbl_803E64BC))
        {
            dfptargetblock_resetToHome(obj, home, state);

            effect.x = obj->x;
            effect.y = obj->y;
            effect.z = obj->z;
            effect.scale = lbl_803E6490;
            effect.rotZ = 0;
            effect.rotY = 0;
            effect.rotX = 0;

            for (i = DFPTARGETBLOCK_RESET_PARTICLE_COUNT; i != 0; i--)
            {
                (*gPartfxInterface)->spawnObject(obj, DFPTARGETBLOCK_RESET_PARTICLE_ID,
                                                 &effect, DFPTARGETBLOCK_RESET_PARTICLE_MODE, -1, NULL);
            }
        }
        dfptargetblock_checkSettled(obj, state, &lbl_803E64C0);
    }
}

static inline int* ZBomb_GetActiveModel(DfpTargetBlockObject* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
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
        buf[3] = lbl_803E648C;
        buf[4] = lbl_803E64C4;
        buf[5] = lbl_803E648C;
        objfx_spawnArcedBurst((int)obj, 5, lbl_803E64C8, 1, 2, 0x32, lbl_803E64C4,
                              lbl_803E64C4, lbl_803E64B0, buf, 0);
    }
    else
    {
        if (state->completionSfxReady == '\0')
        {
            bitVal = GameBit_Get((int)state->completionSfxId);
            state->completionSfxReady = bitVal;
        }
        if (state->stateSfxReady == '\0')
        {
            bitVal = GameBit_Get((int)state->stateSfxId);
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
            if (obj->y >= home->y - lbl_803E64AC)
            {
                obj->y = lbl_803E6494 * timeDelta + obj->y;
                if (obj->y <= home->y - lbl_803E64AC)
                {
                    obj->y = home->y - lbl_803E64AC;
                    state->mode = DFPTARGETBLOCK_MODE_SETTLED;
                    GameBit_Set((int)state->completionSfxId, 1);
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
    int model;
    double fconv;
    DfpTargetBlockPoint point;

    state = (DfpTargetBlockState*)obj->state;
    model = *ZBomb_GetActiveModel(obj);
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | DFPTARGETBLOCK_OBJFLAG_HIDDEN;
    if (obj->objectType == DFPTARGETBLOCK_HOME_OBJECT_TYPE)
    {
        gTargetBlockHomePos[0] = obj->x;
        gTargetBlockHomePos[1] = obj->y;
        gTargetBlockHomePos[2] = obj->z;
    }
    else
    {
        fconv = (double)gTargetBlockMinVertexYSeed;
        for (i = 0; i < (int)(u32) * (u16*)(model + 0xe4); i = i + 1)
        {
            Model_GetVertexPosition(model, i, &point.x);
            if ((double)point.y < fconv)
            {
                fconv = (double)point.y;
            }
        }
        for (i = 0; i < (int)(u32) * (u16*)(model + 0xe4); i = i + 1)
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
        obj->y = obj->y - lbl_803E64AC;
        state->completionSfxId = ((DfpTargetBlockPlacement*)placementData)->completionSfxId;
        state->stateSfxId = ((DfpTargetBlockPlacement*)placementData)->stateSfxId;
        bitVal = GameBit_Get((int)state->completionSfxId);
        state->completionSfxReady = bitVal;
        bitVal = GameBit_Get((int)state->stateSfxId);
        state->stateSfxReady = bitVal;
        if (state->completionSfxReady != '\0')
        {
            obj->x = obj->x + lbl_803E64D0;
            obj->z = obj->z + lbl_803E64D4;
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
        0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
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

void dfptargetblock_resolveCollisionPoints(DfpTargetBlockObject* obj,
                                           DfpTargetBlockCollisionPoints* collisionPoints)
{
    u8* point;
    f32 probe[3];
    u8 hit[0x54];
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
        if (objBboxFn_800640cc(&obj->x, probe, lbl_803E6488, 1, hit, obj, 8, -1, 0, 0) != 0)
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
            Sfx_PlayFromObject(obj, SFXfoot_dirt_scuff);
            return;
        }
        point += DFPTARGETBLOCK_POINT_STRIDE;
        i++;
    }
}
