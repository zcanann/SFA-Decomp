/*
 * shthorntail_ai - SHThorntail (Thorntail Hollow) AI helpers, split from the
 * thorntail DLL 0x1AD.
 *
 * Three routines split out of the main thorntail DLL (0x1AD):
 *  - SHthorntail_HasNearbyPendingEventObject: scans ObjGroup 3 for the
 *    linked thorntails configured for this one (via gSHthorntailDataTables)
 *    and reports whether any linked partner is in range with its linked
 *    game bit still clear (a co-op trigger event is still pending).
 *  - SHthorntail_updateTailSwing: drives the tail-swing windup/active/
 *    recover timer state machine, firing the windup and active sfx.
 *  - SHthorntail_chooseNextState: picks the next behavior state from
 *    player distance, leash radius, facing error and frustum visibility.
 */
#include "main/dll/SH/shthorntail_ai.h"
#include "main/frustum.h"
#include "main/audio/sfx.h"

/* home TU: SHThorntail DLL 0x1AD (gSHthorntailDataTables, the tuning
   floats and the debug string); the rest are engine-wide imports. */

extern f32 getXZDistance(Vec * a, Vec * b);
extern f32 vec3f_distanceSquared(Vec * a, Vec * b);
extern s16 getAngle(f32 deltaX, f32 deltaZ);
extern int randomGetRange(int lo, int hi);
extern int Obj_GetPlayerObject(void);
extern SHthorntailObject** ObjGroup_GetObjects(int group, int* countOut);
extern void fn_8014C66C(SHthorntailObject * obj, SHthorntailObject * other);
extern void OSReport(const char* msg, ...);
extern u32 gSHthorntailDataTables[][4];
extern char sSHthorntailAngleYawDebug[];
extern f32 timeDelta;
extern f32 SHTHORNTAIL_TIMER_DONE_THRESHOLD;
extern f32 SHTHORNTAIL_LINKED_EVENT_DISTANCE_SQ;
extern f32 SHTHORNTAIL_TAIL_SWING_WINDUP_TIME;
extern f32 SHTHORNTAIL_TAIL_SWING_RECOVER_TIME;
extern f32 SHTHORNTAIL_CLOSE_ATTACK_DISTANCE;

#define SHTHORNTAIL_OBJ_TYPE 0x4d7
#define SHTHORNTAIL_OBJ_GROUP 3
#define SHTHORNTAIL_LINKED_CONFIG_ROW_BYTES 0x10
/* player object pos vector lives at +0x18 */
#define PLAYER_POS_OFFSET 0x18

int SHthorntail_HasNearbyPendingEventObject(SHthorntailObject* obj)
{
    SHthorntailObject** objects;
    u32* linkedConfigRow;
    int count;
    int index;
    s8 groupIndex;
    int linkedEventPending;
    s8 matchCount;

    linkedEventPending = 0;
    groupIndex = -1;
    matchCount = 0;
    linkedConfigRow = gSHthorntailDataTables[0];
    for (index = 0; index < 6; index++)
    {
        if (obj->config->configToken == linkedConfigRow[0])
        {
            groupIndex = index;
            break;
        }
        linkedConfigRow = (u32*)((u8*)linkedConfigRow + SHTHORNTAIL_LINKED_CONFIG_ROW_BYTES);
    }
    objects = ObjGroup_GetObjects(SHTHORNTAIL_OBJ_GROUP, &count);
    for (index = 0; index < count; index++)
    {
        if ((objects[index]->objType == SHTHORNTAIL_OBJ_TYPE) &&
            ((objects[index]->config->configToken == gSHthorntailDataTables[groupIndex][1]) ||
                (objects[index]->config->configToken == gSHthorntailDataTables[groupIndex][2]) ||
                (objects[index]->config->configToken == gSHthorntailDataTables[groupIndex][3])))
        {
            fn_8014C66C(objects[index], obj);
            if ((vec3f_distanceSquared(&objects[index]->pos, &obj->pos) < SHTHORNTAIL_LINKED_EVENT_DISTANCE_SQ) &&
                (GameBit_Get(SHthorntail_GetLinkedGameBit(objects[index]->config)) == 0u))
            {
                linkedEventPending = 1;
            }
            matchCount++;
            if (matchCount == SHTHORNTAIL_LINKED_CONFIG_COUNT)
            {
                break;
            }
        }
    }
    return linkedEventPending;
}

void SHthorntail_updateTailSwing(u32 objectId, SHthorntailRuntime* runtime)
{
    u8 tailSwingState;
    int moveComplete;

    tailSwingState = runtime->tailSwingState;
    switch (tailSwingState)
    {
    case SHTHORNTAIL_TAIL_SWING_READY:
        runtime->tailSwingTimer = runtime->tailSwingTimer - timeDelta;
        if (runtime->tailSwingTimer <= SHTHORNTAIL_TIMER_DONE_THRESHOLD)
        {
            Sfx_PlayFromObject(objectId, SHTHORNTAIL_TAIL_SWING_WINDUP_VOLUME_ID);
            runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_WINDUP;
            runtime->tailSwingTimer = SHTHORNTAIL_TAIL_SWING_WINDUP_TIME;
        }
        break;
    case SHTHORNTAIL_TAIL_SWING_WINDUP:
        runtime->tailSwingTimer = runtime->tailSwingTimer - timeDelta;
        if (runtime->tailSwingTimer <= SHTHORNTAIL_TIMER_DONE_THRESHOLD)
        {
            Sfx_PlayFromObject(objectId, SHTHORNTAIL_TAIL_SWING_ACTIVE_VOLUME_ID);
            runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_ACTIVE;
        }
        break;
    case SHTHORNTAIL_TAIL_SWING_ACTIVE:
        moveComplete = runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE;
        if (moveComplete != 0)
        {
            runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_READY;
            runtime->tailSwingTimer = SHTHORNTAIL_TAIL_SWING_RECOVER_TIME;
        }
        break;
    default:
        break;
    }
}

u32 SHthorntail_chooseNextState(SHthorntailObject* object, SHthorntailRuntime* runtime,
                                 SHthorntailConfig* config)
{
    short angleDelta;
    int value;
    u32 nextState;
    s8 behaviorState;
    f32 dist;

    if (config->leashRadiusByte != '\0')
    {
        value = Obj_GetPlayerObject();
        dist = getXZDistance(&object->pos, (Vec*)(value + PLAYER_POS_OFFSET));
        if (dist < SHTHORNTAIL_CLOSE_ATTACK_DISTANCE)
        {
            behaviorState = runtime->behaviorState;
            if ((SHTHORNTAIL_STATE_MOVE_2 <= behaviorState) &&
                (behaviorState <= SHTHORNTAIL_STATE_MOVE_5))
            {
                nextState = SHTHORNTAIL_STATE_TURN_HOME;
            }
            else
            {
                nextState = SHTHORNTAIL_STATE_CLOSE_ATTACK;
            }
            return nextState;
        }
        dist = getXZDistance(&object->pos, &config->homePos);
        if (dist > (float)(s32)(config->leashRadiusByte * config->leashRadiusByte))
        {
            value = getAngle(object->modelPos.x - config->homePos.x,
                             object->modelPos.z - config->homePos.z);
            angleDelta = value - (u16)object->facingAngle;
            if (0x8000 < angleDelta)
            {
                angleDelta = angleDelta - 0xFFFF;
            }
            if (angleDelta < -0x8000)
            {
                angleDelta = angleDelta + 0xFFFF;
            }
            value = angleDelta;
            value = (value >= 0) ? value : -value;
            if (0x20 < value)
            {
                OSReport(sSHthorntailAngleYawDebug,
                         (u16)getAngle(object->modelPos.x - config->homePos.x,
                                       object->modelPos.z - config->homePos.z),
                         object->facingAngle);
                behaviorState = runtime->behaviorState;
                if ((SHTHORNTAIL_STATE_MOVE_2 <= behaviorState) &&
                    (behaviorState <= SHTHORNTAIL_STATE_MOVE_5))
                {
                    return SHTHORNTAIL_STATE_TURN_HOME;
                }
                return SHTHORNTAIL_STATE_CLOSE_ATTACK;
            }
        }
    }
    else
    {
        return SHTHORNTAIL_STATE_CLOSE_ATTACK;
    }
    value = ViewFrustum_IsSphereVisible((float*)&object->modelPos,
                                        object->cullRadius * object->modelScale);
    if (value == 0)
    {
        return SHTHORNTAIL_STATE_CLOSE_ATTACK;
    }
    behaviorState = runtime->behaviorState;
    if ((SHTHORNTAIL_STATE_MOVE_2 <= behaviorState) &&
        (behaviorState <= SHTHORNTAIL_STATE_MOVE_5))
    {
        nextState = randomGetRange(SHTHORNTAIL_STATE_MOVE_3, SHTHORNTAIL_STATE_MOVE_5);
        return nextState & 0xff;
    }
    return SHTHORNTAIL_STATE_MOVE_2;
}
