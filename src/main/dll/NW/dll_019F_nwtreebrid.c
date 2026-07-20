/*
 * nwtreebrid (DLL 0x19F) - a path-bound bird object in SnowHorn Wastes
 * (map 'nwastes', 0x0A).
 *
 * On its animation events it emits bursts of particle fx (the burst id
 * varies with the active sequence and trigger variant). Each frame it
 * samples a point along its object path and drags a linked target object
 * to that world position. It runs its trigger sequence either when armed
 * by an immediate trigger (set once its game bit is found set at init)
 * or directly once its game bit becomes set, after first locating a
 * nearby object in object group 4.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll/dll_019F_nwtreebrid.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/obj_group.h"
#include "main/obj_path.h"
#include "main/object_render.h"

#define NWTREEBRID_TARGET_OBJGROUP 4

int TreeBird_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    NwTreeBirdState* state;
    int i;
    int j;
    u8 cmd;

    state = (obj)->extra;
    i = 0;
    while (i < animUpdate->eventCount)
    {
        cmd = animUpdate->eventIds[i];
        switch (cmd)
        {
        case 1:
            j = 200;
            do
            {
                (*gPartfxInterface)->spawnObject(obj, 0xcc, 0, 1, -1, 0);
                j--;
            } while (j != 0);
            break;
        case 2:
            j = 100;
            if ((obj)->anim.seqId == 0x5d)
            {
                do
                {
                    (*gPartfxInterface)->spawnObject(obj, 0xd3, 0, 1, -1, 0);
                    j--;
                } while (j != 0);
            }
            else if (state->triggerId == 0)
            {
                do
                {
                    (*gPartfxInterface)->spawnObject(obj, 0xcd, 0, 1, -1, 0);
                    j--;
                } while (j != 0);
            }
            else if (state->triggerId == 1)
            {
                do
                {
                    (*gPartfxInterface)->spawnObject(obj, 0xcf, 0, 1, -1, 0);
                    j--;
                } while (j != 0);
            }
            break;
        case 3:
            j = 5;
            if ((obj)->anim.seqId == 0x5d)
            {
                do
                {
                    (*gPartfxInterface)->spawnObject(obj, 0xd4, 0, 1, -1, 0);
                    j--;
                } while (j != 0);
            }
            else if (state->triggerId == 0)
            {
                do
                {
                    (*gPartfxInterface)->spawnObject(obj, 0xce, 0, 1, -1, 0);
                    j--;
                } while (j != 0);
            }
            else if (state->triggerId == 1)
            {
                do
                {
                    (*gPartfxInterface)->spawnObject(obj, 0xd0, 0, 1, -1, 0);
                    j--;
                } while (j != 0);
            }
            break;
        }
        i++;
    }
    return 0;
}

int treebird_getExtraSize(void)
{
    return sizeof(NwTreeBirdState);
}

void treebird_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    NwTreeBirdState* state;
    f32 fx, fy, fz;

    state = obj->extra;
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    if (state->pathFollower != NULL)
    {
        ObjPath_GetPointWorldPosition(obj, 0, &fx, &fy, &fz, 0);
        state->pathFollower->anim.localPosX = fx;
        state->pathFollower->anim.localPosY = fy;
        state->pathFollower->anim.localPosZ = fz;
    }
}

void treebird_update(GameObject* obj)
{
    NwTreeBirdState* state;
    int preemptSequenceId;
    f32 dist;

    state = (obj)->extra;
    dist = 100.0f;
    if (state->searchDelay != 0)
    {
        state->pathFollower = (GameObject*)ObjGroup_FindNearestObject(NWTREEBRID_TARGET_OBJGROUP, obj, &dist);
        if (state->pathFollower != NULL)
        {
            state->searchDelay = 0;
        }
        else
        {
            state->searchDelay--;
        }
    }
    else if (state->triggerLatched == 0)
    {
        preemptSequenceId = state->preemptSequenceId;
        if (preemptSequenceId != 0)
        {
            (*gObjectTriggerInterface)->preempt((int)obj, preemptSequenceId);
            (*gObjectTriggerInterface)->runSequence((int)state->triggerId, (void*)obj, 1);
            state->triggerLatched = 1;
        }
        else if (mainGetBit((int)state->gameBit) != 0)
        {
            (*gObjectTriggerInterface)->runSequence((int)state->triggerId, (void*)obj, -1);
            state->triggerLatched = 1;
        }
    }
}

void treebird_init(GameObject* obj, NwTreeBirdPlacement* placement)
{
    NwTreeBirdState* state;

    state = obj->extra;
    obj->animEventCallback = TreeBird_SeqFn;
    obj->anim.rotX = (s16)(placement->initialRotX << 8);
    obj->anim.rotY = placement->initialRotY;
    obj->anim.rotZ = placement->initialRotZ;
    state->triggerId = placement->triggerVariant;
    state->gameBit = placement->gameBit;
    if (mainGetBit((int)state->gameBit) != 0)
    {
        state->preemptSequenceId = 0x154;
    }
    state->searchDelay = 4;
}
