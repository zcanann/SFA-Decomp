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
#include "main/dll/dll_019F_nwtreebrid.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/objlib.h"
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern f32 lbl_803E51F8;
extern f32 lbl_803E51FC;

typedef struct TreeBirdState
{
    s16 gameBit;            /* 0x00: game bit that arms / fires the trigger */
    s16 triggerId;          /* 0x02: which trigger sequence to run */
    s16 immediateTrigger;   /* 0x04: preempt trigger id, set if already armed */
    u8 triggerLatched;      /* 0x06: trigger has fired; stop re-firing */
    u8 searchDelay;         /* 0x07: frames left to keep searching for target */
    void* targetObj;        /* 0x08: object dragged along the path each frame */
} TreeBirdState;

typedef struct NwTreeBirdMapData
{
    u8 pad00[0x18];
    s8 rotXByte;            /* 0x18: rotX in 1/256 turns */
    s8 triggerVariant;      /* 0x19: selects particle / trigger variant */
    s16 rotY;              /* 0x1A */
    s16 rotZ;              /* 0x1C */
    s16 gameBit;            /* 0x1E */
} NwTreeBirdMapData;

#define TREEBIRD_SPAWN_PARTICLE(obj,id) \
  (*gPartfxInterface)->spawnObject((void *)(obj),(id),0,1,-1,0)

int TreeBird_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    TreeBirdState* state;
    int i;
    int j;
    u8 cmd;

    state = ((GameObject*)obj)->extra;
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
                TREEBIRD_SPAWN_PARTICLE(obj, 0xcc);
                j--;
            }
            while (j != 0);
            break;
        case 2:
            j = 100;
            if (((GameObject*)obj)->anim.seqId == 0x5d)
            {
                do
                {
                    TREEBIRD_SPAWN_PARTICLE(obj, 0xd3);
                    j--;
                }
                while (j != 0);
            }
            else if (state->triggerId == 0)
            {
                do
                {
                    TREEBIRD_SPAWN_PARTICLE(obj, 0xcd);
                    j--;
                }
                while (j != 0);
            }
            else if (state->triggerId == 1)
            {
                do
                {
                    TREEBIRD_SPAWN_PARTICLE(obj, 0xcf);
                    j--;
                }
                while (j != 0);
            }
            break;
        case 3:
            j = 5;
            if (((GameObject*)obj)->anim.seqId == 0x5d)
            {
                do
                {
                    TREEBIRD_SPAWN_PARTICLE(obj, 0xd4);
                    j--;
                }
                while (j != 0);
            }
            else if (state->triggerId == 0)
            {
                do
                {
                    TREEBIRD_SPAWN_PARTICLE(obj, 0xce);
                    j--;
                }
                while (j != 0);
            }
            else if (state->triggerId == 1)
            {
                do
                {
                    TREEBIRD_SPAWN_PARTICLE(obj, 0xd0);
                    j--;
                }
                while (j != 0);
            }
            break;
        }
        i++;
    }
    return 0;
}

int treebird_getExtraSize(void)
{
    return 0xc;
}

void treebird_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    TreeBirdState* state;
    float fx, fy, fz;

    state = ((GameObject*)obj)->extra;
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E51F8);
    if (state->targetObj != NULL)
    {
        ObjPath_GetPointWorldPosition(obj, 0, &fx, &fy, &fz, 0);
        ((GameObject*)state->targetObj)->anim.localPosX = fx;
        ((GameObject*)state->targetObj)->anim.localPosY = fy;
        ((GameObject*)state->targetObj)->anim.localPosZ = fz;
    }
}

void treebird_update(int obj)
{
    TreeBirdState* state;
    int immediateTrigger;
    float dist;

    state = ((GameObject*)obj)->extra;
    dist = lbl_803E51FC;
    if (state->searchDelay != 0)
    {
        state->targetObj = (void*)ObjGroup_FindNearestObject(4, obj, &dist);
        if ((u32)state->targetObj != 0)
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
        immediateTrigger = state->immediateTrigger;
        if (immediateTrigger != 0)
        {
            (*gObjectTriggerInterface)->preempt(obj, immediateTrigger);
            (*gObjectTriggerInterface)->runSequence((int)state->triggerId, (void*)obj, 1);
            state->triggerLatched = 1;
        }
        else if (GameBit_Get((int)state->gameBit) != 0)
        {
            (*gObjectTriggerInterface)->runSequence((int)state->triggerId, (void*)obj, -1);
            state->triggerLatched = 1;
        }
    }
}

void treebird_init(int obj, int setup)
{
    TreeBirdState* state;

    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = TreeBird_SeqFn;
    ((GameObject*)obj)->anim.rotX = (s16)(((NwTreeBirdMapData*)setup)->rotXByte << 8);
    ((GameObject*)obj)->anim.rotY = ((NwTreeBirdMapData*)setup)->rotY;
    ((GameObject*)obj)->anim.rotZ = ((NwTreeBirdMapData*)setup)->rotZ;
    state->triggerId = ((NwTreeBirdMapData*)setup)->triggerVariant;
    state->gameBit = ((NwTreeBirdMapData*)setup)->gameBit;
    if (GameBit_Get((int)state->gameBit) != 0)
    {
        state->immediateTrigger = 0x154;
    }
    state->searchDelay = 4;
}
