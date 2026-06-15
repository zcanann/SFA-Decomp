#include "main/dll/dll_019F_nwtreebrid.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objseq.h"
extern uint GameBit_Get(int eventId);
extern void objRenderFn_8003b8f4(int obj, float arg);
extern int ObjGroup_FindNearestObject(int group, int obj, float* outDist);
extern void ObjPath_GetPointWorldPosition(int obj, int param2, float* outX, float* outY, float* outZ, int param6);

extern f32 lbl_803E51F8;
extern f32 lbl_803E51FC;

typedef struct TreeBirdState
{
    s16 gameBit;
    s16 triggerId;
    s16 immediateTrigger;
    u8 triggerLatched;
    u8 searchDelay;
    void* targetObj;
} TreeBirdState;

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
    while (i < (int)animUpdate->eventCount)
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

void treebird_render(int obj)
{
    TreeBirdState* state;
    float fx, fy, fz;

    state = ((GameObject*)obj)->extra;
    objRenderFn_8003b8f4(obj, lbl_803E51F8);
    if (state->targetObj != NULL)
    {
        ObjPath_GetPointWorldPosition(obj, 0, &fx, &fy, &fz, 0);
        *(float*)((u8*)state->targetObj + 0xc) = fx;
        *(float*)((u8*)state->targetObj + 0x10) = fy;
        *(float*)((u8*)state->targetObj + 0x14) = fz;
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

#include "main/game_object.h"
#include "main/objseq.h"
#include "main/dll/dll_019F_nwtreebrid.h"


void treebird_init(int obj, int setup)
{
    TreeBirdState* state;

    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = (void*)TreeBird_SeqFn;
    *(s16*)obj = (s16)((s8) * (u8*)(setup + 0x18) << 8);
    ((GameObject*)obj)->anim.rotY = *(s16*)(setup + 0x1a);
    ((GameObject*)obj)->anim.rotZ = *(s16*)(setup + 0x1c);
    state->triggerId = (s16)(s8) * (u8*)(setup + 0x19);
    state->gameBit = *(s16*)(setup + 0x1e);
    if (GameBit_Get((int)state->gameBit) != 0)
    {
        state->immediateTrigger = 0x154;
    }
    state->searchDelay = 4;
}

char* fn_801CDE70(int* obj);
