/*
 * dimgate (DLL 0x1C3) — mission gate object for Dinosaur Island.
 * Opens (hitbox state 0→2) once a type-399 object appears in the trigger
 * list, latching a gamebit so the gate stays open on reload.
 */
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/dll/VF/vf_shared.h"

#define DIMGATE_TRIGGER_OBJ_TYPE 399
#define DIMGATE_OBJFLAG_HITDETECT_DISABLED 0x2000
#define DIMGATE_OBJFLAG_HIDDEN 0x4000

enum DimgateState
{
    DIMGATE_STATE_CLOSED = 0,
    DIMGATE_STATE_OPENING = 1,
    DIMGATE_STATE_OPEN = 2,
};

typedef struct DimgatePlacement
{
    u8 pad0[0x1E - 0x0];
    s16 gateGameBit;
} DimgatePlacement;

extern void ObjHitbox_SetStateIndex(int obj, ObjHitsPriorityState* hitState, int stateIndex);
extern f32 lbl_803E4878;

void dimgate_free(void)
{
}

void dimgate_hitDetect(void)
{
}

void dimgate_release(void)
{
}

void dimgate_initialise(void)
{
}


int dimgate_SeqFn(void) { return 0x0; }
int dimgate_getExtraSize(void) { return 0x1; }
int dimgate_getObjectTypeId(void) { return 0x0; }

void dimgate_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E4878);
}


void dimgate_init(int obj, s8* p_unused_passthrough)
{
    char* inner;
    char* param;
    param = *(char**)&((GameObject*)obj)->anim.placementData;
    inner = ((GameObject*)obj)->extra;
    if (GameBit_Get(((DimgatePlacement*)param)->gateGameBit) != 0)
    {
        inner[0] = DIMGATE_STATE_OPEN;
        ((GameObject*)obj)->anim.currentMoveProgress = lbl_803E4878;
    }
    else
    {
        inner[0] = DIMGATE_STATE_CLOSED;
    }
    ((GameObject*)obj)->animEventCallback = dimgate_SeqFn;
    ((GameObject*)obj)->anim.rotX = (s16)((s8) * (u8*)(param + 0x18) << 8);
    ((GameObject*)obj)->objectFlags |= (DIMGATE_OBJFLAG_HIDDEN | DIMGATE_OBJFLAG_HITDETECT_DISABLED);
}


void dimgate_update(int obj)
{
    int* extra = ((GameObject*)obj)->extra;
    int* def = *(int**)&((GameObject*)obj)->anim.placementData;
    switch (*(s8*)extra)
    {
    case DIMGATE_STATE_CLOSED:
        {
            int found;
            int i;
            if (*(s8*)&((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->stateIndex != DIMGATE_STATE_OPENING)
            {
                ObjHitbox_SetStateIndex(obj, (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState, DIMGATE_STATE_OPENING);
            }
            found = 0;
            for (i = 0; i < (int)*(s8*)(*(int*)(obj + 0x58) + 0x10f); i++)
            {
                if (*(s16*)(*(int*)(*(int*)(obj + 0x58) + i * 4 + 0x100) + 0x46) == DIMGATE_TRIGGER_OBJ_TYPE)
                {
                    found = 1;
                    break;
                }
            }
            if (found)
            {
                GameBit_Set(((DimgatePlacement*)def)->gateGameBit, 1);
                if (*(s8*)&((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->stateIndex != DIMGATE_STATE_OPEN)
                {
                    ObjHitbox_SetStateIndex(obj, (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState, DIMGATE_STATE_OPEN);
                }
                *(s8*)extra = DIMGATE_STATE_OPEN;
            }
            break;
        }
    case DIMGATE_STATE_OPENING:
        break;
    case DIMGATE_STATE_OPEN:
        {
            if (*(s8*)&((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->stateIndex != DIMGATE_STATE_OPEN)
            {
                ObjHitbox_SetStateIndex(obj, (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState, DIMGATE_STATE_OPEN);
            }
            break;
        }
    }
}
