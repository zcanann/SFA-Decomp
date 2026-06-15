/*
 * dimgate (DLL 0x1C3) — mission gate object for Dinosaur Island.
 * Opens (hitbox state 0→2) once a type-399 object appears in the trigger
 * list, latching a gamebit so the gate stays open on reload.
 */
#include "main/game_object.h"

typedef struct DimgatePlacement
{
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
} DimgatePlacement;

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern void ObjHitbox_SetStateIndex(int obj, ObjHitsPriorityState* hitState, int stateIndex);

extern void objRenderFn_8003b8f4(f32);
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

void dimbarrier_free(void);

int dimgate_SeqFn(void) { return 0x0; }
int dimgate_getExtraSize(void) { return 0x1; }
int dimgate_getObjectTypeId(void) { return 0x0; }
int dimicewall_getExtraSize(void);

void dimgate_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4878);
}

void dimbarrier_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dimgate_init(int obj, s8* p_unused_passthrough)
{
    char* inner;
    char* param;
    param = *(char**)&((GameObject*)obj)->anim.placementData;
    inner = ((GameObject*)obj)->extra;
    if (GameBit_Get(((DimgatePlacement*)param)->unk1E) != 0)
    {
        inner[0] = 2;
        ((GameObject*)obj)->anim.currentMoveProgress = lbl_803E4878;
    }
    else
    {
        inner[0] = 0;
    }
    ((GameObject*)obj)->animEventCallback = (void*)dimgate_SeqFn;
    *(s16*)obj = (s16)((s8) * (u8*)(param + 0x18) << 8);
    ((GameObject*)obj)->objectFlags |= 0x6000;
}

void dimbarrier_init(int obj, s8* p);

void dimgate_update(int obj)
{
    int* extra = ((GameObject*)obj)->extra;
    int* def = *(int**)&((GameObject*)obj)->anim.placementData;
    switch (*(s8*)extra)
    {
    case 0:
        {
            int found;
            int i;
            if (*(s8*)&((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->stateIndex != 1)
            {
                ObjHitbox_SetStateIndex(obj, (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState, 1);
            }
            found = 0;
            for (i = 0; i < (int)*(s8*)(*(int*)(obj + 0x58) + 0x10f); i++)
            {
                if (*(s16*)(*(int*)(*(int*)(obj + 0x58) + i * 4 + 0x100) + 0x46) == 399)
                {
                    found = 1;
                    break;
                }
            }
            if (found)
            {
                GameBit_Set(((DimgatePlacement*)def)->unk1E, 1);
                if (*(s8*)&((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->stateIndex != 2)
                {
                    ObjHitbox_SetStateIndex(obj, (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState, 2);
                }
                *(s8*)extra = 2;
            }
            break;
        }
    case 1:
        break;
    case 2:
        {
            if (*(s8*)&((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->stateIndex != 2)
            {
                ObjHitbox_SetStateIndex(obj, (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState, 2);
            }
            break;
        }
    }
}
