/*
 * dimbarrier (DLL 0x1C5) — barrier object for Dinosaur Island Mission.
 * While a live type-470 object is in the trigger list, counts down an arm
 * timer; on expiry fades the barrier out and latches its gamebit.
 */
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/gamebits.h"
#include "main/dll/VF/vf_shared.h"
#include "main/audio/sfx.h"

#define DIMBARRIER_TRIGGER_OBJ_TYPE 470

typedef struct DimbarrierPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 barrierGameBit;
} DimbarrierPlacement;

typedef struct DimbarrierState
{
    s16 timer;
    u8 state;
    s8 countdown;
} DimbarrierState;

extern f32 lbl_803E4898;

void dimbarrier_free(void)
{
}

void dimbarrier_hitDetect(void)
{
}

void dimbarrier_release(void)
{
}

void dimbarrier_initialise(void)
{
}

int dimsnowball1c2_getObjectTypeId(void);
int dimbarrier_getExtraSize(void) { return 0x4; }
int dimbarrier_getObjectTypeId(void) { return 0x0; }

void dimbarrier_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4898);
}

void dimsnowball1c2_init(int obj, u8* p);

void dimbarrier_init(int obj, s8* p)
{
    char* inner;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)p[0x18] << 8);
    ((GameObject*)obj)->objectFlags |= 0x6000;
    inner = ((GameObject*)obj)->extra;
    inner[3] = 1;
    inner[2] = 0;
    if (GameBit_Get(((DimbarrierPlacement*)p)->barrierGameBit) != 0)
    {
        ObjHitsPriorityState* hitState;
        inner[3] = 0;
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
        ((GameObject*)obj)->anim.alpha = 0;
        inner[2] = 2;
    }
}

int fn_801B17F4(int obj, int delta);

void dimbarrier_update(int obj)
{
    int* def = *(int**)&((GameObject*)obj)->anim.placementData;
    DimbarrierState* extra = (DimbarrierState*)((GameObject*)obj)->extra;
    switch (extra->state)
    {
    case 0:
        {
            int entry;
            int ex;
            int found;
            int i;
            found = 0;
            for (i = 0; i < (int)*(s8*)(*(int*)(obj + 0x58) + 0x10f); i++)
            {
                entry = *(int*)(*(int*)(obj + 0x58) + i * 4 + 0x100);
                ex = *(int*)&((GameObject*)entry)->extra;
                if (((GameObject*)entry)->anim.seqId == DIMBARRIER_TRIGGER_OBJ_TYPE && *(u8*)(ex + 4) != 0)
                {
                    found = 1;
                    break;
                }
            }
            if (found)
            {
                if (--extra->countdown <= 0)
                {
                    extra->state = 1;
                    extra->timer = 30;
                    Sfx_PlayFromObject(obj, SFXthorntail_chew1);
                }
                else
                {
                    Sfx_PlayFromObject(obj, SFXthorntail_chew2);
                }
            }
            break;
        }
    case 1:
        {
            ObjHitsPriorityState* hitState;
            int v = ((GameObject*)obj)->anim.alpha - framesThisStep * 16;
            if (v < 0)
            {
                v = 0;
            }
            hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
            hitState->flags &= ~1;
            ((GameObject*)obj)->anim.alpha = v;
            extra->timer -= framesThisStep;
            if (extra->timer <= 0)
            {
                GameBit_Set(((DimbarrierPlacement*)def)->barrierGameBit, 1);
                extra->state = 2;
            }
            break;
        }
    case 2:
        break;
    }
}
