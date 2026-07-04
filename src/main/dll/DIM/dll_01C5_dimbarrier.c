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
#define DIMBARRIER_OBJFLAG_HITDETECT_DISABLED 0x2000
#define DIMBARRIER_OBJFLAG_HIDDEN 0x4000

/* dimbarrier_update state machine */
#define DIMBARRIER_STATE_ARMED 0    /* watching the trigger list, counting down */
#define DIMBARRIER_STATE_FADING 1   /* fading alpha out before latching the gamebit */
#define DIMBARRIER_STATE_RESOLVED 2 /* faded away, gamebit latched */

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

int dimbarrier_getExtraSize(void) { return 0x4; }
int dimbarrier_getObjectTypeId(void) { return 0x0; }

void dimbarrier_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4898);
}


void dimbarrier_init(int obj, s8* p)
{
    char* inner;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)p[0x18] << 8);
    ((GameObject*)obj)->objectFlags |= (DIMBARRIER_OBJFLAG_HIDDEN | DIMBARRIER_OBJFLAG_HITDETECT_DISABLED);
    inner = ((GameObject*)obj)->extra;
    inner[3] = 1;
    inner[2] = DIMBARRIER_STATE_ARMED;
    if (GameBit_Get(((DimbarrierPlacement*)p)->barrierGameBit) != 0)
    {
        ObjHitsPriorityState* hitState;
        inner[3] = 0;
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
        ((GameObject*)obj)->anim.alpha = 0;
        inner[2] = DIMBARRIER_STATE_RESOLVED;
    }
}


void dimbarrier_update(int obj)
{
    int* def = *(int**)&((GameObject*)obj)->anim.placementData;
    DimbarrierState* extra = (DimbarrierState*)((GameObject*)obj)->extra;
    switch (extra->state)
    {
    case DIMBARRIER_STATE_ARMED:
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
                    extra->state = DIMBARRIER_STATE_FADING;
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
    case DIMBARRIER_STATE_FADING:
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
                extra->state = DIMBARRIER_STATE_RESOLVED;
            }
            break;
        }
    case DIMBARRIER_STATE_RESOLVED:
        break;
    }
}
