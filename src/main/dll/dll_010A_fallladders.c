/*
 * fallladders (DLL 0x010A) - a placed "falling ladder" prop driven by the
 * object sequence/trigger system.
 *
 * Two game bits from the placement record control it:
 *   upperGameBit (placement 0x20): when set the ladder begins to fall;
 *     during FALLLADDERS_SEQ_ID it also selects trigger sequence 0.
 *   lowerGameBit (placement 0x1E): during FALLLADDERS_SEQ_ID it selects
 *     trigger sequence 1 (the settled / alternate path).
 *
 * While the object is playing FALLLADDERS_SEQ_ID it runs trigger sequence 0
 * when only the upper bit is set, and trigger sequence 1 when only the lower
 * bit is set. Otherwise it runs a simple gravity drop: once the upper bit is
 * set it waits a short delay, plays a start sound, then falls under gravity
 * toward the placement rest Y, bouncing (velocity damped each landing) until
 * the bounce speed drops below a threshold and it settles (motionState 2).
 *
 * The placement supplies the rest-Y offset (restYOffset), the two game bits
 * and the model index; init pre-positions the object at restY + offset above
 * the floor.
 */
#include "main/dll_000A_expgfx.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"

/* sequence id during which the object reacts to the two game bits */
#define FALLLADDERS_SEQ_ID 0x548

#define FALLLADDERS_OBJFLAG_HIDDEN 0x4000
#define FALLLADDERS_OBJFLAG_HITDETECT_DISABLED 0x2000

typedef struct FallLaddersObjectDef
{
    ObjPlacement base;
    s8 rotXByte;       /* 0x18: rotX in 1/256 turns */
    s8 modelIndex;     /* 0x19: active model index */
    s16 restYOffset;   /* 0x1A: rest-Y offset added above the floor */
    s16 unk1C;         /* 0x1C: never read in this TU */
    s16 lowerGameBit;  /* 0x1E: trigger-sequence-1 / settled game bit */
    s16 upperGameBit;  /* 0x20: fall / trigger-sequence-0 game bit */
    u8 pad22[0x28 - 0x22];
} FallLaddersObjectDef;

STATIC_ASSERT(offsetof(FallLaddersObjectDef, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(FallLaddersObjectDef, modelIndex) == 0x19);
STATIC_ASSERT(offsetof(FallLaddersObjectDef, restYOffset) == 0x1A);
STATIC_ASSERT(offsetof(FallLaddersObjectDef, lowerGameBit) == 0x1E);
STATIC_ASSERT(offsetof(FallLaddersObjectDef, upperGameBit) == 0x20);

typedef struct FallLaddersState
{
    f32 restYOffset;
    s16 lowerGameBit;
    s16 upperGameBit;
    u8 motionState;
    u8 playStartSound;
    s16 delay;
} FallLaddersState;

extern f32 timeDelta;

extern void Obj_SetActiveModelIndex(int* obj, int idx);

int Fall_Ladders_SeqFn(void) { return 0x0; }
int Fall_Ladders_getExtraSize(void) { return 0xc; }
int Fall_Ladders_getObjectTypeId(void) { return 0x0; }

void Fall_Ladders_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void Fall_Ladders_render(void)
{
}

void Fall_Ladders_hitDetect(void)
{
}

#pragma scheduling off
#pragma peephole off
void Fall_Ladders_update(int obj)
{
    int def;
    FallLaddersState* state;
    f32 speed;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.seqId == FALLLADDERS_SEQ_ID)
    {
        if (GameBit_Get(state->upperGameBit) != 0 && GameBit_Get(state->lowerGameBit) == 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        }
        if (GameBit_Get(state->upperGameBit) == 0 && GameBit_Get(state->lowerGameBit) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
        }
    }
    else if (state->delay != 0)
    {
        state->delay -= (s16)timeDelta;
        if (state->delay <= 0)
        {
            state->motionState = 1;
            if (state->playStartSound != 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_totem_slide);
                state->playStartSound = 0;
            }
            state->delay = 0;
        }
    }
    else
    {
        if ((s8)state->motionState == 0 && GameBit_Get(state->upperGameBit) != 0)
        {
            state->delay = 10;
        }
        if ((s8)state->motionState == 1 && ((GameObject*)obj)->anim.localPosY >= ((ObjPlacement*)def)->posY)
        {
            ((GameObject*)obj)->anim.velocityY -= 0.9f;
            ((GameObject*)obj)->anim.localPosY =
                ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.localPosY;
            if (((GameObject*)obj)->anim.localPosY <= ((ObjPlacement*)def)->posY)
            {
                ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)def)->posY;
                ((GameObject*)obj)->anim.velocityY = 0.3f * -((GameObject*)obj)->anim.velocityY;
                speed = ((GameObject*)obj)->anim.velocityY;
                speed = (speed >= 0.0f) ? speed : -speed;
                if (speed < 0.01f)
                {
                    state->motionState = 2;
                }
            }
        }
    }
}

void Fall_Ladders_init(int* obj, FallLaddersObjectDef* def)
{
    FallLaddersState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)def->rotXByte << 8);
    state->upperGameBit = def->upperGameBit;
    state->lowerGameBit = def->lowerGameBit;
    state->restYOffset = (f32)(s32)def->restYOffset;
    ((GameObject*)obj)->objectFlags |= (FALLLADDERS_OBJFLAG_HIDDEN | FALLLADDERS_OBJFLAG_HITDETECT_DISABLED);
    ((GameObject*)obj)->animEventCallback = Fall_Ladders_SeqFn;
    ((GameObject*)obj)->anim.localPosY = def->base.posY + state->restYOffset;
    Obj_SetActiveModelIndex(obj, def->modelIndex);
    state->motionState = 0;
    if (GameBit_Get(state->upperGameBit) == 0)
    {
        state->playStartSound = 1;
    }
}
#pragma peephole reset
#pragma scheduling reset

void Fall_Ladders_release(void)
{
}

void Fall_Ladders_initialise(void)
{
}
