/*
 * magiclight (DLL 0x16B) - proximity-triggered "magic light" object.
 *
 * magiclight: seqId 0x172 is a render-only variant (draws a glow each
 * visible frame). The other variants carry a MagicLightState: at init a
 * random lifetime is rolled and, for seqId 0x16B, the placement subtype
 * picks an enter/leave L-action pair and a trigger radius preset. Each
 * tick (magiclight_SeqFn) the distance to the player is measured: crossing
 * inside triggerRadius fires the enter action, crossing back outside the
 * radius plus hysteresis fires the leave action. magiclight_update kicks
 * off trigger sequence 0 once, on the first update.
 */
#include "main/dll/magiclightstate_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/dll/DIM/DIMboulder.h"
#include "main/sfa_shared_decls.h"

/* seqId of the render-only glow variant (no MagicLightState, no proximity logic) */
#define MAGICLIGHT_SEQ_GLOW 0x172
/* seqId of the main proximity-triggered variant (subtype-selected L-actions) */
#define MAGICLIGHT_SEQ_PROXIMITY 0x16b

STATIC_ASSERT(sizeof(MagicLightState) == 0x14);

extern u32 getLActions();
extern int randomGetRange(int lo, int hi);
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern f32 Vec_distance(f32* a, f32* b);

#pragma scheduling off
#pragma peephole off
int magiclight_SeqFn(int* obj)
{
    MagicLightState* state;
    int* player;
    f32 dist;

    if (((GameObject*)obj)->anim.seqId == MAGICLIGHT_SEQ_GLOW) return 0;

    state = ((GameObject*)obj)->extra;
    player = (int*)Obj_GetPlayerObject();
    dist = Vec_distance(&((GameObject*)player)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX);

    if (dist < state->triggerRadius && state->inRange == 0)
    {
        state->inRange = 1;
        getLActions(obj, obj, (u16)state->enterAction, 0, 0, 0);
    }
    else if (dist > 10.0f + state->triggerRadius && state->inRange != 0)
    {
        state->inRange = 0;
        getLActions(obj, obj, (u16)state->leaveAction, 0, 0, 0);
    }
    return 0;
}

#pragma scheduling on
int magiclight_getExtraSize(int* obj)
{
    if (((GameObject*)obj)->anim.seqId == MAGICLIGHT_SEQ_GLOW) return 0x0;
    return 0x14;
}

#pragma scheduling off
int magiclight_getObjectTypeId(void) { return 0x0; }

void magiclight_free(int obj)
{
    MagicLightState* state = ((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.seqId != MAGICLIGHT_SEQ_GLOW)
    {
        if ((s8)state->inRange != 0)
        {
            getLActions(obj, obj, (u16)state->leaveAction, 0, 0, 0);
        }
        (*gExpgfxInterface)->freeSource2((u32)obj);
    }
}

#pragma scheduling on
void magiclight_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    if (((GameObject*)obj)->anim.seqId == MAGICLIGHT_SEQ_GLOW && visible != 0)
    {
        objRenderFn_8003b8f4(obj, p1, p2, p3, p4, 1.0f);
    }
}

#pragma peephole on
void magiclight_hitDetect(void)
{
}

#pragma scheduling off
#pragma peephole off
void magiclight_update(int obj)
{
    if (((GameObject*)obj)->anim.seqId != MAGICLIGHT_SEQ_GLOW && ((GameObject*)obj)->unkF4 == 0)
    {
        ((GameObject*)obj)->anim.rotX = 0;
        ((GameObject*)obj)->anim.rotY = 0;
        ((GameObject*)obj)->anim.rotZ = 0;
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        ((GameObject*)obj)->unkF4 = 1;
    }
}

void magiclight_init(int* obj, u8* params)
{
    MagicLightState* state;
    ((GameObject*)obj)->unkF4 = 0;
    ((GameObject*)obj)->anim.rotX = (s16)((s8)params[0x18] << 8);
    ((GameObject*)obj)->animEventCallback = magiclight_SeqFn;
    if (((GameObject*)obj)->anim.seqId == MAGICLIGHT_SEQ_GLOW)
    {
        return;
    }
    state = ((GameObject*)obj)->extra;
    state->lifetime = randomGetRange(0xc8, 0x258);
    state->subtype = (s8) * (s16*)(params + 0x1a);
    state->inRange = 0;
    if (((GameObject*)obj)->anim.seqId == MAGICLIGHT_SEQ_PROXIMITY)
    {
        switch (state->subtype)
        {
        case 0:
            state->enterAction = 0x90;
            state->leaveAction = 0x91;
            state->triggerRadius = 100.0f;
            break;
        case 1:
            state->enterAction = 0x92;
            state->leaveAction = 0x93;
            state->triggerRadius = 100.0f;
            break;
        default:
            state->enterAction = 0x94;
            state->leaveAction = 0x95;
            state->triggerRadius = 300.0f;
            break;
        case 3:
            state->enterAction = 0x187;
            state->leaveAction = 0x5;
            state->triggerRadius = 100.0f;
            break;
        }
        state->unk10 = 0x12d;
    }
    else
    {
        state->unk10 = 0x12d;
    }
}

#pragma scheduling on
#pragma peephole on
void magiclight_release(void)
{
}

void magiclight_initialise(void)
{
}
