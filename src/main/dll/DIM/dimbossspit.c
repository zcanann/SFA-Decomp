/*
 * dimbossspit - the DIM boss-tonsil "spit/fight" main hit-state.
 *
 * dimBossTonsil_newState_hitFightMain drives the boss-tonsil object while it
 * is actively being fought: it flags the hit-react model active, ticks the
 * baddie-control hit/animation vtable callbacks, and runs two independent
 * countdown timers (lbl_803DDBA4 / lbl_803DDB98) off timeDelta. When either
 * timer expires it clears the active flag, marks the object disabled, clears
 * the boss-active game bit and sets one of the two route game bits depending
 * on gDIMbosstonsilRoutePhase. A separate rumble timer (lbl_803DDB9C/BA0)
 * plays the rumble sfx and triggers controller rumble. The player update is
 * called with the object's pending-parent link temporarily detached.
 */
#include "main/dll/DIM/DIMbossspit.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/player_control_interface.h"
#include "main/dll/DIM/dll_223.h"
#include "main/dll/fx_800944A0_shared.h"
extern f32 timeDelta;
extern f32 lbl_803DDB98;
extern f32 lbl_803DDB9C;
extern f32 lbl_803DDBA0;
extern f32 lbl_803DDBA4;
extern u8 lbl_803DDBA8[8];
extern u8 lbl_803DDBB0[8];
extern u8* gBaddieControlInterface;
extern f32 lbl_803E4C90;
extern f32 lbl_803E4C9C;
extern f32 lbl_803E4CB4;
extern f32 lbl_803E4CB8;
extern f32 lbl_803E4CBC;
extern f32 lbl_803E4CC0;


#define DIMBOSSSPIT_MODEL_ACTIVE_FLAG 0x1
#define DIMBOSSSPIT_OBJECT_DISABLED_FLAG 0x8

#define DIMBOSSSPIT_GAMEBIT_ACTIVE 0x20e
#define DIMBOSSSPIT_GAMEBIT_ROUTE_LOW 0x268
#define DIMBOSSSPIT_GAMEBIT_ROUTE_HIGH 0x311

#define DIMBOSSSPIT_ROUTE_HIGH_THRESHOLD 7
#define DIMBOSSSPIT_ROUTE_SPLIT_THRESHOLD 3
#define DIMBOSSSPIT_RUMBLE_SFX 0x189

void dimBossTonsil_newState_hitFightMain(u8* obj, ObjAnimUpdateState* animUpdate,
                                         DIMbosstonsilState* state,
                                         DIMbosstonsilState* updateState)
{
    f32 timer;
    u8* vt;

    timer = lbl_803E4C90;

    (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags |= DIMBOSSSPIT_MODEL_ACTIVE_FLAG;

    updateState->effectActive = 1;

    (*(void (**)(u8*, DIMbosstonsilState*, double, int))(*(int*)gBaddieControlInterface + 0x2C))(
        obj, updateState, (double)timer, 1);

    vt = (u8*)*(int*)gBaddieControlInterface;
    ((void (*)(u8*, DIMbosstonsilState*, u8*, s16, u8*, int, int, int))*(void**)(vt + 0x54))(
        obj, updateState, state->animPoints, state->animFrame,
        &state->hitReactMode, 0, 0, 0);

    if (lbl_803E4C90 != lbl_803DDBA4)
    {
        lbl_803DDBA4 = lbl_803DDBA4 - timeDelta;
        timer = lbl_803DDBA4 * lbl_803E4CB4;
        if (lbl_803DDBA4 <= lbl_803E4CB8)
        {
            lbl_803DDBA4 = lbl_803E4C90;
            updateState->animFinished = 0;
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags &= ~DIMBOSSSPIT_MODEL_ACTIVE_FLAG;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | DIMBOSSSPIT_OBJECT_DISABLED_FLAG);
            GameBit_Set(DIMBOSSSPIT_GAMEBIT_ACTIVE, 0);
            if (gDIMbosstonsilRoutePhase >= DIMBOSSSPIT_ROUTE_HIGH_THRESHOLD)
            {
                GameBit_Set(DIMBOSSSPIT_GAMEBIT_ROUTE_HIGH, 1);
            }
            else
            {
                GameBit_Set(DIMBOSSSPIT_GAMEBIT_ROUTE_LOW, 1);
            }
        }
    }
    else
    {
        timer = timer + lbl_803E4CBC;
    }

    if (lbl_803DDBA0 >= lbl_803DDB9C)
    {
        Sfx_PlayFromObject((u32)obj, DIMBOSSSPIT_RUMBLE_SFX);
        if (timer > lbl_803E4CBC) timer = lbl_803E4CBC;
        if (timer < lbl_803E4C9C) timer = lbl_803E4C9C;
        lbl_803DDB9C = lbl_803DDB9C + timer;
        doRumble(lbl_803E4CC0);
    }

    lbl_803DDBA0 = lbl_803DDBA0 + timeDelta;
    DIMbosstonsil_checkHit(obj, updateState);

    if (lbl_803E4C90 != lbl_803DDB98)
    {
        lbl_803DDB98 = lbl_803DDB98 - timeDelta;
        if (lbl_803DDB98 <= lbl_803E4C90)
        {
            lbl_803DDB98 = lbl_803E4C90;
            updateState->animFinished = 0;
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags &= ~DIMBOSSSPIT_MODEL_ACTIVE_FLAG;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | DIMBOSSSPIT_OBJECT_DISABLED_FLAG);
            GameBit_Set(DIMBOSSSPIT_GAMEBIT_ACTIVE, 0);
            if (gDIMbosstonsilRoutePhase == DIMBOSSSPIT_ROUTE_SPLIT_THRESHOLD)
            {
                GameBit_Set(DIMBOSSSPIT_GAMEBIT_ROUTE_LOW, 1);
            }
            else
            {
                GameBit_Set(DIMBOSSSPIT_GAMEBIT_ROUTE_HIGH, 1);
            }
        }
    }

    state->savedObjFieldC0 = *(u32*)&((GameObject*)obj)->pendingParentObj;
    *(u32*)&((GameObject*)obj)->pendingParentObj = 0;

    (*gPlayerInterface)->update(obj, updateState, timeDelta, timeDelta, lbl_803DDBB0, lbl_803DDBA8);

    *(u32*)&((GameObject*)obj)->pendingParentObj = state->savedObjFieldC0;
}
