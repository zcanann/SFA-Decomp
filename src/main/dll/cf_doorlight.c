/*
 * cf_doorlight (dll_131) - the "Kaldachom" door creature.
 *
 * A chompy baddie embedded in a locked door/wall: it pulls itself up,
 * lunges/bites at the player, and on death frees itself or returns to a
 * placement slot. Behaviour is driven entirely as gPlayerInterface
 * actor-control state handlers (kaldachom_stateHandler{A07,B00..B05}),
 * each returning the next requested control state (0 = stay).
 *
 * State record is the obj extra block (CfDoorlightState) whose tail holds
 * a KaldaChomControl (timers + soundFlags one-shots). The creature reads
 * its per-instance gate game bits (gameBitA/gameBitB) and an aggro chance
 * (placement unk2F vs randomGetRange) to pick its reaction.
 *
 * soundFlags one-shots: SOUNDFLAG_PULLUP_BURST = climb/attack/unlock burst played,
 * SOUNDFLAG_DOOR_CREAK = door-creak played once currentMoveProgress passes lbl_803E3088.
 */
#include "main/audio/sfx.h"
#include "main/audio/sfx_ids.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/dll/cf_doorlight_state.h"
#include "main/dll/cf_doorlight.h"
#include "main/dll/wallanimator.h"
#include "main/objhits.h"
#include "main/player_control_interface.h"
#include "main/gameplay_runtime.h"

typedef struct KaldachomPlacement
{
    u8 pad0[0x2F - 0x0];
    u8 aggroChance; /* 0x2F: 0..99 chance to lunge instead of return */
} KaldachomPlacement;

extern f32 timeDelta;
extern f32 lbl_803E3060; /* 0.0f */
extern f32 lbl_803E3078;
extern f32 lbl_803E307C;
extern f32 lbl_803E3080;
extern f32 lbl_803E3084;
extern f32 lbl_803E3088;
extern f32 lbl_803E308C;
extern int* gBaddieControlInterface; /* main/dll/player_80295318_shared.h */
extern void Obj_FreeObject(int obj);

#define BADDIE_CONTROL_MODE_PULLUP 2
#define BADDIE_CONTROL_MODE_RETURN 6

#define SOUNDFLAG_PULLUP_BURST 0x1
#define SOUNDFLAG_DOOR_CREAK 0x2

#define AGGRO_CHANCE_RANGE 0x63

int kaldachom_stateHandlerB05(int obj, int p)
{
    int state;
    KaldaChomControl* control;
    int def;

    state = *(int*)&((GameObject*)obj)->extra;
    control = ((CfDoorlightState*)state)->control;
    if (((GroundBaddieState*)p)->baddie.controlMode == BADDIE_CONTROL_MODE_PULLUP)
    {
        control->pullupSfxTimer = control->pullupSfxTimer - timeDelta;
        if (control->pullupSfxTimer <= lbl_803E3060)
        {
            ((GroundBaddieState*)p)->baddie.moveDone = 1;
        }
    }
    if ((s8)((GroundBaddieState*)p)->baddie.moveDone != 0 || (s8)((GroundBaddieState*)p)->baddie.moveJustStartedB != 0)
    {
        if (((int (*)(int, int, f32, int))((void**)*(int*)gBaddieControlInterface)[0x11])
            (obj, p, (f32)(u32)((CfDoorlightState*)state)->aggroRange, 1) != 0)
        {
            return 5;
        }
        def = *(int*)&((GameObject*)obj)->anim.placementData;
        if ((int)randomGetRange(0, AGGRO_CHANCE_RANGE) < (int)((KaldachomPlacement*)def)->aggroChance)
        {
            (*gPlayerInterface)->setState((void*)obj, (void*)p, 3);
        }
        else
        {
            control->pullupSfxTimer = (f32)(int)randomGetRange(0x12c, 0x258);
            (*gPlayerInterface)->setState((void*)obj, (void*)p, 2);
        }
    }
    return 0;
}

int kaldachom_stateHandlerB04(int obj, GroundBaddieState* state)
{
    if ((s8)state->baddie.moveJustStartedB != 0)
    {
        (*gPlayerInterface)->setState((void*)obj, state, 1);
    }
    return 0;
}

int kaldachom_stateHandlerB03(int obj, GroundBaddieState* state)
{
    if ((s8)state->baddie.moveJustStartedB != 0)
    {
        GroundBaddieState* extra = ((GameObject*)obj)->extra;
        extra->unk405 = 0;
        GameBit_Set(((CfDoorlightState*)extra)->gameBitB, 0);
        GameBit_Set(((CfDoorlightState*)extra)->gameBitA, 1);
    }
    return 0;
}

int kaldachom_stateHandlerA07(int obj, int p)
{
    int state;
    KaldaChomControl* control;

    state = *(int*)&((GameObject*)obj)->extra;
    *(u8*)&((GroundBaddieState*)p)->baddie.unk34D = 3;
    ((GroundBaddieState*)p)->baddie.moveSpeed = lbl_803E3084;
    {
        f32 fz = lbl_803E3060;
        ((GroundBaddieState*)p)->baddie.animSpeedA = fz;
        ((GroundBaddieState*)p)->baddie.animSpeedB = fz;
        if (*(char*)&((GroundBaddieState*)p)->baddie.moveJustStartedA != '\0')
        {
            ObjAnim_SetCurrentMove(obj, 5, fz, 0);
            *(s8*)&((GroundBaddieState*)p)->baddie.moveDone = 0;
        }
    }
    {
        int v = *(int*)&((GroundBaddieState*)p)->baddie.eventFlags;
        if ((v & 0x1000) != 0)
        {
            *(int*)&((GroundBaddieState*)p)->baddie.eventFlags = v & ~0x1000;
            kaldachompme_setLinkedMouthMode((u8*)obj, 2);
        }
    }
    control = ((CfDoorlightState*)state)->control;
    if ((control->soundFlags & SOUNDFLAG_PULLUP_BURST) == 0)
    {
        Sfx_PlayFromObject(obj, SFXkr_climb2);
        Sfx_PlayFromObject(obj, SFXsc_attack01);
        Sfx_PlayFromObject(obj, SFXdoor_unlocked);
        control->soundFlags |= SOUNDFLAG_PULLUP_BURST;
        {
            char* linkedObj;
            if (((CfDoorlightState*)state)->spawnsLinkedObj != 0)
            {
                linkedObj = ((char *(*)(int, int, int, int))((void**)*gBaddieControlInterface)[0x13])(obj, 6, -1, 0);
            }
            else
            {
                linkedObj = NULL;
            }
            if (linkedObj != NULL)
            {
                f32 fz = lbl_803E3060;
                (**(void (**)(char*, f32, f32, f32))(*(int*)(*(int*)(linkedObj + 0x68)) + 0x2c))(linkedObj, fz, lbl_803E3078, fz);
            }
        }
    }
    if ((control->soundFlags & SOUNDFLAG_DOOR_CREAK) == 0)
    {
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E3088)
        {
            Sfx_PlayFromObject(obj, SFXdoor_creak);
            control->soundFlags |= SOUNDFLAG_DOOR_CREAK;
        }
    }
    ((GameObject*)obj)->anim.alpha =
        (lbl_803E3078 - ((GameObject*)obj)->anim.currentMoveProgress) * lbl_803E308C;
    return 0;
}

int kaldachom_stateHandlerB01(int* obj, GroundBaddieState* state)
{
    KaldaChomControl* control = ((CfDoorlightState*)((GameObject*)obj)->extra)->control;
    if (state->baddie.controlMode == BADDIE_CONTROL_MODE_RETURN)
    {
        f32 zero;
        f32 timer;
        if ((s8)state->baddie.moveJustStartedB != 0)
        {
            control->returnStateTimer = lbl_803E3080;
        }
        timer = control->returnStateTimer;
        zero = lbl_803E3060;
        if (timer != zero)
        {
            control->returnStateTimer = timer - timeDelta;
            if (control->returnStateTimer < zero)
            {
                control->returnStateTimer = zero;
            }
        }
        else
        {
            return 6;
        }
    }
    else
    {
        if ((s8)state->baddie.moveDone != 0) return 6;
    }
    return 0;
}

int kaldachom_stateHandlerB00(int* obj, GroundBaddieState* state)
{
    if (state->baddie.targetObj != NULL)
    {
        if ((s8)state->baddie.moveJustStartedB != 0)
        {
            f32 fz = lbl_803E3060;
            state->baddie.animSpeedB = fz;
            state->baddie.animSpeedA = fz;
            (*gPlayerInterface)->setState(obj, state, 0);
        }
        else if ((s8)state->baddie.moveDone != 0)
        {
            return 6;
        }
    }
    return 0;
}

int kaldachom_stateHandlerB02(int obj, GroundBaddieState* p2)
{
    int sub = *(int*)&((GameObject*)obj)->extra;

    if ((s32)(s8)p2->baddie.moveJustStartedB != 0)
    {
        ((CfDoorlightState*)sub)->control->soundFlags = 0;
        (*gPlayerInterface)->setState((void*)obj, p2, 7);
        ObjHits_DisableObject(obj);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
        ((CfDoorlightState*)sub)->flags400 = (u16)(((CfDoorlightState*)sub)->flags400 | 0x20);
        ((CfDoorlightState*)sub)->unk3E8 = lbl_803E3078;
        ((CfDoorlightState*)sub)->unk3EC = lbl_803E307C;
    }
    else if ((s32)(s8)p2->baddie.moveDone != 0)
    {
        if (((GameObject*)obj)->anim.placementData == NULL)
        {
            Obj_FreeObject(obj);
            return 0;
        }
        return 4;
    }
    return 0;
}
