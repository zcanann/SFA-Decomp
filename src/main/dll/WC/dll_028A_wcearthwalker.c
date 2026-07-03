/*
 * earthwalker (DLL 0x28A) - the large EarthWalker dinosaur NPC as it
 * appears in the Walled City (WC). Its per-instance record lives at
 * ewObj->state (obj+0xB8; getExtraSize 0x660) and is viewed through
 * EarthWalkerState (dll_80220608_shared.h). render/update/hitDetect
 * forward into the shared dll_2E_* character helpers.
 *
 * Behavior is keyed on ewState->encounterType (read from the placement
 * setup byte at +0x19). update() runs a hit-reaction pass, picks an idle
 * vs. interaction animation move (0x203 / 2), runs eye anims, then a
 * two-step interactionState handshake: on player contact it disables the
 * A-button, sets game bit 0x7fb and, from interactionState 2, selects a
 * trigger-sequence number from a large encounterType-by-game-bit table
 * (gMapEventInterface map-act 2 plus quest bits 0xc90/0xc36/0xc55/0x7fc/
 * 0x235/0x9ad/0xc92) and runs it via gObjectTriggerInterface (objRunSeq),
 * remembering it in lastTriggeredState. Confirmed live (Dolphin): contact
 * on an encounterType-6 instance sets game bit 0x7fb and runs sequence 2;
 * the encounterType-8 instance (the Krazoa Shrine door dino) runs sequence 4,
 * disables the A-button and latches GAMEBIT_K1_SHRINE_DOOR_DIALOGUE_DONE
 * (0x9ad) - that sequence is the dialogue that unlocks the Krazoa Shrine door
 * (lastTriggeredState observed -1 -> 4).
 *
 * The dll_28B_stateHandlerN / dll_28B_substateHandlerN functions below are
 * compiled into this TU but belong to DLL 0x28B's state machine (a separate
 * player-following NPC): dll_028B.c installs them into gDll28BStateHandlers /
 * gDll28BSubstateHandlers and drives them via gPlayerInterface->update().
 * They operate on Dll28BAiState (earthwalker_state.h), NOT EarthWalkerState.
 * The gWcEarthWalker{Far,Near,Approach}PlayerDistance / {Chase,Walk}MoveSpeed
 * and gWcEarthWalker{IdleTimerThreshold,CurveAdvanceStep} constants are read
 * only by those 0x28B handlers (the follower AI), not by earthwalker_update.
 * Exact game-bit meanings and several encounter sub-states are inferred
 * from use, not confirmed.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/dll/earthwalker_state.h"
#include "main/dll/baddie_state.h"
#include "main/audio/sfx_trigger_ids.h"

int earthwalker_getExtraSize(void) { return 0x660; }

int earthwalker_getObjectTypeId(void) { return 0; }

void earthwalker_free(void)
{
}

void earthwalker_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    EarthWalkerObject* ewObj = (EarthWalkerObject*)obj;
    int state = (int)ewObj->state;

    if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6CE0);
        dll_2E_func06(obj, state, 0);
    }
}

void earthwalker_hitDetect(int obj)
{
    EarthWalkerObject* ewObj = (EarthWalkerObject*)obj;
    int state = (int)ewObj->state;
    EarthWalkerState* ewState = (EarthWalkerState*)state;

    if (ewObj->currentMove == 0x203)
    {
        fn_8003AAE0(obj, seqFn_800394a0(), ewState->hitTriggerId, 0, 0x186a0);
    }
}

void earthwalker_release(void)
{
}

void earthwalker_initialise(void)
{
}

void earthwalker_update(int obj)
{
    extern int GameBit_Get(int eventId);
    extern u8 ObjHitReact_Update();
    EarthWalkerObject* ewObj = (EarthWalkerObject*)obj;
    int state = (int)ewObj->state;
    EarthWalkerState* ewState = (EarthWalkerState*)state;
    int prevAnim;

    if ((ewState->hitReactState = ObjHitReact_Update(obj, gEarthWalkerHitReactEntries, 1,
                                                     ewState->hitReactState, &ewState->hitReactStepScale)) != 0)
    {
        return;
    }

    if (ewState->encounterType >= 4 && ewState->encounterType <= 8)
    {
        if (ewObj->currentMove != 0x203)
        {
            ObjAnim_SetCurrentMove(obj, 0x203, gEarthWalkerMoveStartProgress, 0);
        }
    }
    else
    {
        if (ewObj->currentMove != 2)
        {
            ObjAnim_SetCurrentMove(obj, 2, gEarthWalkerMoveStartProgress, 0);
        }
    }

    prevAnim = ewState->animPhase;
    dll_2E_func03(obj, state);
    if (ewState->encounterType >= 4 && ewState->encounterType <= 7 && prevAnim != 1 &&
        ewState->animPhase == 1)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_mammoth);
    }

    characterDoEyeAnims(obj, (int)ewState->eyeAnimState);
    if (ewState->flags & 1)
    {
        return;
    }

    switch (ewState->interactionState)
    {
    case 0:
        if (ewObj->statusFlags & 1)
        {
            buttonDisable(0, 0x100);
            GameBit_Set(0x7fb, 1);
            ewState->interactionState = 2;
            ewState->flags |= 1;
        }
        break;
    case 1:
        break;
    case 2:
        if (ewObj->statusFlags & 1)
        {
            int newState;
            switch (ewState->encounterType)
            {
            case 0:
                if ((*gMapEventInterface)->getMapAct(ewObj->mapEventId) == 2)
                {
                    if (ewState->lastTriggeredState == 0x14)
                    {
                        newState = 0x15;
                    }
                    else
                    {
                        newState = 0x14;
                    }
                }
                else if (GameBit_Get(0xc90) != 0)
                {
                    newState = 5;
                }
                else if (GameBit_Get(0xc36) != 0)
                {
                    newState = 4;
                }
                else if (GameBit_Get(0xc55) != 0)
                {
                    newState = 3;
                }
                else if (GameBit_Get(0x7fc) != 0)
                {
                    newState = 3;
                }
                else if (ewState->lastTriggeredState == 0)
                {
                    newState = 1;
                }
                else if (ewState->lastTriggeredState == 1)
                {
                    newState = 2;
                }
                else
                {
                    newState = 0;
                }
                break;
            case 9:
                if ((*gMapEventInterface)->getMapAct(ewObj->mapEventId) == 2)
                {
                    if (ewState->lastTriggeredState == 0x16)
                    {
                        newState = 0x17;
                    }
                    else
                    {
                        newState = 0x16;
                    }
                }
                else if (GameBit_Get(0xc90) != 0)
                {
                    newState = 0xa;
                }
                else if (GameBit_Get(0xc36) != 0)
                {
                    newState = 9;
                }
                else if (GameBit_Get(0xc55) != 0)
                {
                    newState = 8;
                }
                else if (GameBit_Get(0x7fc) != 0)
                {
                    newState = 8;
                }
                else if (ewState->lastTriggeredState == 6)
                {
                    newState = 7;
                }
                else
                {
                    newState = 6;
                }
                break;
            case 10:
                if ((*gMapEventInterface)->getMapAct(ewObj->mapEventId) == 2)
                {
                    if (ewState->lastTriggeredState == 0x18)
                    {
                        newState = 0x19;
                    }
                    else if (ewState->lastTriggeredState == 0x19)
                    {
                        newState = 0x1a;
                    }
                    else if (ewState->lastTriggeredState == 0x1a)
                    {
                        newState = 0x1b;
                    }
                    else
                    {
                        newState = 0x18;
                    }
                }
                else if (GameBit_Get(0xc90) != 0)
                {
                    newState = 0xf;
                }
                else if (GameBit_Get(0xc36) != 0)
                {
                    newState = 0xe;
                }
                else if (GameBit_Get(0xc55) != 0)
                {
                    newState = 0xd;
                }
                else if (GameBit_Get(0x7fc) != 0)
                {
                    if (ewState->lastTriggeredState == 0xb)
                    {
                        newState = 0xc;
                    }
                    else
                    {
                        newState = 0xb;
                    }
                }
                break;
            case 11:
                if ((*gMapEventInterface)->getMapAct(ewObj->mapEventId) == 2)
                {
                    if (ewState->lastTriggeredState == 0x1c)
                    {
                        newState = 0x1d;
                    }
                    else if (ewState->lastTriggeredState == 0x1d)
                    {
                        newState = 0x1e;
                    }
                    else if (ewState->lastTriggeredState == 0x1e)
                    {
                        newState = 0x1f;
                    }
                    else
                    {
                        newState = 0x1c;
                    }
                }
                else if (GameBit_Get(0xc90) != 0)
                {
                    newState = 0x13;
                }
                else if (GameBit_Get(0xc36) != 0)
                {
                    if (ewState->lastTriggeredState == 0x11)
                    {
                        newState = 0x12;
                    }
                    else
                    {
                        newState = 0x11;
                    }
                }
                else if (GameBit_Get(0xc55) != 0)
                {
                    newState = 0x10;
                }
                else if (GameBit_Get(0x7fc) != 0)
                {
                    newState = 0x10;
                }
                break;
            case 1:
                if ((*gMapEventInterface)->getMapAct(ewObj->mapEventId) == 2)
                {
                    if (GameBit_Get(0xc92) != 0)
                    {
                        ewObj->statusFlags |= 8;
                        newState = -1;
                    }
                    else if (GameBit_Get(0x235) != 0)
                    {
                        newState = 9;
                    }
                    else
                    {
                        newState = 8;
                    }
                }
                else if (GameBit_Get(0xc90) != 0)
                {
                    newState = 7;
                }
                else if (GameBit_Get(0xc36) != 0)
                {
                    newState = 6;
                }
                else if (GameBit_Get(0xc55) != 0)
                {
                    newState = 5;
                }
                else
                {
                    newState = 0;
                }
                break;
            case 3:
                newState = 0;
                break;
            case 2:
                newState = 0;
                break;
            case 4:
                newState = 0;
                break;
            case 5:
                newState = 1;
                break;
            case 6:
                newState = 2;
                break;
            case 7:
                newState = 3;
                break;
            case 8:
                if ((u32)GameBit_Get(GAMEBIT_K1_SHRINE_DOOR_DIALOGUE_DONE) == 0)
                {
                    newState = 4;
                    buttonDisable(0, 0x100);
                    GameBit_Set(GAMEBIT_K1_SHRINE_DOOR_DIALOGUE_DONE, 1);
                }
                else
                {
                    newState = 0;
                }
                break;
            }
            if (newState != -1)
            {
                buttonDisable(0, 0x100);
                (*gObjectTriggerInterface)->runSequence(
                    newState, (void*)obj, -1);
                ewState->lastTriggeredState = newState;
            }
        }
        break;
    }

    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, gEarthWalkerAnimAdvanceRate, timeDelta, 0);
}

/*
 * DLL 0x28B state-machine handlers (installed by dll_028B_initialise into
 * gDll28BStateHandlers / gDll28BSubstateHandlers; driven each frame by
 * gPlayerInterface->update). Each returns the next state index (0 = stay).
 * `ai` is the BaddieState at obj->extra (== the local `state` pointer); the
 * (*gPlayerInterface + 0x14)(obj, ai, N) calls are setState() requests.
 *
 *   stateHandler:    0 -> next state 2; 1/3 set moveSpeed on (re)entry,
 *                    3 also faces the player; 2 = locomotion: drives the
 *                    object along the ROM-curve route and samples root motion.
 *   substateHandler: 0 -> next state 2; 1 = follow curve, advancing points,
 *                    -> 3 when the player is within range; 2 = idle/watch,
 *                    -> 2 when player far, -> 4 (after a random 120..250
 *                    frame timer) when near; 3 requests setState 3 and
 *                    -> 3 when the move finishes.
 */
int dll_28B_substateHandler0(void) { return 0x2; }

int dll_28B_stateHandler0(void) { return 0x2; }

int dll_28B_substateHandler3(int obj, int ai)
{
    Dll28BAiState* state = *(Dll28BAiState**)&((GameObject*)obj)->extra;

    if (*(s8*)&((BaddieState*)ai)->moveJustStartedB != 0)
    {
        state->flagsAC0 &= ~1;
        (*(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, ai, 3);
    }
    else if (*(s8*)&((BaddieState*)ai)->moveDone != 0)
    {
        return 3;
    }
    return 0;
}

int dll_28B_substateHandler2(int obj, int ai)
{
    Dll28BAiState* state = *(Dll28BAiState**)&((GameObject*)obj)->extra;
    f32 dist;

    if (*(s8*)&((BaddieState*)ai)->moveJustStartedB != 0)
    {
        state->flagsAC0 |= 1;
        (*(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, ai, 1);
    }
    state->randomTimer -= timeDelta;
    dist = state->playerDistance;
    if (dist > gWcEarthWalkerFarPlayerDistance)
    {
        return 2;
    }
    if (dist < gWcEarthWalkerNearPlayerDistance)
    {
        if (state->randomTimer <= gWcEarthWalkerIdleTimerThreshold)
        {
            state->randomTimer = randomGetRange(0x78, 0xfa);
            return 4;
        }
    }
    return 0;
}

int dll_28B_substateHandler1(int obj, int ai)
{
    Dll28BAiState* state = *(Dll28BAiState**)&((GameObject*)obj)->extra;
    RomCurveWalker* route = &state->route;

    if (*(s8*)&((BaddieState*)ai)->moveJustStartedB != 0)
    {
        state->flagsAC0 &= ~1;
        (*(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, ai, 2);
    }
    if (Curve_AdvanceAlongPath(route, gWcEarthWalkerCurveAdvanceStep) != 0 || route->atSegmentEnd != 0)
    {
        (*gRomCurveInterface)->goNextPoint(route);
    }
    if (state->playerDistance < gWcEarthWalkerApproachPlayerDistance)
    {
        return 3;
    }
    return 0;
}

int dll_28B_stateHandler3(int obj, int ai)
{
    GameObject* player = (GameObject*)Obj_GetPlayerObject();

    if (*(s8*)&((BaddieState*)ai)->moveJustStartedA != 0)
    {
        ((BaddieState*)ai)->moveSpeed = gWcEarthWalkerChaseMoveSpeed;
        getAngle(((GameObject*)obj)->anim.localPosX - player->anim.localPosX,
                 ((GameObject*)obj)->anim.localPosZ - player->anim.localPosZ);
    }
    return 0;
}

int dll_28B_stateHandler2(int obj, int ai)
{
    EarthWalkerObject* ewObj = (EarthWalkerObject*)obj;
    Dll28BAiState* state = *(Dll28BAiState**)&((GameObject*)obj)->extra;

    ((GameObject*)obj)->anim.velocityX = oneOverTimeDelta * (state->route.posX - ((GameObject*)obj)->anim.localPosX);
    ((GameObject*)obj)->anim.velocityZ = oneOverTimeDelta * (state->route.posZ - ((GameObject*)obj)->anim.localPosZ);
    ((GameObject*)obj)->anim.localPosX = state->route.posX;
    ((GameObject*)obj)->anim.localPosZ = state->route.posZ;
    ewObj->facingAngle = getAngle(-state->route.tangentX, -state->route.tangentZ);
    ObjAnim_SampleRootCurvePhase(
        sqrtf(((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
            ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ),
        (ObjAnimComponent*)obj, &((BaddieState*)ai)->moveSpeed);
    return 0;
}

int dll_28B_stateHandler1(int obj, int ai)
{
    if (*(s8*)&((BaddieState*)ai)->moveJustStartedA != 0)
    {
        ((BaddieState*)ai)->moveSpeed = gWcEarthWalkerWalkMoveSpeed;
    }
    return 0;
}

int earthwalker_animEventCallback(int obj, int unused, ObjAnimUpdateState* animUpdate, int shouldAdvanceMove)
{
    EarthWalkerObject* ewObj = (EarthWalkerObject*)obj;
    int state = (int)ewObj->state;
    EarthWalkerState* ewState = (EarthWalkerState*)state;
    int i;

    ewState->flags &= ~1;
    characterDoEyeAnims(obj, (int)ewState->eyeAnimState);
    if (dll_2E_func07(obj, (int)(u8*)animUpdate, state, 0, 0) != 0)
    {
        return 0;
    }
    if ((s8)shouldAdvanceMove != 0)
    {
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, gEarthWalkerAnimAdvanceRate, timeDelta, 0);
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            getEnvfxActImmediately(obj, obj, 509, 0);
            break;
        case 2:
            getEnvfxActImmediately(obj, obj, 512, 0);
            break;
        }
    }
    return 0;
}

void earthwalker_init(int obj, int setup)
{
    EarthWalkerObject* ewObj = (EarthWalkerObject*)obj;
    int state = (int)ewObj->state;
    EarthWalkerState* ewState = (EarthWalkerState*)state;
    int local;

    local = gEarthWalkerMoveBlendData;
    ewObj->animEventCallback = earthwalker_animEventCallback;
    dll_2E_func05(obj, state, -8192, 12743, 2);
    dll_2E_func09(state, 0, &local, 2);
    /* moveLib state+0x614: head look-at only engages while the target is
     * within this distance (live-verified in Dolphin - drop it below the
     * player distance and the head snaps back to neutral). */
    dll_2E_setLookAtMaxDistance(state, gEarthWalkerLookAtMaxDistance);
    ewState->moveLibFlags611 |= 2;
    ewObj->facingAngle = (s16)((s8) * (s8*)(setup + 0x18) << 8);
    ewState->encounterType = *(u8*)(setup + 0x19);
    if (ewState->encounterType == 1)
    {
        if ((int)GameBit_Get(0x7fc) != 0 ||
            (*gMapEventInterface)->getMapAct(ewObj->mapEventId) == 2)
        {
            ewState->interactionState = 2;
        }
        else
        {
            ewState->interactionState = 0;
        }
    }
    else
    {
        ewState->interactionState = 2;
    }
    ewState->lastTriggeredState = -1;
}
