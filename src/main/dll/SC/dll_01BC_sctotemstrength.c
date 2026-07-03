/*
 * LightFoot Village "Test of Strength" (DLL 0x1BC): a push-of-war against
 * MuscleFoot - both shove opposite sides of a rotating mechanism, and
 * button-mashing hard enough pushes him into the pit to win. platform1_control
 * is the minigame; it runs while the village map-event 0xe is in state 6.
 * Winning sets GameBit 0x784, losing sets 0x786. (This file also carries the
 * FElevControl descriptor tail.)
 */
#include "main/camera_interface.h"
#include "main/game_object.h"
#include "main/dll/VF/platform1.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/screen_transition.h"
#include "main/dll/DB/DBrockfall.h"
#include "main/dll/SC/sc_shared.h"
#include "main/objlib.h"
#include "main/pad.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"

#define PAD_BUTTON_A 0x100

extern void Sfx_SetObjectSfxVolume(u32 obj, u32 sfxId, u8 volume, f32 volumeScale);
extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);
extern u32 Sfx_KeepAliveLoopedObjectSound();

extern void setAButtonIcon(int x);

extern int isGameTimerDisabled(void);
extern f32 fn_8001461C(void);
extern void fn_801DE320(void* dst, int val);
extern int ObjSeq_takeXrotChanged(int index);
extern void hudFn_8011f38c(u8 x);
extern void objRenderFn_8003b8f4(f32);
extern int gTotemStrengthDeactivateTimer;
extern int lbl_803DC070;
extern const f32 lbl_803E5668;
extern const f32 lbl_803E566C;
extern const f32 lbl_803E5670;
extern const f32 lbl_803E5674;
extern const f32 lbl_803E5678;
extern const f32 lbl_803E567C;
extern const f32 lbl_803E5680;
extern const f32 lbl_803E5684;
extern f32 lbl_803E5688;
extern const f32 lbl_803E568C;
extern const f32 lbl_803E5690;
extern f32 lbl_803E5694;
extern f32 lbl_803E5698;
extern const f32 lbl_803E569C;
extern f32 lbl_803E56A0;
extern f32 lbl_803E56A4;

#define PLATFORM1_ANCHOR_SEQ_ID 0x3ff
#define PLATFORM1_PLAYER_PULL_MOVE_ID 0x401
#define PLATFORM1_IDLE_PULL_MOVE_ID 0

#define PLATFORM1_LOOP_SFX_ID 0x3af
#define PLATFORM1_PLAYER_SFX_ID 0x13a
#define PLATFORM1_PLATFORM_SFX_ID 0x4a3

#define PLATFORM1_TRACK_EXIT_NEG (-0x46dc) /* offset below this -> EXIT_NEGATIVE */
#define PLATFORM1_TRACK_EXIT_POS (-0xb24)  /* offset above this -> EXIT_POSITIVE */

#define SC_TOTEMSTRENGTH_OBJFLAG_HIDDEN 0x4000
#define SC_TOTEMSTRENGTH_OBJFLAG_HITDETECT_DISABLED 0x2000

/* platform1_control: tug-of-war rope
 * minigame. Resolves the anchor object, applies sequence events, then per
 * frame works the rope position from A-press mashing, runs both pull anims
 * and grunt/creak sfx, and ends the game through the screen transition
 * when either side wins. */
int platform1_control(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    GameObject* self;
    Platform1State* st;
    GameObject* playerObj;
    int player;
    int* list;
    int* p;
    int o;
    int i;
    u8 ev;
    int buttons;
    f32 wob1, wob2, push;
    f32 diff;
    f32 absDiff;
    f32 t;
    int vol;
    int ret;
    int idx1, cnt1, cnt2, idx2, cnt3, idx3, cnt4, idx4, cnt5, idx5;
    struct
    {
        int mode;
        u8 flag;
    } evt;

    self = (GameObject*)obj;
    st = self->extra;
    playerObj = (GameObject*)Obj_GetPlayerObject();
    player = (int)playerObj;
    st->flags = (u8)(st->flags | PLATFORM1_FLAG_ACTIVE);
    setAButtonIcon(0xf);
    gTotemStrengthDeactivateTimer = 0;
    st->linkedObject = 0;
    list = ObjList_GetObjects(&idx1, &cnt1);
    while (idx1 < cnt1)
    {
        st->linkedObject = list[idx1++];
        if (((GameObject*)st->linkedObject)->anim.seqId == PLATFORM1_ANCHOR_SEQ_ID)
        {
            idx1 = cnt1;
        }
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        ev = animUpdate->eventIds[i];
        switch (ev)
        {
        case 1:
            st->flags = (u8)(st->flags | PLATFORM1_TRIGGER_FLAG_01);
            break;
        case 2:
            st->flags = (u8)(st->flags | PLATFORM1_TRIGGER_FLAG_02);
            st->transitionStep = 0;
            (*gObjectTriggerInterface)->setCamVars(0x48, 3, 0, 0);
            break;
        case 3:
            list = ObjList_GetObjects(&idx2, &cnt2);
            for (; idx2 < cnt2; idx2++)
            {
                if ((GameObject*)list[idx2] != self &&
                    ((GameObject*)list[idx2])->anim.seqId == SC_SEQ_TOTEMPOLE)
                {
                    o = list[idx2];
                    ((void (*)(int, int))*(void**)((char*)*((GameObject*)o)->anim.dll + SC_VT_HANDLE_EVENT))(o, 2);
                    break;
                }
            }
            break;
        case 4:
            list = ObjList_GetObjects(&idx3, &cnt3);
            for (; idx3 < cnt3; idx3++)
            {
                if ((GameObject*)list[idx3] != self &&
                    ((GameObject*)list[idx3])->anim.seqId == SC_SEQ_TOTEMPOLE)
                {
                    o = list[idx3];
                    ((void (*)(int, int))*(void**)((char*)*((GameObject*)o)->anim.dll + SC_VT_HANDLE_EVENT))(o, 3);
                    break;
                }
            }
            break;
        case 5:
            if ((u32)st->linkedObject != 0)
            {
                playerObj->anim.currentMoveProgress = lbl_803E5668;
                ((GameObject*)st->linkedObject)->anim.currentMoveProgress = lbl_803E5668;
                ObjAnim_SetCurrentMove(player, PLATFORM1_PLAYER_PULL_MOVE_ID,
                                       playerObj->anim.currentMoveProgress, 0);
                ObjAnim_SetCurrentMove(st->linkedObject, PLATFORM1_IDLE_PULL_MOVE_ID,
                                       ((GameObject*)st->linkedObject)->anim.currentMoveProgress, 0);
                st->prevTrackOffset = st->currentTrackOffset;
            }
            break;
        }
    }
    if ((st->flags & PLATFORM1_TRIGGER_MASK) == 0)
    {
        ret = 0;
    }
    else if (st->loopSfxHandle < 0x19)
    {
        ret = 0;
    }
    else
    {
        if ((*gCameraInterface)->getMode() != 0x48)
        {
            evt.mode = 3;
            evt.flag = 1;
            (*gCameraInterface)->setMode(0x48, 1, 3, 8, &evt, 0, 0xff);
        }
        if (playerObj->anim.currentMove != PLATFORM1_PLAYER_PULL_MOVE_ID)
        {
            ObjAnim_SetCurrentMove(player, PLATFORM1_PLAYER_PULL_MOVE_ID,
                                   playerObj->anim.currentMoveProgress, 0);
        }
        o = st->linkedObject;
        if (((GameObject*)o)->anim.currentMove != PLATFORM1_IDLE_PULL_MOVE_ID)
        {
            ObjAnim_SetCurrentMove(o, PLATFORM1_IDLE_PULL_MOVE_ID,
                                   ((GameObject*)o)->anim.currentMoveProgress, 0);
        }
        animUpdate->hitVolumePair = -1;
        animUpdate->sequenceEventActive = 0;
        Sfx_KeepAliveLoopedObjectSound(obj, PLATFORM1_LOOP_SFX_ID);
        for (i = 0; i < framesThisStep; i++)
        {
            if ((u32)st->linkedObject == 0)
            {
                ret = 0;
                goto done;
            }
            wob1 = (f32)(st->currentTrackOffset + 0xb24) / lbl_803E566C;
            wob2 = lbl_803E5674 * wob1 + lbl_803E5670;
            if (wob2 < lbl_803E5678)
            {
                wob2 = -wob2;
            }
            push = lbl_803E5684 * wob1 + lbl_803E5680;
            push = push * wob2 + lbl_803E567C;
            buttons = getButtonsJustPressedIfNotBusy(0);
            if ((buttons & PAD_BUTTON_A) != 0 && isGameTimerDisabled() == 0)
            {
                st->offsetVelocity = st->offsetVelocity - lbl_803E5688;
            }
            if (st->offsetVelocity < lbl_803E568C)
            {
                st->offsetVelocity = *(const f32*)&lbl_803E568C;
            }
            if (st->currentTrackOffset >= PLATFORM1_TRACK_EXIT_NEG && st->currentTrackOffset <= PLATFORM1_TRACK_EXIT_POS)
            {
                st->currentTrackOffset = (int)((f32)st->currentTrackOffset + st->offsetVelocity);
            }
            diff = ((f32)st->prevTrackOffset - st->currentTrackOffset) / lbl_803E5690;
            if (st->currentTrackOffset < PLATFORM1_TRACK_EXIT_NEG)
            {
                st->transitionStep = 0;
                st->flags = (u8)(st->flags & ~PLATFORM1_TRIGGER_MASK);
                st->flags = (u8)(st->flags | PLATFORM1_FLAG_EXIT_NEGATIVE);
                list = ObjList_GetObjects(&idx4, &cnt4);
                for (; idx4 < cnt4; idx4++)
                {
                    if ((GameObject*)list[idx4] != self &&
                        ((GameObject*)list[idx4])->anim.seqId == SC_SEQ_TOTEMPOLE)
                    {
                        o = list[idx4];
                        ((void (*)(int, int))*(void**)((char*)*((GameObject*)o)->anim.dll + SC_VT_HANDLE_EVENT))(o, 4);
                        break;
                    }
                }
                fn_801DE320(&lbl_803DC070, (int)(fn_8001461C() / lbl_803E5694));
                hudFn_8011f38c(0);
                if (st->loopSfxHandle > 0)
                {
                    ObjSeq_takeXrotChanged(st->loopSfxHandle);
                }
                (*gScreenTransitionInterface)->step(0x14, 1);
                gTotemStrengthDeactivateTimer = 2;
                ret = 4;
                goto done;
            }
            if (st->currentTrackOffset > PLATFORM1_TRACK_EXIT_POS)
            {
                st->transitionStep = 3;
                st->flags = (u8)(st->flags & ~PLATFORM1_TRIGGER_MASK);
                st->flags = (u8)(st->flags | PLATFORM1_FLAG_EXIT_POSITIVE);
                list = ObjList_GetObjects(&idx5, &cnt5);
                for (; idx5 < cnt5; idx5++)
                {
                    if ((GameObject*)list[idx5] != self &&
                        ((GameObject*)list[idx5])->anim.seqId == SC_SEQ_TOTEMPOLE)
                    {
                        o = list[idx5];
                        ((void (*)(int, int))*(void**)((char*)*((GameObject*)o)->anim.dll + SC_VT_HANDLE_EVENT))(o, 4);
                        break;
                    }
                }
                hudFn_8011f38c(0);
                if (st->loopSfxHandle > 0)
                {
                    ObjSeq_takeXrotChanged(st->loopSfxHandle);
                }
                (*gScreenTransitionInterface)->step(0x14, 1);
                gTotemStrengthDeactivateTimer = 2;
                ret = 4;
                goto done;
            }
            if (st->loopSfxHandle > 0)
            {
                (*gObjectTriggerInterface)->setXrot(st->loopSfxHandle, st->currentTrackOffset);
            }
            if (st->offsetVelocity < lbl_803E5690)
            {
                st->offsetVelocity = lbl_803E5698 * push + st->offsetVelocity;
            }
            if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(
                    player, ((f32)st->prevTrackOffset - st->currentTrackOffset) / lbl_803E569C,
                    timeDelta, 0) != 0 &&
                playerObj->anim.currentMoveProgress < lbl_803E5678)
            {
                playerObj->anim.currentMoveProgress = lbl_803E567C + playerObj->anim.currentMoveProgress;
            }
            if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(
                st->linkedObject, ((f32)st->currentTrackOffset - st->prevTrackOffset) / lbl_803E569C,
                timeDelta, 0) != 0)
            {
                t = ((GameObject*)st->linkedObject)->anim.currentMoveProgress;
                if (t < lbl_803E5678)
                {
                    ((GameObject*)st->linkedObject)->anim.currentMoveProgress = lbl_803E567C + t;
                }
            }
            st->prevTrackOffset = st->currentTrackOffset;
        }
        st->playerSfxTimer = st->playerSfxTimer - timeDelta;
        if (st->playerSfxTimer < *(f32*)&lbl_803E5678)
        {
            if (diff < lbl_803E5678)
            {
                st->playerSfxTimer = (f32)(int)
                randomGetRange(0x28, 100);
            }
            else
            {
                st->playerSfxTimer = (f32)(int)
                randomGetRange(0x78, 0xf0);
            }
            Sfx_PlayFromObject(player, PLATFORM1_PLAYER_SFX_ID);
        }
        st->platformSfxTimer = st->platformSfxTimer - timeDelta;
        if (st->platformSfxTimer < *(f32*)&lbl_803E5678)
        {
            if (diff > lbl_803E5678)
            {
                st->platformSfxTimer = (f32)(int)
                randomGetRange(0x28, 100);
            }
            else
            {
                st->platformSfxTimer = (f32)(int)
                randomGetRange(0x78, 0xf0);
            }
            Sfx_PlayFromObject(obj, PLATFORM1_PLATFORM_SFX_ID);
        }
        if (diff < lbl_803E5678)
        {
            absDiff = -diff;
        }
        else
        {
            absDiff = diff;
        }
        vol = (int)(lbl_803E56A0 * absDiff);
        if (vol > 100)
        {
            vol = 100;
        }
        Sfx_SetObjectSfxVolume(obj, PLATFORM1_LOOP_SFX_ID, vol & 0xff, lbl_803E56A4);
        ret = 0;
    }
done:
    return ret;
}

void sc_totemstrength_free(void)
{
}

void sc_totemstrength_hitDetect(void)
{
}

void sc_totemstrength_release(void)
{
}

void sc_totemstrength_initialise(void)
{
}

int sc_totemstrength_getExtraSize(void) { return 0x34; }
int sc_totemstrength_getObjectTypeId(void) { return 0x0; }

void sc_totemstrength_render(void) { objRenderFn_8003b8f4(lbl_803E567C); }

void sc_totemstrength_init(int* obj)
{
    GameObject* self = (GameObject*)obj;
    Platform1State* st = self->extra;
    self->animEventCallback = platform1_control;
    self->objectFlags |= (SC_TOTEMSTRENGTH_OBJFLAG_HIDDEN | SC_TOTEMSTRENGTH_OBJFLAG_HITDETECT_DISABLED);
    self->anim.rotX = (s16) - 10496;
    st->currentTrackOffset = -10496;
    st->transitionStep = 0;
    st->linkedObject = 0;
    st->savedPosX = self->anim.localPosX;
    st->savedPosY = self->anim.localPosY;
    st->savedPosZ = self->anim.localPosZ;
}

/* sc_totemstrength_update: drive the
 * tug-of-war intro/outro sequencing once map event 0xe reaches state 6. */
void sc_totemstrength_update(u8* obj)
{
    Platform1State* st = ((GameObject*)obj)->extra;
    u8 mapMode;
    s16 step;
    u8 flags;
    f32 zero;

    Obj_GetPlayerObject();
    GameBit_Set(0xf1d, 0);
    mapMode = (*gMapEventInterface)->getMapAct(0xe);
    if (mapMode == 6)
    {
        if ((st->flags & PLATFORM1_FLAG_ACTIVE) != 0)
        {
            if (st->loopSfxHandle > 0)
            {
                (*gObjectTriggerInterface)->endSequence(st->loopSfxHandle);
                ObjSeq_takeXrotChanged(st->loopSfxHandle);
            }
            if (gTotemStrengthDeactivateTimer-- == 0)
            {
                st->flags = (u8)(st->flags & ~PLATFORM1_FLAG_ACTIVE);
                ((GameObject*)obj)->anim.localPosX = st->savedPosX;
                ((GameObject*)obj)->anim.localPosY = st->savedPosY;
                ((GameObject*)obj)->anim.localPosZ = st->savedPosZ;
                st->linkedObject = 0;
                ((GameObject*)obj)->anim.rotX = -0x2900;
                st->currentTrackOffset = -0x2900;
                flags = st->flags;
                if ((flags & PLATFORM1_FLAG_EXIT_NEGATIVE) != 0)
                {
                    GameBit_Set(0x784, 1);
                    st->loopSfxHandle = -1;
                    st->flags = (u8)(st->flags & ~PLATFORM1_TRIGGER_MASK);
                    st->flags = (u8)(st->flags & ~PLATFORM1_FLAG_EXIT_NEGATIVE);
                }
                else if ((flags & PLATFORM1_FLAG_EXIT_POSITIVE) != 0)
                {
                    st->flags = (u8)(flags & ~PLATFORM1_FLAG_EXIT_POSITIVE);
                    st->loopSfxHandle = -1;
                    GameBit_Set(0x786, 1);
                }
            }
        }
        else if ((st->flags & PLATFORM1_TRIGGER_FLAG_02) != 0)
        {
            step = st->transitionStep;
            if (step == 0)
            {
                ((GameObject*)obj)->anim.rotX = -0x2900;
                st->currentTrackOffset = -0x2900;
                st->prevTrackOffset = st->currentTrackOffset;
                zero = lbl_803E5678;
                st->motionValue0 = lbl_803E5678;
                st->offsetVelocity = zero;
                st->transitionStep = 1;
                st->flags = (u8)(st->flags & ~PLATFORM1_TRIGGER_FLAG_01);
            }
            else if (step == 1)
            {
                GameBit_Set(0xf1d, 1);
                hudFn_8011f38c(1);
                st->loopSfxHandle =
                    (*gObjectTriggerInterface)->runSequence(0, obj, -1);
            }
            else if (step == 2)
            {
                st->transitionStep = 0;
            }
            else if (step == 3)
            {
                st->transitionStep = 0;
            }
        }
    }
}

ObjectDescriptor gFElevControlObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)FElevControl_initialise,
    (ObjectDescriptorCallback)FElevControl_release,
    0,
    (ObjectDescriptorCallback)FElevControl_init,
    (ObjectDescriptorCallback)FElevControl_update,
    (ObjectDescriptorCallback)FElevControl_hitDetect,
    (ObjectDescriptorCallback)FElevControl_render,
    (ObjectDescriptorCallback)FElevControl_free,
    (ObjectDescriptorCallback)FElevControl_getObjectTypeId,
    FElevControl_getExtraSize,
};
