#include "main/dll/paymentkiosk.h"
#include "main/game_object.h"
#include "main/dll/VF/platform1.h"
#include "main/mapEventTypes.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"
#include "main/screen_transition.h"

extern undefined4 Sfx_SetObjectSfxVolume();
extern undefined4 Sfx_PlayFromObject();
extern undefined4 Sfx_KeepAliveLoopedObjectSound();
extern double FUN_80006b34();
extern byte FUN_80006b44();
extern uint FUN_80006bf8();
extern uint randomGetRange();
extern uint FUN_80017a98();
extern int ObjList_GetObjects();
extern int FUN_8002fc3c();
extern undefined4 FUN_80080eec();
extern undefined4 FUN_8011e800();
extern undefined4 setAButtonIcon();
extern uint FUN_80286840();
extern undefined4 FUN_8028688c();
extern u8 *Obj_GetPlayerObject(void);

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d0;
extern undefined4 DAT_803de890;
extern f64 DOUBLE_803e6340;
extern f32 lbl_803DC074;
extern f32 lbl_803E6300;
extern f32 lbl_803E6304;
extern f32 lbl_803E6308;
extern f32 lbl_803E630C;
extern f32 lbl_803E6310;
extern f32 lbl_803E6314;
extern f32 lbl_803E6318;
extern f32 lbl_803E631C;
extern f32 lbl_803E6320;
extern f32 lbl_803E6324;
extern f32 lbl_803E6328;
extern f32 lbl_803E632C;
extern f32 lbl_803E6330;
extern f32 lbl_803E6334;
extern f32 lbl_803E6338;
extern f32 lbl_803E633C;

#define PLATFORM1_ANCHOR_SEQ_ID 0x3ff
#define PLATFORM1_PEER_SEQ_ID 0x282
#define PLATFORM1_PLAYER_PULL_MOVE_ID 0x401
#define PLATFORM1_IDLE_PULL_MOVE_ID 0

#define PLATFORM1_LOOP_SFX_ID 0x3af
#define PLATFORM1_PLAYER_SFX_ID 0x13a
#define PLATFORM1_PLATFORM_SFX_ID 0x4a3

/*
 * --INFO--
 *
 * Function: platform1_control
 * EN v1.0 Address: 0x801DE430
 * EN v1.0 Size: 3368b
 * EN v1.1 Address: 0x801DEA20
 * EN v1.1 Size: 2596b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u32  getButtonsJustPressedIfNotBusy(int pad);
extern int  isGameTimerDisabled(void);
extern f64  fn_8001461C(void);
extern void fn_801DE320(void *dst, int val);
extern int ObjSeq_takeXrotChanged(int index);
extern void hudFn_8011f38c(int n);
extern int *gCameraInterface;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern ScreenTransitionInterface **gScreenTransitionInterface;
extern int  lbl_803DDC10;
extern int  lbl_803DC070;
extern u8   framesThisStep;
extern f32  timeDelta;
extern f32  lbl_803E5668;
extern f32  lbl_803E566C;
extern f32  lbl_803E5670;
extern f32  lbl_803E5674;
extern f32  lbl_803E5678;
extern f32  lbl_803E567C;
extern f32  lbl_803E5680;
extern f32  lbl_803E5684;
extern f32  lbl_803E5688;
extern f32  lbl_803E568C;
extern f32  lbl_803E5690;
extern f32  lbl_803E5694;
extern f32  lbl_803E5698;
extern f32  lbl_803E569C;
extern f32  lbl_803E56A0;
extern f32  lbl_803E56A4;

/* EN v1.0 0x801DE430  size: 2596b  platform1_control: tug-of-war rope
 * minigame. Resolves the anchor object, applies sequence events, then per
 * frame works the rope position from A-press mashing, runs both pull anims
 * and grunt/creak sfx, and ends the game through the screen transition
 * when either side wins. */
#pragma scheduling off
#pragma peephole off
int platform1_control(int obj, int p2, u8 *data)
{
    GameObject *self;
    Platform1State *st;
    GameObject *playerObj;
    int player;
    int *list;
    int *p;
    int o;
    int i;
    u8 ev;
    u32 buttons;
    f32 wob1, wob2, push;
    f32 diff;
    f32 absDiff;
    f32 t;
    int vol;
    int ret;
    f32 c566C, c5674, c5670, c5678, c5684, c5680, c567C, c568C, c5690, c569C;
    int idx1, cnt1, idx2, cnt2, idx3, cnt3, idx4, cnt4, idx5, cnt5;
    struct {
        int mode;
        u8 flag;
    } evt;

    self = (GameObject *)obj;
    st = self->extra;
    playerObj = (GameObject *)Obj_GetPlayerObject();
    player = (int)playerObj;
    st->flags = (u8)(st->flags | PLATFORM1_FLAG_ACTIVE);
    setAButtonIcon(0xf);
    lbl_803DDC10 = 0;
    st->linkedObject = 0;
    list = (int *)ObjList_GetObjects(&idx1, &cnt1);
    while (idx1 < cnt1) {
        st->linkedObject = list[idx1++];
        if (((GameObject *)st->linkedObject)->anim.seqId == PLATFORM1_ANCHOR_SEQ_ID) {
            idx1 = cnt1;
        }
    }
    for (i = 0; i < data[0x8b]; i++) {
        ev = data[i + 0x81];
        switch (ev) {
        case 1:
            st->flags = (u8)(st->flags | PLATFORM1_TRIGGER_FLAG_01);
            break;
        case 2:
            st->flags = (u8)(st->flags | PLATFORM1_TRIGGER_FLAG_02);
            st->transitionStep = 0;
            (*gObjectTriggerInterface)->setCamVars(0x48, 3, 0, 0);
            break;
        case 3:
            list = (int *)ObjList_GetObjects(&idx2, &cnt2);
            p = &list[idx2];
            for (; idx2 < cnt2; idx2++) {
                if ((u32)*p != (u32)obj && ((GameObject *)*p)->anim.seqId == PLATFORM1_PEER_SEQ_ID) {
                    o = list[idx2];
                    ((void (*)(int, int))*(void **)((char *)*((GameObject *)o)->anim.dll + 0x20))(o, 2);
                    break;
                }
                p++;
            }
            break;
        case 4:
            list = (int *)ObjList_GetObjects(&idx3, &cnt3);
            p = &list[idx3];
            for (; idx3 < cnt3; idx3++) {
                if ((u32)*p != (u32)obj && ((GameObject *)*p)->anim.seqId == PLATFORM1_PEER_SEQ_ID) {
                    o = list[idx3];
                    ((void (*)(int, int))*(void **)((char *)*((GameObject *)o)->anim.dll + 0x20))(o, 3);
                    break;
                }
                p++;
            }
            break;
        case 5:
            if ((u32)st->linkedObject != 0) {
                playerObj->anim.currentMoveProgress = lbl_803E5668;
                ((GameObject *)st->linkedObject)->anim.currentMoveProgress = lbl_803E5668;
                ObjAnim_SetCurrentMove(player, PLATFORM1_PLAYER_PULL_MOVE_ID,
                                       playerObj->anim.currentMoveProgress, 0);
                ObjAnim_SetCurrentMove(st->linkedObject, PLATFORM1_IDLE_PULL_MOVE_ID,
                                       ((GameObject *)st->linkedObject)->anim.currentMoveProgress, 0);
                st->prevTrackOffset = st->currentTrackOffset;
            }
            break;
        }
    }
    if ((st->flags & PLATFORM1_TRIGGER_MASK) == 0) {
        ret = 0;
    } else if (st->loopSfxHandle < 0x19) {
        ret = 0;
    } else {
        if ((*(int (**)(void))((char *)(*gCameraInterface) + 0x10))() != 0x48) {
            evt.mode = 3;
            evt.flag = 1;
            (*(void (**)(int, int, int, int, void *, int, int))((char *)(*gCameraInterface) + 0x1c))(0x48, 1, 3, 8, &evt, 0, 0xff);
        }
        if (playerObj->anim.currentMove != PLATFORM1_PLAYER_PULL_MOVE_ID) {
            ObjAnim_SetCurrentMove(player, PLATFORM1_PLAYER_PULL_MOVE_ID,
                                   playerObj->anim.currentMoveProgress, 0);
        }
        o = st->linkedObject;
        if (((GameObject *)o)->anim.currentMove != PLATFORM1_IDLE_PULL_MOVE_ID) {
            ObjAnim_SetCurrentMove(o, PLATFORM1_IDLE_PULL_MOVE_ID,
                                   ((GameObject *)o)->anim.currentMoveProgress, 0);
        }
        *(u16 *)(data + 0x6e) = 0xffff;
        data[0x56] = 0;
        Sfx_KeepAliveLoopedObjectSound(obj, PLATFORM1_LOOP_SFX_ID);
        c566C = lbl_803E566C;
        c5674 = lbl_803E5674;
        c5670 = lbl_803E5670;
        c5678 = lbl_803E5678;
        c5684 = lbl_803E5684;
        c5680 = lbl_803E5680;
        c567C = lbl_803E567C;
        c568C = lbl_803E568C;
        c5690 = lbl_803E5690;
        c569C = lbl_803E569C;
        for (i = 0; i < framesThisStep; i++) {
            if ((u32)st->linkedObject == 0) {
                ret = 0;
                goto done;
            }
            wob1 = (f32)(st->currentTrackOffset + 0xb24) / c566C;
            wob2 = c5674 * wob1 + c5670;
            if (wob2 < c5678) {
                wob2 = -wob2;
            }
            push = (c5684 * wob1 + c5680) * wob2 + c567C;
            buttons = getButtonsJustPressedIfNotBusy(0);
            if ((buttons & 0x100) != 0 && isGameTimerDisabled() == 0) {
                st->offsetVelocity = st->offsetVelocity - lbl_803E5688;
            }
            if (st->offsetVelocity < c568C) {
                st->offsetVelocity = c568C;
            }
            if (st->currentTrackOffset > -0x46de && st->currentTrackOffset < -0xb23) {
                st->currentTrackOffset = (int)((f32)st->currentTrackOffset + st->offsetVelocity);
            }
            diff = ((f32)st->prevTrackOffset - (f32)st->currentTrackOffset) / c5690;
            if (st->currentTrackOffset < -0x46dc) {
                st->transitionStep = 0;
                st->flags = (u8)(st->flags & ~PLATFORM1_TRIGGER_MASK);
                st->flags = (u8)(st->flags | PLATFORM1_FLAG_EXIT_NEGATIVE);
                list = (int *)ObjList_GetObjects(&idx4, &cnt4);
                p = &list[idx4];
                for (; idx4 < cnt4; idx4++) {
                    if ((u32)*p != (u32)obj && ((GameObject *)*p)->anim.seqId == PLATFORM1_PEER_SEQ_ID) {
                        o = list[idx4];
                        ((void (*)(int, int))*(void **)((char *)*((GameObject *)o)->anim.dll + 0x20))(o, 4);
                        break;
                    }
                    p++;
                }
                fn_801DE320(&lbl_803DC070, (int)(fn_8001461C() / lbl_803E5694));
                hudFn_8011f38c(0);
                if (st->loopSfxHandle > 0) {
                    ObjSeq_takeXrotChanged(st->loopSfxHandle);
                }
                (*gScreenTransitionInterface)->step(0x14, 1);
                lbl_803DDC10 = 2;
                ret = 4;
                goto done;
            }
            if (st->currentTrackOffset > -0xb24) {
                st->transitionStep = 3;
                st->flags = (u8)(st->flags & ~PLATFORM1_TRIGGER_MASK);
                st->flags = (u8)(st->flags | PLATFORM1_FLAG_EXIT_POSITIVE);
                list = (int *)ObjList_GetObjects(&idx5, &cnt5);
                p = &list[idx5];
                for (; idx5 < cnt5; idx5++) {
                    if ((u32)*p != (u32)obj && ((GameObject *)*p)->anim.seqId == PLATFORM1_PEER_SEQ_ID) {
                        o = list[idx5];
                        ((void (*)(int, int))*(void **)((char *)*((GameObject *)o)->anim.dll + 0x20))(o, 4);
                        break;
                    }
                    p++;
                }
                hudFn_8011f38c(0);
                if (st->loopSfxHandle > 0) {
                    ObjSeq_takeXrotChanged(st->loopSfxHandle);
                }
                (*gScreenTransitionInterface)->step(0x14, 1);
                lbl_803DDC10 = 2;
                ret = 4;
                goto done;
            }
            if (st->loopSfxHandle > 0) {
                (*gObjectTriggerInterface)->setXrot(st->loopSfxHandle, st->currentTrackOffset);
            }
            if (st->offsetVelocity < c5690) {
                st->offsetVelocity = lbl_803E5698 * push + st->offsetVelocity;
            }
            if (ObjAnim_AdvanceCurrentMove(((f32)st->prevTrackOffset - (f32)st->currentTrackOffset) / c569C,
                                           timeDelta, player, 0) != 0 &&
                playerObj->anim.currentMoveProgress < c5678) {
                playerObj->anim.currentMoveProgress = c567C + playerObj->anim.currentMoveProgress;
            }
            if (ObjAnim_AdvanceCurrentMove(((f32)st->currentTrackOffset - (f32)st->prevTrackOffset) / c569C,
                                           timeDelta, st->linkedObject, 0) != 0) {
                t = ((GameObject *)st->linkedObject)->anim.currentMoveProgress;
                if (t < c5678) {
                    ((GameObject *)st->linkedObject)->anim.currentMoveProgress = c567C + t;
                }
            }
            st->prevTrackOffset = st->currentTrackOffset;
        }
        st->playerSfxTimer = st->playerSfxTimer - timeDelta;
        if (st->playerSfxTimer < lbl_803E5678) {
            if (lbl_803E5678 <= diff) {
                st->playerSfxTimer = (f32)(int)randomGetRange(0x78, 0xf0);
            } else {
                st->playerSfxTimer = (f32)(int)randomGetRange(0x28, 100);
            }
            Sfx_PlayFromObject(player, PLATFORM1_PLAYER_SFX_ID);
        }
        st->platformSfxTimer = st->platformSfxTimer - timeDelta;
        if (st->platformSfxTimer < lbl_803E5678) {
            if (diff <= lbl_803E5678) {
                st->platformSfxTimer = (f32)(int)randomGetRange(0x78, 0xf0);
            } else {
                st->platformSfxTimer = (f32)(int)randomGetRange(0x28, 100);
            }
            Sfx_PlayFromObject(obj, PLATFORM1_PLATFORM_SFX_ID);
        }
        if (diff < lbl_803E5678) {
            absDiff = -diff;
        } else {
            absDiff = diff;
        }
        vol = (int)(lbl_803E56A0 * absDiff);
        if (vol > 100) {
            vol = 100;
        }
        Sfx_SetObjectSfxVolume(obj, PLATFORM1_LOOP_SFX_ID, vol & 0xff, lbl_803E56A4);
        ret = 0;
    }
done:
    return ret;
}
#pragma peephole reset
#pragma scheduling reset


/* Trivial 4b 0-arg blr leaves. */
void sc_totemstrength_free(void) {}
void sc_totemstrength_hitDetect(void) {}
void sc_totemstrength_release(void) {}
void sc_totemstrength_initialise(void) {}
void paymentkiosk_free(void) {}
void paymentkiosk_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int sc_totemstrength_getExtraSize(void) { return 0x34; }
int sc_totemstrength_getObjectTypeId(void) { return 0x0; }
int paymentkiosk_getExtraSize(void) { return 0x3; }
int paymentkiosk_getObjectTypeId(void) { return 0x1; }

/* render-with-fn(lbl) (no visibility check). */
extern void objRenderFn_8003b8f4(f32);
#pragma scheduling off
#pragma peephole off
void sc_totemstrength_render(void) { objRenderFn_8003b8f4(lbl_803E567C); }
void paymentkiosk_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }
void sc_totemstrength_init(int *obj) {
    GameObject *self = (GameObject *)obj;
    Platform1State *st = self->extra;
    self->animEventCallback = (void *)platform1_control;
    self->objectFlags |= 0x6000;
    self->anim.rotX = (s16)-10496;
    st->currentTrackOffset = -10496;
    st->transitionStep = 0;
    st->linkedObject = 0;
    st->savedPosX = self->anim.localPosX;
    st->savedPosY = self->anim.localPosY;
    st->savedPosZ = self->anim.localPosZ;
}
#pragma peephole reset
#pragma scheduling reset

extern void GameBit_Set(int eventId, int value);
extern u32  GameBit_Get(int eventId);
extern MapEventInterface **gMapEventInterface;
extern u32  getButtonsJustPressed(int pad);
extern int  playerGetMoney(int player);
extern void playerAddMoney(int player, int amount);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShow(int id);
extern void objRenderFn_80041018(int obj);
typedef struct KioskTextPair {
    int approachText;
    int poorText;
} KioskTextPair;
extern KioskTextPair lbl_80327AF0[];

/* EN v1.0 0x801DEE90  size: 548b  sc_totemstrength_update: drive the
 * tug-of-war intro/outro sequencing once map event 0xe reaches state 6. */
#pragma scheduling off
#pragma peephole off
void sc_totemstrength_update(u8 *obj)
{
    Platform1State *st = ((GameObject *)obj)->extra;
    u8 t;
    s16 step;
    u8 b;
    f32 fz;

    Obj_GetPlayerObject();
    GameBit_Set(0xf1d, 0);
    t = (*gMapEventInterface)->getMode(0xe);
    if (t == 6) {
        if ((st->flags & PLATFORM1_FLAG_ACTIVE) != 0) {
            if (st->loopSfxHandle > 0) {
                (*gObjectTriggerInterface)->endSequence(st->loopSfxHandle);
                ObjSeq_takeXrotChanged(st->loopSfxHandle);
            }
            if (lbl_803DDC10-- == 0) {
                st->flags = (u8)(st->flags & ~PLATFORM1_FLAG_ACTIVE);
                ((GameObject *)obj)->anim.localPosX = st->savedPosX;
                ((GameObject *)obj)->anim.localPosY = st->savedPosY;
                ((GameObject *)obj)->anim.localPosZ = st->savedPosZ;
                st->linkedObject = 0;
                *(s16 *)obj = -0x2900;
                st->currentTrackOffset = -0x2900;
                b = st->flags;
                if ((b & PLATFORM1_FLAG_EXIT_NEGATIVE) != 0) {
                    GameBit_Set(0x784, 1);
                    st->loopSfxHandle = -1;
                    st->flags = (u8)(st->flags & ~PLATFORM1_TRIGGER_MASK);
                    st->flags = (u8)(st->flags & ~PLATFORM1_FLAG_EXIT_NEGATIVE);
                } else if ((b & PLATFORM1_FLAG_EXIT_POSITIVE) != 0) {
                    st->flags = (u8)(b & ~PLATFORM1_FLAG_EXIT_POSITIVE);
                    st->loopSfxHandle = -1;
                    GameBit_Set(0x786, 1);
                }
            }
        } else if ((st->flags & PLATFORM1_TRIGGER_FLAG_02) != 0) {
            step = st->transitionStep;
            if (step == 0) {
                *(s16 *)obj = -0x2900;
                st->currentTrackOffset = -0x2900;
                st->prevTrackOffset = st->currentTrackOffset;
                fz = lbl_803E5678;
                st->motionValue0 = lbl_803E5678;
                st->offsetVelocity = fz;
                st->transitionStep = 1;
                st->flags = (u8)(st->flags & ~PLATFORM1_TRIGGER_FLAG_01);
            } else if (step == 1) {
                GameBit_Set(0xf1d, 1);
                hudFn_8011f38c(1);
                st->loopSfxHandle =
                    (*gObjectTriggerInterface)->runSequence(0, obj, -1);
            } else if (step == 2) {
                st->transitionStep = 0;
            } else if (step == 3) {
                st->transitionStep = 0;
            }
        }
    }
}

/* EN v1.0 0x801DF110  size: 220b  PaymentKiosk_testEvent. */
u32 PaymentKiosk_testEvent(int obj, int p2, int ev)
{
    PaymentKioskMapData *setup = (PaymentKioskMapData *)((GameObject *)obj)->anim.placementData;
    PaymentKioskState *st = ((GameObject *)obj)->extra;
    int player;
    u32 r;

    player = (int)Obj_GetPlayerObject();
    r = getButtonsJustPressed(0);
    if ((r & 0x100) == 0) {
        r = 0;
    } else {
        st->promptState = 0;
        if (playerGetMoney(player) >= setup->price) {
            r = 1;
            st->promptState = 0;
        } else {
            r = 0;
            st->promptState = 2;
        }
        switch (ev) {
        case 0x14:
            r = !(1 - r);
            break;
        case 0x15:
            r = !r;
            break;
        default:
            r = 0;
            break;
        }
    }
    return r;
}

/* EN v1.0 0x801DF1EC  size: 280b  PaymentKiosk_SeqFn. */
int PaymentKiosk_SeqFn(int obj, int p2, u8 *data)
{
    PaymentKioskState *st = ((GameObject *)obj)->extra;
    PaymentKioskMapData *setup = (PaymentKioskMapData *)((GameObject *)obj)->anim.placementData;
    int player;
    int i;
    u8 ev;

    player = (int)Obj_GetPlayerObject();
    *(void **)(data + 0xec) = (void *)PaymentKiosk_testEvent;
    for (i = 0; i < data[0x8b]; i++) {
        ev = data[i + 0x81];
        switch (ev) {
        case 2:
            GameBit_Set(setup->gameBit, 1);
            playerAddMoney(player, -setup->price);
            st->payState = 2;
            break;
        case 1:
            st->promptState = 1;
            break;
        }
    }
    gameTextSetColor(0xff, 0xff, 0xff, 0xff);
    if (st->promptState == 1) {
        gameTextShow(lbl_80327AF0[st->textVariant].approachText);
    } else if (st->promptState == 2) {
        gameTextShow(lbl_80327AF0[st->textVariant].poorText);
    }
    return 0;
}

/* EN v1.0 0x801DF328  size: 276b  paymentkiosk_update. */
void paymentkiosk_update(int obj)
{
    PaymentKioskState *st = ((GameObject *)obj)->extra;
    PaymentKioskMapData *setup = (PaymentKioskMapData *)((GameObject *)obj)->anim.placementData;
    u8 b = st->payState;

    switch (b) {
    case 0:
        if (setup->gameBit != -1 && GameBit_Get(setup->gameBit) != 0) {
            st->payState = 2;
        } else {
            st->payState = 1;
        }
        break;
    case 1:
        if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 1) != 0) {
            (*gObjectTriggerInterface)->runSequence(0, (void *)obj, -1);
        }
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~8);
        break;
    case 2:
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 8);
        break;
    }
    st->promptState = 0;
    if ((((ObjAnimComponent *)obj)->modelInstance->flags & 1) != 0 && *(void **)(obj + 0x74) != NULL) {
        objRenderFn_80041018(obj);
    }
}
#pragma peephole reset
#pragma scheduling reset
