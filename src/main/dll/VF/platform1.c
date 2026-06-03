#include "ghidra_import.h"
#include "main/dll/VF/platform1.h"
#include "main/objanim.h"

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
extern undefined4 sc_totemstrength_sortCompletionGameBits();
extern uint FUN_80286840();
extern undefined4 FUN_8028688c();
extern u8 *Obj_GetPlayerObject(void);

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
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

#define PLATFORM1_OBJECT_TYPE_OFFSET 0x46
#define PLATFORM1_TRACK_VALUE_OFFSET 0x98
#define PLATFORM1_MODEL_ID_OFFSET 0xa0
#define PLATFORM1_STATE_OFFSET 0xb8

#define PLATFORM1_ANCHOR_OBJECT_TYPE 0x3ff
#define PLATFORM1_PEER_OBJECT_TYPE 0x282
#define PLATFORM1_ACTIVE_MODEL_ID 0x401
#define PLATFORM1_IDLE_MODEL_ID 0

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
extern void fn_800882C8(void);
extern void hudFn_8011f38c(int n);
extern int *gCameraInterface;
extern int *gObjectTriggerInterface;
extern int *gScreenTransitionInterface;
extern u8   lbl_803DDC10;
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
    Platform1State *st;
    int player;
    int *list;
    int *p;
    int o;
    int i;
    u8 ev;
    u32 buttons;
    f32 wob1, wob2, push;
    f32 diff;
    f32 t;
    u32 vol;
    int ret;
    int idx1, cnt1, idx2, cnt2, idx3, cnt3, idx4, cnt4, idx5, cnt5;
    struct {
        int mode;
        u8 flag;
    } evt;

    st = *(Platform1State **)(obj + PLATFORM1_STATE_OFFSET);
    player = (int)Obj_GetPlayerObject();
    st->flags = (u8)(st->flags | PLATFORM1_FLAG_ACTIVE);
    setAButtonIcon(0xf);
    lbl_803DDC10 = 0;
    st->linkedObject = 0;
    list = (int *)ObjList_GetObjects(&idx1, &cnt1);
    while (idx1 < cnt1) {
        st->linkedObject = list[idx1];
        idx1++;
        if (*(s16 *)(st->linkedObject + PLATFORM1_OBJECT_TYPE_OFFSET) == PLATFORM1_ANCHOR_OBJECT_TYPE) {
            idx1 = cnt1;
        }
    }
    for (i = 0; i < data[0x8b]; i++) {
        ev = data[i + 0x81];
        switch (ev) {
        case 3:
            list = (int *)ObjList_GetObjects(&idx2, &cnt2);
            p = &list[idx2];
            for (; idx2 < cnt2; idx2++) {
                if (*p != obj && *(s16 *)(*p + PLATFORM1_OBJECT_TYPE_OFFSET) == PLATFORM1_PEER_OBJECT_TYPE) {
                    o = list[idx2];
                    ((void (*)(int, int))*(void **)(*(int *)(*(int *)(o + 0x68)) + 0x20))(o, 2);
                    break;
                }
                p++;
            }
            break;
        case 1:
            st->flags = (u8)(st->flags | PLATFORM1_TRIGGER_FLAG_01);
            break;
        case 2:
            st->flags = (u8)(st->flags | PLATFORM1_TRIGGER_FLAG_02);
            st->transitionStep = 0;
            ((void (*)(int, int, int, int))*(void **)((char *)(*gObjectTriggerInterface) + 0x50))(0x48, 3, 0, 0);
            break;
        case 5:
            if (st->linkedObject != 0) {
                *(f32 *)(player + PLATFORM1_TRACK_VALUE_OFFSET) = lbl_803E5668;
                *(f32 *)(st->linkedObject + PLATFORM1_TRACK_VALUE_OFFSET) = lbl_803E5668;
                ObjAnim_SetCurrentMove(player, PLATFORM1_ACTIVE_MODEL_ID,
                                       *(f32 *)(player + PLATFORM1_TRACK_VALUE_OFFSET), 0);
                ObjAnim_SetCurrentMove(st->linkedObject, PLATFORM1_IDLE_MODEL_ID,
                                       *(f32 *)(st->linkedObject + PLATFORM1_TRACK_VALUE_OFFSET), 0);
                st->prevTrackOffset = st->currentTrackOffset;
            }
            break;
        case 4:
            list = (int *)ObjList_GetObjects(&idx3, &cnt3);
            p = &list[idx3];
            for (; idx3 < cnt3; idx3++) {
                if (*p != obj && *(s16 *)(*p + PLATFORM1_OBJECT_TYPE_OFFSET) == PLATFORM1_PEER_OBJECT_TYPE) {
                    o = list[idx3];
                    ((void (*)(int, int))*(void **)(*(int *)(*(int *)(o + 0x68)) + 0x20))(o, 3);
                    break;
                }
                p++;
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
        if (*(s16 *)(player + PLATFORM1_MODEL_ID_OFFSET) != PLATFORM1_ACTIVE_MODEL_ID) {
            ObjAnim_SetCurrentMove(player, PLATFORM1_ACTIVE_MODEL_ID,
                                   *(f32 *)(player + PLATFORM1_TRACK_VALUE_OFFSET), 0);
        }
        o = st->linkedObject;
        if (*(s16 *)(o + PLATFORM1_MODEL_ID_OFFSET) != PLATFORM1_IDLE_MODEL_ID) {
            ObjAnim_SetCurrentMove(o, PLATFORM1_IDLE_MODEL_ID,
                                   *(f32 *)(o + PLATFORM1_TRACK_VALUE_OFFSET), 0);
        }
        *(u16 *)(data + 0x6e) = 0xffff;
        data[0x56] = 0;
        Sfx_KeepAliveLoopedObjectSound(obj, PLATFORM1_LOOP_SFX_ID);
        for (i = 0; i < framesThisStep; i++) {
            if (st->linkedObject == 0) {
                ret = 0;
                goto done;
            }
            wob1 = (f32)(st->currentTrackOffset + 0xb24) / lbl_803E566C;
            wob2 = lbl_803E5674 * wob1 + lbl_803E5670;
            if (wob2 < lbl_803E5678) {
                wob2 = -wob2;
            }
            push = (lbl_803E5684 * wob1 + lbl_803E5680) * wob2 + lbl_803E567C;
            buttons = getButtonsJustPressedIfNotBusy(0);
            if ((buttons & 0x100) != 0 && isGameTimerDisabled() == 0) {
                st->offsetVelocity = st->offsetVelocity - lbl_803E5688;
            }
            if (st->offsetVelocity < lbl_803E568C) {
                st->offsetVelocity = lbl_803E568C;
            }
            if (st->currentTrackOffset > -0x46de && st->currentTrackOffset < -0xb23) {
                st->currentTrackOffset = (int)((f32)st->currentTrackOffset + st->offsetVelocity);
            }
            diff = ((f32)st->prevTrackOffset - (f32)st->currentTrackOffset) / lbl_803E5690;
            if (st->currentTrackOffset < -0x46dc) {
                st->transitionStep = 0;
                st->flags = (u8)(st->flags & ~PLATFORM1_TRIGGER_MASK);
                st->flags = (u8)(st->flags | PLATFORM1_FLAG_EXIT_NEGATIVE);
                list = (int *)ObjList_GetObjects(&idx4, &cnt4);
                p = &list[idx4];
                for (; idx4 < cnt4; idx4++) {
                    if (*p != obj && *(s16 *)(*p + PLATFORM1_OBJECT_TYPE_OFFSET) == PLATFORM1_PEER_OBJECT_TYPE) {
                        o = list[idx4];
                        ((void (*)(int, int))*(void **)(*(int *)(*(int *)(o + 0x68)) + 0x20))(o, 4);
                        break;
                    }
                    p++;
                }
                fn_801DE320(&lbl_803DC070, (int)(fn_8001461C() / lbl_803E5694));
                hudFn_8011f38c(0);
                if (st->loopSfxHandle > 0) {
                    fn_800882C8();
                }
                (*(void (**)(int, int))((char *)(*gScreenTransitionInterface) + 0xc))(0x14, 1);
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
                    if (*p != obj && *(s16 *)(*p + PLATFORM1_OBJECT_TYPE_OFFSET) == PLATFORM1_PEER_OBJECT_TYPE) {
                        o = list[idx5];
                        ((void (*)(int, int))*(void **)(*(int *)(*(int *)(o + 0x68)) + 0x20))(o, 4);
                        break;
                    }
                    p++;
                }
                hudFn_8011f38c(0);
                if (st->loopSfxHandle > 0) {
                    fn_800882C8();
                }
                (*(void (**)(int, int))((char *)(*gScreenTransitionInterface) + 0xc))(0x14, 1);
                lbl_803DDC10 = 2;
                ret = 4;
                goto done;
            }
            if (st->loopSfxHandle > 0) {
                ((void (*)(void))*(void **)((char *)(*gObjectTriggerInterface) + 0x74))();
            }
            if (st->offsetVelocity < lbl_803E5690) {
                st->offsetVelocity = lbl_803E5698 * push + st->offsetVelocity;
            }
            if (ObjAnim_AdvanceCurrentMove(((f32)st->prevTrackOffset - (f32)st->currentTrackOffset) / lbl_803E569C,
                                           timeDelta, player, 0) != 0 &&
                *(f32 *)(player + PLATFORM1_TRACK_VALUE_OFFSET) < lbl_803E5678) {
                *(f32 *)(player + PLATFORM1_TRACK_VALUE_OFFSET) =
                    lbl_803E567C + *(f32 *)(player + PLATFORM1_TRACK_VALUE_OFFSET);
            }
            if (ObjAnim_AdvanceCurrentMove(((f32)st->currentTrackOffset - (f32)st->prevTrackOffset) / lbl_803E569C,
                                           timeDelta, st->linkedObject, 0) != 0) {
                t = *(f32 *)(st->linkedObject + PLATFORM1_TRACK_VALUE_OFFSET);
                if (t < lbl_803E5678) {
                    *(f32 *)(st->linkedObject + PLATFORM1_TRACK_VALUE_OFFSET) = lbl_803E567C + t;
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
            diff = -diff;
        }
        vol = (u32)(lbl_803E56A0 * diff);
        if ((int)vol > 100) {
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
extern f32 lbl_803E567C;
extern void objRenderFn_8003b8f4(f32);
#pragma scheduling off
#pragma peephole off
void sc_totemstrength_render(void) { objRenderFn_8003b8f4(lbl_803E567C); }
void paymentkiosk_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }
void sc_totemstrength_init(int *obj) {
    int *inner = *(int **)((char *)obj + 0xb8);
    *(int *)((char *)obj + 0xbc) = (int)&platform1_control;
    *(u16 *)((char *)obj + 0xb0) |= 0x6000;
    *(s16 *)obj = (s16)-10496;
    inner[8] = -10496;
    *(s16 *)((char *)inner + 0x2e) = 0;
    inner[0] = 0;
    *(f32 *)((char *)inner + 0xc) = *(f32 *)((char *)obj + 0xc);
    *(f32 *)((char *)inner + 0x10) = *(f32 *)((char *)obj + 0x10);
    *(f32 *)((char *)inner + 0x14) = *(f32 *)((char *)obj + 0x14);
}
#pragma peephole reset
#pragma scheduling reset
