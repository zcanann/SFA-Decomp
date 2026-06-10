#include "main/dll/tricky_state.h"
#include "main/dll/tumbleweedbush.h"
#include "main/game_object.h"

typedef struct TrickyGrowlState {
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    u8 padC[0x58 - 0xC];
    u8 unk58;
    u8 pad59[0x60 - 0x59];
} TrickyGrowlState;



extern int trickyDebugPrint(const char *fmt, ...);
extern int trickyFn_8013b368(void *param_1, float threshold, void *param_2);
extern int Sfx_IsPlayingFromObjectChannel(void *obj, int chan);
extern void *Obj_AllocObjectSetup(int p1, int p2);
extern int Obj_SetupObject(void *setup, int p2, int p3, int p4, void *p5);
extern int Obj_IsLoadingLocked(void);
extern int Sfx_PlayFromObject(void *obj, int sfxId);
extern int Sfx_AddLoopedObjectSound(void *obj, int sfxId);
extern int Sfx_RemoveLoopedObjectSound(void *obj, int sfxId);
extern int randomGetRange(int lo, int hi);
extern int getAngle(float x, float z);
extern void objAudioFn_800393f8(void *obj, void *p2, int p3, int p4, int p5, int p6);
extern void objAnimFn_8013a3f0(void *obj, int p2, float p3, int p4);
extern void trickyTurnTowardYaw(void *obj, s16 angle);
extern void objSetAnimSpeedTo1(void *obj);

extern char lbl_8031D2E8[];

extern f32 lbl_803E23DC;
extern f32 lbl_803E2444;
extern f32 lbl_803E24C8;
extern f32 lbl_803E24CC;
extern f32 lbl_803E24D0;

/*
 * --INFO--
 *
 * Function: trickyGrowl
 * EN v1.0 Address: 0x8013DC88
 * EN v1.0 Size: 1096b
 */
void trickyGrowl(void *param_1, void *param_2)
{
    void *state;
    int i;
    void **slot;
    void *setup;
    char *strBase = lbl_8031D2E8;

    switch (((TrickyState *)param_2)->substate) {
    case 0:
        trickyDebugPrint(strBase + 0x558);
        if (trickyFn_8013b368(param_1, lbl_803E24C8, param_2) == 0) {
            state = ((GameObject *)param_1)->extra;
            if ((((uint)((TrickyGrowlState *)state)->unk58 >> 6) & 1) == 0u) {
                s16 a0 = ((GameObject *)param_1)->anim.currentMove;
                if (a0 >= 0x30 || a0 < 0x29) {
                    if (Sfx_IsPlayingFromObjectChannel(param_1, 0x10) == 0) {
                        objAudioFn_800393f8(param_1, (char *)state + 0x3a8, 0x299, 0x100, -1, 0);
                    }
                }
            }
            ((TrickyState *)param_2)->substate = 1;
            objAnimFn_8013a3f0(param_1, 0x33, lbl_803E2444, 0x4000000);
            *(int *)((char *)param_2 + 0x728) = 0;
        }
        break;
    case 1:
        trickyDebugPrint(strBase + 0x568);
        if (*(u8 *)*(int *)param_2 != 0 && *(int *)((char *)param_2 + 0x728) != 0) {
            ((TrickyState *)param_2)->substate = 2;
        } else {
            void *target = *(void **)((char *)((GameObject *)param_1)->extra + 0x28);
            trickyTurnTowardYaw(param_1, (s16)getAngle(
                -(*(f32 *)target - ((GameObject *)param_1)->anim.worldPosX),
                -(((TrickyGrowlState *)target)->unk8 - ((GameObject *)param_1)->anim.worldPosZ)));
            if (randomGetRange(0, 10) == 0) {
                state = ((GameObject *)param_1)->extra;
                if (((((TrickyGrowlState *)state)->unk58 >> 6) & 1) == 0u) {
                    s16 a0 = ((GameObject *)param_1)->anim.currentMove;
                    if (a0 >= 0x30 || a0 < 0x29) {
                        if (Sfx_IsPlayingFromObjectChannel(param_1, 0x10) == 0) {
                            objAudioFn_800393f8(param_1, (char *)state + 0x3a8, 0x299, 0x100, -1, 0);
                        }
                    }
                }
            }
        }
        break;
    case 2:
        trickyDebugPrint(strBase + 0x57c);
        if (trickyFn_8013b368(param_1, lbl_803E24CC, param_2) == 0) {
            if ((u8)Obj_IsLoadingLocked() != 0) {
                ((TrickyState *)param_2)->stateFlags = ((TrickyState *)param_2)->stateFlags | 0x800;
                for (i = 0, slot = (void **)param_2; i < 7; slot++, i++) {
                    setup = Obj_AllocObjectSetup(0x24, 0x4f0);
                    *(u8 *)((char *)setup + 0x4) = 2;
                    *(u8 *)((char *)setup + 0x5) = 1;
                    *(s16 *)((char *)setup + 0x1a) = (s16)i;
                    slot[0x700 / 4] = (void *)Obj_SetupObject(
                        setup, 5, ((GameObject *)param_1)->anim.mapEventSlot, -1,
                        ((GameObject *)param_1)->anim.parent);
                }
                Sfx_PlayFromObject(param_1, 0x3db);
                Sfx_AddLoopedObjectSound(param_1, 0x3dc);
            }
            (*(u8 *)*(int *)param_2)--;
            objAnimFn_8013a3f0(param_1, 0x34, lbl_803E2444, 0x4000000);
            ((TrickyState *)param_2)->stateFlags = ((TrickyState *)param_2)->stateFlags | 0x10;
            ((TrickyState *)param_2)->substate = 3;
            *(int *)((char *)param_2 + 0x728) = 0;
        }
        break;
    case 3:
        trickyDebugPrint(strBase + 0x590);
        if (((GameObject *)param_1)->anim.currentMoveProgress >= lbl_803E24D0) {
            ((TrickyState *)param_2)->stateFlags &= ~0x800LL;
            ((TrickyState *)param_2)->stateFlags = ((TrickyState *)param_2)->stateFlags | 0x1000;
            for (i = 0, slot = (void **)param_2; i < 7; slot++, i++) {
                objSetAnimSpeedTo1(slot[0x700 / 4]);
            }
            Sfx_RemoveLoopedObjectSound(param_1, 0x3dc);
            state = ((GameObject *)param_1)->extra;
            if (((((TrickyGrowlState *)state)->unk58 >> 6) & 1) == 0u) {
                s16 a0 = ((GameObject *)param_1)->anim.currentMove;
                if (a0 >= 0x30 || a0 < 0x29) {
                    if (Sfx_IsPlayingFromObjectChannel(param_1, 0x10) == 0) {
                        objAudioFn_800393f8(param_1, (char *)state + 0x3a8, 0x29d, 0, -1, 0);
                    }
                }
            }
            ((TrickyState *)param_2)->unk08 = 1;
            ((TrickyState *)param_2)->substate = 0;
            {
                f32 resetValue = lbl_803E23DC;
                ((TrickyState *)param_2)->unk71C = resetValue;
                ((TrickyState *)param_2)->unk720 = resetValue;
            }
            ((TrickyState *)param_2)->stateFlags &= ~0x10LL;
            ((TrickyState *)param_2)->stateFlags &= ~0x10000LL;
            ((TrickyState *)param_2)->stateFlags &= ~0x20000LL;
            ((TrickyState *)param_2)->stateFlags &= ~0x40000LL;
            ((TrickyState *)param_2)->unkD = -1;
        } else {
            void *target = *(void **)((char *)((GameObject *)param_1)->extra + 0x28);
            trickyTurnTowardYaw(param_1, (s16)getAngle(
                -(*(f32 *)target - ((GameObject *)param_1)->anim.worldPosX),
                -(((TrickyGrowlState *)target)->unk8 - ((GameObject *)param_1)->anim.worldPosZ)));
        }
        break;
    }
}

