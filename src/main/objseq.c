#include "main/sky_80080E58_shared.h"
#include "main/mapEventTypes.h"

extern int getTabEntry(void *p, int sz, int off, int unk);
extern int getTableFileEntry(int fileId, int index, int *out);
extern int loadAndDecompressDataFile(int id, void *buf, int blockOff, int len, int a, int b, int c);
extern int strncmp(const char *a, const char *b, u32 n);
extern void fn_80137948(char *fmt, ...);
extern char sObjLoadAnimdataNullACRomTabWarning[];
extern char sSeqAAnimDataTag;
extern char sSeqBAnimDataTag;
void ObjSeq_seqState_init(u8 *seq);
extern void endObjSequence(int seq);
extern int *gCameraInterface;
extern u8 lbl_80399E50[];
extern int lbl_803DD064;
extern int lbl_803DD084;
extern s16 lbl_803DD060;
extern s16 lbl_803DD062;
extern char sObjSequenceMissingObjectFormat[];
extern s8 lbl_8030EE1C[];
extern int lbl_8030EDC0[];
extern f32 lbl_803DF018;
extern s8 lbl_8039A60C[];
int objSeqExecCmd06(u8 *obj, u8 *sourceObj, u8 *seq, int cmd, s8 flag);
extern void fn_80295E90(void *obj, int idx);
extern void fn_802967E0(void *obj, int idx);
extern void fn_8029672C(void *obj, int idx);
extern void Obj_SetActiveModelIndex(void *obj, int idx);
extern void playerLock(void *player, int mode);
extern void setMotionBlur(int enabled, f32 amount);
extern void Rcp_SetMonochromeFilterEnabled(int enabled);
extern void gameTimerInit(int type, int value);
extern void timerSetToCountUp(void);
extern void gameTimerStop(void);
extern void Sfx_StopObjectChannel(void *obj, int channel);
extern void Camera_EnableViewYOffset(void);
extern f32 Vec_xzDistance(f32 *a, f32 *b);
extern void CameraShake_Start(f32 a, f32 b, f32 c);
extern int seqStreamFn_8008023c(int slot);
extern int *seqStreamLookupFn_8007fff8(void *table, int count, int key);
extern int AudioStream_Play(int stream, void *cb);
extern void streamCb_80080384(void);
extern u8 lbl_8030ECD0[];
extern int lbl_803DB718;
extern int lbl_803DB728;
extern f32 lbl_803DB730;
extern u32 lbl_803DD068;
extern s16 lbl_803DD070;
extern f32 lbl_803DF004;
extern f32 lbl_803DF008;
extern f32 lbl_803DF00C;
extern f32 lbl_803DF010;
extern f32 lbl_803DF014;

extern f32 lbl_803DD0F4;
extern f32 lbl_803DD0F0;
extern f32 lbl_803DD0EC;
extern f32 lbl_803DD0D0;
extern f32 lbl_803DB710;
extern f32 lbl_803DD0B0;
extern f32 lbl_803DD0AC;
extern f32 lbl_803DD0A8;
extern f32 lbl_803DD0A4;
extern int lbl_803DD0A0;
extern int lbl_803DD09C;
extern int lbl_803DD098;
extern f32 lbl_803DEFF4;
extern f32 lbl_803DEFF8;
extern f32 lbl_803DEFFC;
extern u8 lbl_803DD088;
extern u8 curSeqNo;
extern void Obj_TransformWorldPointToLocal(f32 *x, f32 *y, f32 *z, void *m, f32 wx, f32 wy, f32 wz);

extern u8 lbl_8039944C[];
extern int lbl_803DD0C0;
extern s16 lbl_803DD08A;
extern f32 lbl_803DF030;
extern f32 lbl_803DF034;
extern f32 MTRCallback;
extern f32 DBGCallback;
extern f32 lbl_803DD0CC;
extern f32 lbl_803DD0C8;
extern f32 lbl_803DD0C4;
extern f32 lbl_803DF038;
extern f32 lbl_803DF03C;
extern f32 lbl_803DF040;
extern f32 lbl_803DF044;
extern int Sfx_IsPlayingFromObject(void *obj, int sfxId);
extern void Sfx_SetObjectSfxVolume(void *obj, int sfxId, int volume, f32 p4);
extern int *seqFn_800394a0(void);
extern u8 lbl_803DB411;
extern int lbl_803DB72C;
extern int lbl_803DB714;
extern int lbl_803DB71C;
extern u8 lbl_803DD0D9;
extern u8 lbl_803DD078;
extern s16 lbl_8030ECF8[];
extern int fn_80296C2C(void *obj);
extern void fn_80297254(void *obj);
extern void fn_8029726C(void *obj);
extern void fn_80297284(void *obj);
extern void gameTextLoadTaskText(int textId);
extern void cameraFocusNpc(int param1, u8 *obj);

typedef struct SeqByte0B4 {
    u8 useAltPos : 1;
    u8 rest : 7;
} SeqByte0B4;

extern int lbl_803DB724;
extern f32 lbl_803DD074;
extern f32 RecvDataLeng;
extern f32 SendMailData;
extern u32 getButtonsJustPressed(int controller);
extern int isTalkingToNpc(void);
extern void setJoypadDisabled(void);
extern u8 lbl_803DD111;
extern u8 lbl_803DD112;
extern f32 lbl_803DF02C;
extern void ObjAnim_SetCurrentMove(void *obj, int move, int p3, f32 phase);
extern void ObjModel_SetBlendChannelTargets(void *action, int mode, int target, int channel, int p5, f32 t);
extern void Sfx_PlayFromObject(void *obj, int sfxId);
extern void Sfx_RemoveLoopedObjectSound(void *obj, int sfxId);
extern void Sfx_AddLoopedObjectSound(void *obj, int sfxId);
extern void Music_Trigger(int id, int mode);
extern void warpToMap(int map, int mode);
extern int ObjAnim_SampleRootCurvePhase(void *obj, f32 *out, f32 dist);
extern void ObjAnim_AdvanceCurrentMove(void *obj, void *state, f32 speed, f32 t);
int ObjSeq_ExecuteActionCommand(u8 *obj, u8 *action, u8 **cmd, int flags, void *out);
void *ObjSeq_ToggleCommand3Target(u8 *obj, u8 *seq, u8 *src);

typedef struct CamRequest {
    s16 rot[3];
    u8 pad6[6];
    f32 posB[3];
    f32 pos[3];
    u8 pad24[0x90];
    f32 fov;
    u8 padB8[0x8c];
} CamRequest;

typedef struct CamFloats {
    f32 a;
    f32 b;
    s16 c;
} CamFloats;

typedef struct CamMode {
    int mode;
    u8 flag;
} CamMode;

typedef struct SeqByte136 {
    u8 modelSlot : 4;
    u8 pad3 : 1;
    u8 mapEvent : 1;
    u8 rest : 2;
} SeqByte136;
int ObjSeq_update(u8 *obj, f32 t);

typedef struct SeqRunFlags {
    u8 active : 1;
} SeqRunFlags;
extern SeqRunFlags lbl_803DD0B4;
extern u8 *lbl_803DD07C;
extern u8 lbl_803DD078;
extern u8 lbl_803DD0D9;
extern int lbl_803DB714;
extern int lbl_803DB71C;
extern int lbl_803DB72C;
extern s16 lbl_8030ECF8[];
extern int fn_80296C2C(void *obj);
extern void fn_80297284(void *obj);
extern void fn_8029726C(void *obj);
extern void fn_80297254(void *obj);
extern void gameTextLoadTaskText(int taskId);
extern void cameraFocusNpc(int param1, u8 *obj);


void ObjSeq_setCamVars(int camA, int camB, int camC, int camD)
{
    lbl_803DD10C = camA;
    lbl_803DD108 = camB;
    lbl_803DD104 = camC;
    lbl_803DD100 = camD;
}

#pragma peephole off
#pragma scheduling off
#pragma dont_inline on
int objSeqFindLabel(u8 *seq, int label)
{
    int currentLabel;
    int commandIndex;
    int commandCount;
    u8 *command;
    int repeatCount;
    u32 packed;

    currentLabel = 0;
    commandIndex = 0;
    commandCount = *(s16 *)(seq + 0x62);
    while (commandIndex < commandCount) {
        command = *(u8 **)(seq + 0x94) + commandIndex * 4;
        if ((s8)command[0] == 0) {
            currentLabel = *(s16 *)(command + 2);
        } else if ((s8)command[0] == 0xb) {
            repeatCount = *(s16 *)(command + 2);
            if (repeatCount > 0) {
                packed = *(u32 *)(command + 4);
                if ((int)(packed & 0x3f) == 9 && (int)(packed >> 16) == label) {
                    return currentLabel;
                }
                commandIndex += repeatCount;
            }
        }
        currentLabel += command[1];
        commandIndex++;
    }
    return -1;
}
#pragma dont_inline reset
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int objSeqFindConditional(u8 *seq, u8 *seqState)
{
    int currentLabel;
    int commandIndex;
    u8 *command;
    int repeatCount;
    u32 packed;

    currentLabel = -1;
    commandIndex = 0;
    while (commandIndex < *(s16 *)(seq + 0x62)) {
        command = *(u8 **)(seq + 0x94) + commandIndex * 4;
        if ((s8)command[0] == 0) {
            currentLabel = *(s16 *)(command + 2);
        } else if ((s8)command[0] == 0xb) {
            repeatCount = *(s16 *)(command + 2);
            if (repeatCount > 0) {
                packed = *(u32 *)(command + 4);
                if ((int)(packed & 0x3f) == 4 &&
                    seqEvalCondition((packed >> 6) & 0x3ff, seq, *(int *)(seqState + 0x4c)) != 0) {
                    currentLabel -= 10;
                    if (currentLabel < 0) {
                        currentLabel = 0;
                    }
                    return currentLabel;
                }
                commandIndex += repeatCount;
            }
        }
        currentLabel += command[1];
        commandIndex++;
    }
    return -1;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void objCallSeqFn(u8 *obj, u8 *sourceObj, u8 *seq, int action)
{
    int callbackResult;
    s8 actionSlot;
    int movementState;
    int flags;
    u8 *sourceModel;

    (void)action;

    sourceModel = *(u8 **)(sourceObj + 0x4c);
    *(f32 *)(obj + 0x80) = *(f32 *)(obj + 0xc);
    *(f32 *)(obj + 0x84) = *(f32 *)(obj + 0x10);
    *(f32 *)(obj + 0x88) = *(f32 *)(obj + 0x14);
    *(f32 *)(obj + 0x8c) = *(f32 *)(obj + 0x18);
    *(f32 *)(obj + 0x90) = *(f32 *)(obj + 0x1c);
    *(f32 *)(obj + 0x94) = *(f32 *)(obj + 0x20);

    if (*(void **)(obj + 0xbc) != NULL) {
        callbackResult = (*(int (**)(void))(obj + 0xbc))();
        if (callbackResult == 4) {
            lbl_803DD0DA = 1;
        } else if (callbackResult != 0) {
            actionSlot = seq[0x57];
            if (lbl_8039A50C[actionSlot] < 2) {
                lbl_8039A50C[actionSlot] = callbackResult;
            }
        }
        seq[0x8b] = 0;
        seq[0x80] = 0;
    } else {
        if ((s8)seq[0x7b] != 0) {
            seq[0x56] = 0;
            return;
        }

        movementState = (s8)seq[0x56];
        if (movementState >= 4) {
            if (ObjSeq_func20(obj, seq, 6, 0x1e, 0x50, -1, -1) != 0) {
                actionSlot = seq[0x57];
                if (lbl_8039A50C[actionSlot] < 2) {
                    lbl_8039A50C[actionSlot] = 1;
                }
            }
        } else if (movementState != 0) {
            if (movementState != 2) {
                *(f32 *)(seq + 0x4c) = lbl_803DEFC8;
                *(f32 *)(seq + 0x40) = *(f32 *)(obj + 0xc) - *(f32 *)(sourceObj + 0xc);
                *(f32 *)(seq + 0x44) = *(f32 *)(obj + 0x10) - *(f32 *)(sourceObj + 0x10);
                *(f32 *)(seq + 0x48) = *(f32 *)(obj + 0x14) - *(f32 *)(sourceObj + 0x14);
                seq[0x56] = 2;
            }
            if ((s8)sourceModel[0x20] == 1) {
                *(f32 *)(seq + 0x24) = lbl_803DF024;
                actionSlot = seq[0x57];
                if (lbl_8039A50C[actionSlot] < 2) {
                    lbl_8039A50C[actionSlot] = 1;
                }
            }
            *(f32 *)(seq + 0x4c) = *(f32 *)(seq + 0x4c) - *(f32 *)(seq + 0x24) * timeDelta;
            if (*(f32 *)(seq + 0x4c) <= lbl_803DEFB0) {
                seq[0x56] = 0;
            }
        }
    }

    flags = obj[0xaf];
    flags &= 0xf8;
    obj[0xaf] = flags;
    Obj_GetWorldPosition(obj, (f32 *)(obj + 0x18), (f32 *)(obj + 0x1c), (f32 *)(obj + 0x20));
    if (*(void **)(obj + 0x54) != NULL) {
        *(void **)(*(u8 **)(obj + 0x54) + 0x50) = NULL;
        *(u8 *)(*(u8 **)(obj + 0x54) + 0x71) = 0;
    }
    if (*(void **)(obj + 0x58) != NULL) {
        *(u8 *)(*(u8 **)(obj + 0x58) + 0x10f) = 0;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void *ObjSeq_ToggleCommand3Target(u8 *obj, u8 *seq, u8 *src)
{
    void *result;
    u8 *activeObj;
    u8 *entry;
    int j;
    u8 *slotBase;
    int slotOff;
    u8 *seqObj;
    f32 groundY[2];

    result = obj;
    *(s8 *)(seq + 0x79) = (s8)(seq[0x79] ^ 1);
    if ((s8)seq[0x79] != 0) {
        fn_8008196C(obj);
        seqObj = *(u8 **)seq;
        if (seqObj != NULL) {
            result = seqObj;
            *(void **)(seqObj + 0xc0) = obj;
            *(u16 *)(seqObj + 0xb0) |= 0x1000;
            *(void **)(seq + 0x110) = seqObj;

            activeObj = *(u8 **)seq;
            j = 0;
            slotOff = (s8)seq[0x57] * 0x80;
            slotBase = lbl_80396918 + slotOff;
            entry = slotBase;
            for (; j < 16; j++) {
                if (*(u8 **)entry == NULL || *(u8 **)entry == activeObj) {
                    break;
                }
                entry += 8;
            }
            *(u8 **)(slotBase + j * 8) = activeObj;
            *(u8 **)(lbl_80396918 + slotOff + j * 8 + 4) = obj;
        }
    } else {
        if (*(void **)seq != NULL) {
            if ((*(s16 *)(seq + 0x6e) & 1) != 0) {
                *(f32 *)(obj + 0xc) = *(f32 *)(obj + 0xc);
                *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x10);
                *(f32 *)(obj + 0x14) = *(f32 *)(obj + 0x14);
                ObjSeq_UpdateCurvePosition(obj, seq);
            }
            if ((s8)seq[0x7a] == 1 &&
                hitDetectFn_800658a4(obj, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10),
                                     *(f32 *)(obj + 0x14), groundY, 0) == 0) {
                *(f32 *)(obj + 0x10) =
                    *(f32 *)(obj + 0x10) +
                    ((*(f32 *)(obj + 0x10) - groundY[0]) - *(f32 *)(src + 0xc));
            }
            if ((*(s16 *)(seq + 0x6e) & 2) != 0) {
                *(u16 *)obj = *(s16 *)obj + *(s16 *)(seq + 0x1a);
            }
            *(void **)(obj + 0xc0) = NULL;
            *(u16 *)(obj + 0xb0) &= ~0x1000;
            *(void **)seq = NULL;
            result = obj;
        }
    }
    return result;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void ObjSeq_run(void)
{
    int count;
    int matchCount;
    int ok;
    int keepCount;
    void **objects;
    u8 *base;
    void **objPtr;
    u8 *cmd;
    s16 *keepWalk;
    s16 *keepBase;
    int i;
    int index;
    int xrot;
    u8 *model;
    u8 *seqp;
    u8 *candidate;
    u8 **mp;
    int n;
    int k;
    u8 *pending;
    u8 *results;
    u8 *actions;
    f32 *dists;
    f32 *frames;
    u8 *marks;
    s8 frames8;
    u8 *matched[0x28];
    s16 keepBuf[0x5a];
    int objectCount;
    void *unused;

    base = lbl_80396918;
    objects = ObjList_GetObjects(&unused, &objectCount);
    if (lbl_803DD060 != lbl_803DD062) {
        lbl_803DD062 = lbl_803DD060;
    }

    pending = base + 0x39e8;
    results = base + 0x3bf4;
    actions = base + 0x3c4c;
    dists = (f32 *)(base + 0x3740);
    frames = (f32 *)(base + 0x3894);
    marks = base + 0x338c;
    frames8 = framesThisStep;

    for (i = 0; i < 0x55; i++) {
        *pending = 0;
        if ((s8)*results != 0 && (s8)*actions == 0) {
            *pending = frames8;
        }
        *actions = *results;
        *results = 0;
        *frames = *dists;
        *dists = lbl_803DEFF0;
        if (*marks == 2) {
            *marks = 1;
        } else {
            *marks = 0;
        }
        pending++;
        results++;
        actions++;
        dists++;
        frames++;
        marks++;
    }

    count = (s8)lbl_803DD0BC;
    keepCount = 0;
    cmd = base + count * 6 + 0x2a80;
    keepBase = keepBuf;
    keepWalk = keepBase;
    while (count > 0) {
        cmd -= 6;
        count--;
        index = *(s16 *)cmd;
        xrot = *(s16 *)(cmd + 2);
        i = 0;
        base[index + 0x3b44] = 0;
        base[index + 0x3b9c] = 0;
        base[index + 0x3a40] = 0;
        matchCount = 0;
        ok = 1;
        objPtr = objects;
        for (; i < objectCount; i++) {
            candidate = *objPtr;
            if (*(s16 *)(candidate + 0x44) == 0x10) {
                model = *(u8 **)(candidate + 0x4c);
                seqp = *(u8 **)(candidate + 0xb8);
                if (model != NULL && (s8)model[0x1f] == index) {
                    if (*(s16 *)(model + 0x1c) >= 4 &&
                        objFindForSeqFn_80081bf0(candidate) == NULL) {
                        ok = 0;
                        fn_80137948(sObjSequenceMissingObjectFormat,
                                    *(s16 *)(model + 0x1c) - 4);
                    } else {
                        *(void **)seqp = NULL;
                    }
                    if (matchCount < 0x28) {
                        matched[matchCount++] = candidate;
                    }
                }
            }
            objPtr++;
        }

        mp = matched;
        for (n = 0; n < matchCount; n++) {
            candidate = *mp;
            model = *(u8 **)(candidate + 0x4c);
            if (model != NULL && (s8)model[0x1f] == index) {
                seqp = *(u8 **)(candidate + 0xb8);
                if (ok != 0) {
                    seqp[0x7e] = 2;
                    *(s16 *)(seqp + 0x5e) = xrot;
                    ObjSeq_update(candidate, lbl_803DEFC8);
                    Obj_GetWorldPosition(candidate, (f32 *)(candidate + 0x18),
                                         (f32 *)(candidate + 0x1c), (f32 *)(candidate + 0x20));
                } else {
                    seqp[0x7e] = 3;
                }
            }
            mp++;
        }

        if (ok == 0) {
            *keepWalk = index;
            keepWalk += 3;
            keepBuf[keepCount++ * 3 + 1] = xrot;
        }
    }

    for (k = 0; k < keepCount; k++) {
        ((s16 *)(base + 0x2a80))[k * 3] = keepBase[k * 3];
        ((s16 *)(base + 0x2a80))[k * 3 + 1] = keepBase[k * 3 + 1];
    }
    lbl_803DD0BC = (s8)keepCount;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void objSeqDoBgCmds0D(u8 *seq, u8 *obj, int skipSpawns)
{
    ObjSeqBgCmd *cmd;
    int cmdObj;
    int cmdParam;
    void *resource;
    int transitionSlot;
    int uiId;

    if (lbl_803DD090 != 0 && *(s16 *)(obj + 0xb4) != (s8)seq[0x57]) {
        (*(void (*)(int, int, int))(*(int *)(*gGameUIInterface + 0x44)))(0, 0, 0);
    }

    while (lbl_803DD113 > 0) {
        lbl_803DD113--;
        cmd = &lbl_8039A5BC[(s8)lbl_803DD113];
        cmdParam = cmd->param;
        cmdObj = cmd->object;

        switch (cmd->opcode) {
        case 3:
            if ((u8)skipSpawns == 0) {
                (*(void (*)(int, int, int, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))(
                    cmdObj, cmdParam, 0, 0x10000, -1, 0);
            }
            break;
        case 4:
            if ((u8)skipSpawns == 0) {
                return0xFFFF_80008B6C(cmdObj, 0, 0, 1, -1, (u8)cmdParam, 0);
            }
            break;
        case 5:
            if ((u8)skipSpawns == 0) {
                resource = Resource_Acquire((u16)(cmdParam + 0xab), 1);
                if (resource != NULL) {
                    (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*(int *)resource + 0x4)))(
                        cmdObj, 0, 0, 1, -1, (u8)cmdParam, 0);
                }
                if (resource != NULL) {
                    Resource_Release(resource);
                }
            }
            break;
        case 9:
            if ((u8)skipSpawns == 0) {
                switch (cmdParam & 0x2f) {
                case 6:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*(void (*)(int, int))(*(int *)(*gScreenTransitionInterface + 0x8)))(
                        transitionSlot, 3);
                    break;
                case 7:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*(void (*)(int, int))(*(int *)(*gScreenTransitionInterface + 0xc)))(
                        transitionSlot, 3);
                    break;
                case 8:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*(void (*)(int, int))(*(int *)(*gScreenTransitionInterface + 0x8)))(
                        transitionSlot, 2);
                    break;
                case 9:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*(void (*)(int, int))(*(int *)(*gScreenTransitionInterface + 0xc)))(
                        transitionSlot, 2);
                    break;
                case 0xb:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*(void (*)(int, int))(*(int *)(*gScreenTransitionInterface + 0x8)))(
                        transitionSlot, 4);
                    break;
                case 0xc:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*(void (*)(int, int, f32))(*(int *)(*gScreenTransitionInterface + 0x10)))(
                        transitionSlot, 4, lbl_803DF028);
                    break;
                }
            }
            break;
        case 0xb:
            GameBit_Set(cmdParam, 1);
            break;
        case 0xc:
            GameBit_Set(cmdParam, 0);
            break;
        case 0xd:
            if ((u8)skipSpawns == 0) {
                uiId = lbl_8030EDA4[cmdParam];
                (*(void (*)(int, int, int))(*(int *)(*gGameUIInterface + 0x44)))(uiId, 0, 0);
                if (lbl_8030EDA4[cmdParam] != -1) {
                    lbl_803DD090 = 1;
                } else {
                    lbl_803DD090 = 0;
                }
            }
            break;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int seqDoSubCmd0B(u8 *obj, u8 *sourceObj, u8 *seq, u8 *cmdsArg, s16 xrot, int countArg,
                  s8 flag1, s8 flag2)
{
    int count;
    u8 *cmds;
    int opcode;
    int arg10;
    int top16;
    int subId;
    int i;
    int freeSlot;
    u32 packed;
    int result;
    int j;
    int found;
    u8 v;
    int n;
    int slot;

    i = 0;
    cmds = cmdsArg;
    count = (s16)countArg;
    for (; i < count; i++) {
        packed = *(u32 *)cmds;
        opcode = packed & 0x3f;
        arg10 = (packed >> 6) & 0x3ff;
        top16 = packed >> 16;
        if (opcode == 2 || opcode == 3) {
            if ((top16 & 0x8000) != 0) {
                top16 |= 0xffff0000;
            }
            subId = arg10;
            arg10 = 0;
        }

        result = 0;
        switch (opcode) {
        case 6:
            if (objSeqExecCmd06(obj, sourceObj, seq, arg10 | (top16 << 8), flag2) == 0) {
                return 1;
            }
            result = -1;
            arg10 = 0;
            break;
        case 7:
            if (sourceObj != obj) {
                switch ((s8)lbl_8030EE1C[arg10]) {
                case 1:
                    ObjMsg_SendToObjects(0, 2, obj, lbl_8030EDC0[arg10], obj);
                    break;
                case 2:
                    ObjMsg_SendToNearbyObjects(0, lbl_803DF018, 2, obj,
                                               lbl_8030EDC0[arg10], obj);
                    break;
                default:
                    ObjMsg_SendToObject(sourceObj, lbl_8030EDC0[arg10], obj, 0);
                    break;
                }
            }
            result = -1;
            arg10 = 0;
            break;
        case 8:
            if (flag2 == 0) {
                found = 0;
                freeSlot = -1;
                for (j = 0; j < 12; j++) {
                    v = seq[j + 0x12c];
                    if (v == arg10) {
                        found = 1;
                    }
                    if (v == 0) {
                        freeSlot = j;
                    }
                }
                if (found == 0 && freeSlot != -1) {
                    seq[freeSlot + 0x12c] = (u8)arg10;
                    *(s16 *)(seq + freeSlot * 2 + 0x118) =
                        (s16)objSeqFindLabel(seq, top16);
                }
                result = 0;
            }
            break;
        case 9:
            break;
        default:
            result = seqEvalCondition(arg10, seq, *(int *)(obj + 0x4c));
            break;
        }

        if (result > 0 && flag1 == 0) {
            switch (opcode) {
            case 1:
                if (flag2 != 0) {
                    break;
                }
                slot = (s8)seq[0x57];
                if ((s8)lbl_8039A60C[slot] == 0) {
                    lbl_8039A60C[slot] = 1;
                    *(s16 *)(seq + 0x58) = (s16)top16;
                    *(s16 *)(seq + 0x5a) = *(s16 *)(seq + 0x58);
                }
                return 1;
            case 10:
                if (flag2 != 0) {
                    break;
                }
                slot = (s8)seq[0x57];
                if ((s8)lbl_8039A60C[slot] == 0) {
                    lbl_8039A60C[slot] = 1;
                    *(s16 *)(seq + 0x58) = (s16)objSeqFindLabel(seq, top16);
                    *(s16 *)(seq + 0x5a) = *(s16 *)(seq + 0x58);
                }
                return 1;
            case 2:
                switch (subId) {
                case 0:
                    seq[0x80] = (u8)top16;
                    n = seq[0x8b];
                    if ((u32)n < 10) {
                        seq[0x8b] = n + 1;
                        seq[n + 0x81] = (u8)top16;
                    }
                    break;
                case 1:
                    *(s16 *)(seq + 0x60) = (s16)top16;
                    break;
                case 3:
                    seqGlobal1 = top16;
                    break;
                case 4:
                    seqGlobal2 = top16;
                    break;
                case 5:
                    lbl_8039A45C[(s8)seq[0x57]] = (s8)top16;
                    break;
                case 6:
                    GameBit_Set(*(s16 *)(seq + 0x6a), top16 != 0);
                    break;
                case 2:
                    break;
                }
                break;
            case 3:
                if (flag2 != 0) {
                    break;
                }
                switch (subId) {
                case 0:
                    *(s16 *)(seq + 0x60) = *(s16 *)(seq + 0x60) + top16;
                    break;
                case 1:
                    break;
                }
                break;
            case 4:
                if (flag2 != 0) {
                    break;
                }
                *(s16 *)(seq + 0x58) = xrot;
                *(s16 *)(seq + 0x5a) = xrot;
                *(s8 *)(seq + 0x7c) = (s8)(arg10 + 1);
                lbl_8039A60C[(s8)seq[0x57]] = 1;
                return 1;
            case 5:
                if (flag2 != 0) {
                    break;
                }
                return 0;
            case 0:
            case 6:
            case 7:
            case 8:
            case 9:
                break;
            }
        }
        cmds += 4;
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void ObjSeq_updateCamera(void)
{
    CamRequest block;
    CamFloats fblock;
    CamMode mode47;
    CamMode mode48;
    void *groupObjs;
    u8 *obj;
    u8 *model;
    u8 *camObj;
    f32 x;
    f32 y;
    f32 z;
    s16 pitch;
    s16 yaw;
    s16 roll;
    int code;

    obj = lbl_803DD0B8;
    if (obj != NULL) {
        model = *(u8 **)(obj + 0x4c);
        if (lbl_803DD0F8 != 0) {
            x = lbl_803DD0F4;
            y = lbl_803DD0F0;
            z = lbl_803DD0EC;
        } else {
            x = *(f32 *)(obj + 0x18);
            y = *(f32 *)(obj + 0x1c);
            z = *(f32 *)(obj + 0x20);
        }
        pitch = *(s16 *)obj;
        yaw = *(s16 *)(obj + 2);
        roll = *(s16 *)(obj + 4);
        if (*(void **)(obj + 0x30) != NULL) {
            pitch = (s16)(pitch + *(s16 *)*(u8 **)(obj + 0x30));
        }
        lbl_803DD0DC = lbl_803DEFC8;
        if ((s8)lbl_803DD110 == 0) {
            block.pos[0] = x;
            block.pos[1] = y;
            block.pos[2] = z;
            block.rot[0] = (s16)(0x8000 - pitch);
            block.rot[1] = (s16)-yaw;
            block.rot[2] = roll;
            if ((s8)lbl_803DD088 != 0) {
                block.fov = lbl_803DD0D0;
                lbl_803DB710 = lbl_803DD0D0;
            } else {
                block.fov = lbl_803DB710;
            }
            (*(void (*)(int, int, int, int, void *, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x4c, 0, 1, 0x144, &block, model[0x24], 0xff);
            lbl_803DD110 = 1;
        } else {
            camObj = (u8 *)(*(void *(*)(void))(*(int *)(*gCameraInterface + 0xc)))();
            *(f32 *)(camObj + 0x18) = x;
            *(f32 *)(camObj + 0x1c) = y;
            *(f32 *)(camObj + 0x20) = z;
            Obj_TransformWorldPointToLocal((f32 *)(camObj + 0xc), (f32 *)(camObj + 0x10),
                                           (f32 *)(camObj + 0x14), *(void **)(camObj + 0x30),
                                           *(f32 *)(camObj + 0x18), *(f32 *)(camObj + 0x1c),
                                           *(f32 *)(camObj + 0x20));
            *(s16 *)camObj = (s16)(0x8000 - pitch);
            *(s16 *)(camObj + 2) = (s16)-yaw;
            *(s16 *)(camObj + 4) = roll;
            if ((s8)lbl_803DD088 != 0) {
                *(f32 *)(camObj + 0xb4) = lbl_803DD0D0;
                lbl_803DB710 = lbl_803DD0D0;
            } else {
                *(f32 *)(camObj + 0xb4) = lbl_803DB710;
            }
            lbl_803DD0B0 = *(f32 *)(camObj + 0x18);
            lbl_803DD0AC = *(f32 *)(camObj + 0x1c);
            lbl_803DD0A8 = *(f32 *)(camObj + 0x20);
            lbl_803DD0A0 = *(s16 *)camObj;
            lbl_803DD09C = *(s16 *)(camObj + 2);
            lbl_803DD098 = *(s16 *)(camObj + 4);
            lbl_803DD0A4 = *(f32 *)(camObj + 0xb4);
        }
    } else {
        if ((s8)lbl_803DD110 != 0) {
            if (lbl_803DD064 == 0) {
                switch (lbl_803DD10C) {
                case 0x47:
                    mode47.mode = lbl_803DD108;
                    mode47.flag = (u8)lbl_803DD104;
                    (*(void (*)(int, int, int, int, void *, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                        0x47, 1, 3, 8, &mode47, lbl_803DD100, 0xff);
                    break;
                case 0x48:
                    mode48.mode = lbl_803DD108;
                    code = lbl_803DD100;
                    if (code == 0) {
                        mode48.flag = 1;
                    }
                    (*(void (*)(int, int, int, int, void *, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                        0x48, 1, 3, 8, &mode48, code, 0xff);
                    break;
                case 0x4a:
                    (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                        0x4a, 1, 0, 0, 0, lbl_803DD100, 0xff);
                    break;
                case 0x4c:
                    block.posB[0] = lbl_803DD0B0;
                    block.posB[1] = lbl_803DD0AC;
                    block.posB[2] = lbl_803DD0A8;
                    block.rot[0] = (s16)lbl_803DD0A0;
                    block.rot[1] = (s16)lbl_803DD09C;
                    block.rot[2] = (s16)lbl_803DD098;
                    block.fov = lbl_803DD0A4;
                    (*(void (*)(int, int, int, int, void *, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                        0x4c, 1, 0, 0x144, &block, 0, 0xff);
                    break;
                case 0x45:
                    (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                        0x45, 1, 0, 0, 0, lbl_803DD100, 0xff);
                    break;
                case 0x44:
                    if (lbl_803DD108 != 0) {
                        fblock.a = lbl_803DEFF4;
                        fblock.b = lbl_803DEFF8;
                        fblock.c = 5;
                        (*(void (*)(int, int, int, int, void *, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                            0x44, 1, 1, 0xc, &fblock, 0, 0xff);
                    } else {
                        fblock.a = lbl_803DEFF4;
                        fblock.b = lbl_803DEFF8;
                        fblock.c = 0x1e;
                        (*(void (*)(int, int, int, int, void *, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                            0x44, 1, 0, 0xc, &fblock, 0, 0xff);
                    }
                    break;
                case 0x49:
                    (*(void (*)(int, int, int, int, void *, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                        0x49, 1, 0, lbl_803DD108, &lbl_803DD104, lbl_803DD100, 0xff);
                    break;
                case 0x53:
                    (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                        0x53, 1, 0, 0, 0, 0, 0xff);
                    break;
                case 0x56:
                    (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                        0x56, 1, lbl_803DD108, 0, 0, 0, 0);
                    break;
                case 0x57:
                    (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                        0x57, 0, 3, 0, 0, 0, 0);
                    (*(void (*)(int, int))(*(int *)(*gCameraInterface + 0x28)))(
                        *(int *)ObjGroup_GetObjects(0xf, &groupObjs), 0);
                    break;
                default:
                    if (lbl_803DD108 == 0) {
                        lbl_803DD108 = 1;
                    }
                    (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                        0x42, 0, lbl_803DD108, 0, 0, lbl_803DD100, 0xff);
                    break;
                }
            }
            lbl_803DD110 = 0;
            lbl_803DB710 = lbl_803DEFFC;
            lbl_803DD108 = 1;
            lbl_803DD100 = 0x5a;
            lbl_803DD10C = 0x42;
            curSeqNo = 0;
        } else {
            lbl_803DD108 = 1;
            lbl_803DD100 = 0x5a;
            lbl_803DD10C = 0x42;
        }
    }

    lbl_803DD088 = 0;
    lbl_803DD0B8 = NULL;
    lbl_803DD0F8 = 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int objSeqExecCmd06(u8 *obj, u8 *sourceObj, u8 *seq, int cmd, s8 flag)
{
    u8 *base = lbl_80396918;
    u32 cmdByte = cmd & 0xff;
    int cmdArg = (cmd >> 8) & 0xff;
    u8 *slotPtr;
    int pair[2];
    u8 *player;
    u8 *slotFlags;
    u8 v;
    int slot;
    int trackId;
    int *streams;
    f32 dist;
    f32 strength;

    switch (cmdByte) {
    case 2:
        if (flag != 0) {
            break;
        }
        pair[0] = 0x19;
        pair[1] = 0x15;
        if (*(int *)(seq + 0x28) < 0) {
            *(int *)(seq + 0x28) =
                (*(int (*)(int *, int, int, f32, f32, f32))(*(int *)((char *)*gRomCurveInterface + 0x14)))(
                    pair, 2, cmdArg, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10),
                    *(f32 *)(obj + 0x14));
            if (*(int *)(seq + 0x28) > -1) {
                if (*(void **)(seq + 0x2c) != NULL) {
                    mm_free(*(void **)(seq + 0x2c));
                    *(void **)(seq + 0x2c) = NULL;
                }
                *(void **)(seq + 0x2c) = mmAlloc(0x2c, 0x11, 0);
                if (*(void **)(seq + 0x2c) != NULL) {
                    RomCurveInterp_InitFromNode(*(RomCurveInterpState **)(seq + 0x2c),
                                         *(int *)(seq + 0x28));
                } else {
                    *(int *)(seq + 0x28) = -1;
                }
            }
        }
        break;
    case 9:
        if (flag != 0) {
            break;
        }
        seq[0x7f] |= 1;
        break;
    case 18:
        if (flag != 0) {
            break;
        }
        slotFlags = base + (s8)seq[0x57];
        slotFlags = slotFlags + 0x3538;
        v = *slotFlags;
        if ((v & 0x10) != 0) {
            *slotFlags = v & ~0x10;
        } else {
            *slotFlags = v | 0x10;
        }
        break;
    case 14:
        if (flag != 0) {
            break;
        }
        if ((s8)base[(s8)seq[0x57] + 0x3a40] == 0) {
            (*(void (*)(int, int))(*(int *)(*gScreenTransitionInterface + 0x8)))(cmdArg, 1);
        }
        break;
    case 15:
        if (flag != 0) {
            break;
        }
        if ((s8)base[(s8)seq[0x57] + 0x3a40] == 0) {
            (*(void (*)(int, int))(*(int *)(*gScreenTransitionInterface + 0xc)))(cmdArg, 1);
        }
        break;
    case 20:
        lbl_803DD10C = 0x47;
        lbl_803DD108 = cmdArg & 0x7f;
        lbl_803DD104 = 1;
        lbl_803DD100 = 0x78;
        break;
    case 23:
        if (flag != 0) {
            break;
        }
        if (cmdArg >= (s8)(*(u8 **)(sourceObj + 0x50))[0x55]) {
            break;
        }
        if (*(s16 *)(sourceObj + 0x44) == 1) {
            slotPtr = base + (s8)seq[0x57] * 2;
            if (*(s16 *)(slotPtr + 0x3a98) - 1 != 0x45) {
                break;
            }
            if (cmdArg == 1) {
                cmdArg = 0;
            }
            fn_80295E90(sourceObj, cmdArg);
        } else {
            Obj_SetActiveModelIndex(sourceObj, cmdArg);
        }
        break;
    case 24:
        if (*(s16 *)(sourceObj + 0x44) == 1) {
            fn_802967E0(sourceObj, cmdArg);
        }
        break;
    case 25:
        if (*(s16 *)(sourceObj + 0x44) == 1) {
            fn_8029672C(sourceObj, cmdArg);
        }
        break;
    case 26:
        lbl_803DD10C = 0x42;
        lbl_803DD108 = 4;
        lbl_803DD104 = 0;
        lbl_803DD100 = 0;
        break;
    case 33:
        *(s16 *)(seq + 0x6e) = *(s16 *)(seq + 0x6e) | 0x400;
        ((SeqByte136 *)(seq + 0x136))->modelSlot = cmdArg;
        break;
    case 34:
        *(s16 *)(seq + 0x6e) = *(s16 *)(seq + 0x6e) & ~0x400;
        ((SeqByte136 *)(seq + 0x136))->modelSlot = 0;
        break;
    case 35:
        ((SeqByte136 *)(seq + 0x136))->mapEvent = 1;
        break;
    case 36:
        (*(void (*)(int, int, int, int))(*(int *)(*gMapEventInterface + 0x1c)))(
            0, 0, 1, getCurMapLayer());
        break;
    case 38:
        playerLock(Obj_GetPlayerObject(), cmdArg);
        break;
    case 44:
        setMotionBlur(1, (f32)cmdArg / lbl_803DF004);
        break;
    case 45:
        setMotionBlur(0, lbl_803DEFB0);
        break;
    case 46:
        Rcp_SetMonochromeFilterEnabled(1);
        break;
    case 47:
        Rcp_SetMonochromeFilterEnabled(0);
        break;
    case 48:
        GameBit_Set(0x3b0, 1);
        getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x134, 0);
        getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x135, 0);
        getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x142, 0);
        break;
    case 49:
        GameBit_Set(0x3b0, 1);
        getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x136, 0);
        getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x137, 0);
        getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x143, 0);
        break;
    case 50:
        GameBit_Set(0x3b0, 0);
        getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x134, 0);
        getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x135, 0);
        getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x142, 0);
        envFxFn_800887cc();
        break;
    }

    switch (cmdByte) {
    case 0:
        lbl_803DD0DA = 1;
        return 0;
    case 7:
        if (flag != 0) {
            break;
        }
        Camera_EnableViewYOffset();
        player = Obj_GetPlayerObject();
        if (player == NULL) {
            break;
        }
        dist = Vec_xzDistance((f32 *)(player + 0x18), (f32 *)(obj + 0x18));
        strength = lbl_803DF008 * (f32)(cmdArg - 7) + lbl_803DEFC8;
        if (dist < lbl_803DF00C) {
            if (dist > lbl_803DF010) {
                strength *= lbl_803DEFC8 - (dist - lbl_803DF010) / lbl_803DF014;
            }
            CameraShake_Start(lbl_803DB730 * strength, lbl_803DB730 * strength, lbl_803DB730);
        }
        break;
    case 10:
        gameTimerInit(0x12, cmdArg);
        break;
    case 11:
        gameTimerInit(0x11, cmdArg);
        break;
    case 12:
        timerSetToCountUp();
        break;
    case 37:
        gameTimerStop();
        break;
    case 13:
        Sfx_StopObjectChannel(sourceObj, 0x7f);
        break;
    case 16:
        *(s8 *)(seq + 0x7d) = (s8)cmdArg;
        break;
    case 21:
        lbl_803DD10C = 0x48;
        lbl_803DD108 = cmdArg & 0x7f;
        lbl_803DD104 = 1;
        lbl_803DD100 = 0x78;
        break;
    case 51:
        lbl_803DD100 = cmdArg;
        break;
    case 23:
        if (flag != 0) {
            break;
        }
        if (*(s16 *)(sourceObj + 0x44) == 1) {
            break;
        }
        if (cmdArg >= (s8)(*(u8 **)(sourceObj + 0x50))[0x55]) {
            break;
        }
        Obj_SetActiveModelIndex(sourceObj, cmdArg);
        break;
    case 27:
        (*(void (*)(int, int, int))(*(int *)(*gMapEventInterface + 0x50)))(
            *(s8 *)(sourceObj + 0xac), cmdArg, 1);
        break;
    case 28:
        (*(void (*)(int, int, int))(*(int *)(*gMapEventInterface + 0x50)))(
            *(s8 *)(sourceObj + 0xac), cmdArg, 0);
        break;
    case 29:
        (*(void (*)(int, int))(*(int *)(*gMapEventInterface + 0x44)))(
            *(s8 *)(sourceObj + 0xac), cmdArg);
        break;
    case 19:
        if (flag != 0) {
            break;
        }
        base[(s8)seq[0x57] + 0x3538] &= ~0x10;
        break;
    case 30:
        if (flag != 0) {
            break;
        }
        base[(s8)seq[0x57] + 0x3538] |= 0x10;
        break;
    case 31:
        (*(void (*)(void))(*(int *)(*gMapEventInterface + 0x2c)))();
        break;
    case 32:
        (*(void (*)(void))(*(int *)(*gMapEventInterface + 0x28)))();
        break;
    case 39:
        if (lbl_803DB720 == (s8)seq[0x57]) {
            slotPtr = base + (s8)seq[0x57] * 4;
            lbl_803DB728 = (int)*(f32 *)(slotPtr + 0x3894);
            lbl_803DD070 = seqStreamFn_8008023c((s8)seq[0x57]) == 0;
        }
        break;
    case 40:
        slot = (s8)seq[0x57];
        if (base[slot + 0x3334] == 0) {
            slotPtr = base + slot * 2;
            trackId = (u32)(*(s16 *)(slotPtr + 0x3a98) - 1) & 0x3fff;
            lbl_803DD068 = trackId;
            streams = seqStreamLookupFn_8007fff8(lbl_8030ECA8, 5, trackId);
            if (streams != NULL) {
                if (AudioStream_Play(streams[cmdArg], streamCb_80080384) != 0) {
                    lbl_803DB720 = slot;
                }
            }
            streams = seqStreamLookupFn_8007fff8(lbl_8030ECD0, 5, trackId);
            if (streams != NULL) {
                lbl_803DB718 = streams[cmdArg];
            }
        }
        break;
    }
    return 1;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void objSeqUpdateCurves(u8 *obj, u8 *seqObj, u8 *seq, int mode)
{
    struct {
        f32 x;
        f32 y;
        f32 z;
    } pos;
    int out;
    u8 *cmd;
    f32 speed;
    u8 *model;
    u8 *activeObj;
    u8 *action;
    s8 flags;
    int found;
    int targetFrame;
    int i;
    int stop;
    int frame;
    f32 val;
    f32 rate;
    f32 prevX;
    f32 prevZ;
    int opcode;
    u8 *entry;

    (void)seqObj;

    if (*(void **)(seq + 0x94) == NULL) {
        return;
    }

    flags = 1;
    if (mode != 0) {
        flags |= 2;
    }

    model = *(u8 **)(obj + 0x4c);
    targetFrame = *(s16 *)(seq + 0x58);
    lbl_803DD08A = targetFrame;
    *(s16 *)(seq + 0x66) = 0;
    *(s16 *)(seq + 0x68) = -0x32;
    seq[0x78] = 0;
    seq[0x7a] = 0;
    seq[0x79] = 0;
    *(void **)seq = NULL;
    seq[0x7b] = 0;
    *(f32 *)(seq + 0x20) = lbl_803DEFB0;
    *(s16 *)(seq + 0x58) = -1;

    found = -1;
    activeObj = obj;
    i = 0;
    while (i < *(s16 *)(seq + 0x62) && *(s16 *)(seq + 0x58) <= targetFrame) {
        cmd = *(u8 **)(seq + 0x94) + i * 4;
        opcode = (s8)cmd[0];
        switch (opcode) {
        case 3:
            flags = (s8)(flags | 4);
            activeObj = ObjSeq_ToggleCommand3Target(obj, seq, model);
            *(s16 *)(activeObj + 0xa2) = -1;
            break;
        case 0:
            *(s16 *)(seq + 0x58) = *(s16 *)(cmd + 2);
            break;
        case 9:
            found = *(s16 *)(seq + 0x58);
            break;
        case 11:
            if (*(s16 *)(cmd + 2) > 0) {
                i += *(s16 *)(cmd + 2);
            }
            break;
        default:
            if (opcode != 0xf) {
                *(s16 *)(seq + 0x58) = *(s16 *)(seq + 0x58) + cmd[1];
            }
            break;
        }
        i++;
    }

    *(s16 *)(seq + 0x58) = (s16)found;
    action = *(u8 **)(*(u8 **)(activeObj + 0x7c) + (s8)activeObj[0xad] * 4);
    if (action != NULL) {
        if (*(void **)(seq + 0x98) == NULL) {
            val = lbl_803DEFB0;
        } else {
            val = lbl_803DEFB0;
            if (*(s16 *)(seq + 0xdc) != 0) {
                val = objCurveInterpolate(
                    (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xb6) * 8),
                    *(s16 *)(seq + 0xdc) & 0xfff, -1);
            }
        }
        prevX = *(f32 *)(model + 0x8) + val;
        if (*(void **)(seq + 0x98) == NULL) {
            val = lbl_803DEFB0;
        } else {
            val = lbl_803DEFB0;
            if (*(s16 *)(seq + 0xd8) != 0) {
                val = objCurveInterpolate(
                    (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xb2) * 8),
                    *(s16 *)(seq + 0xd8) & 0xfff, -1);
            }
        }
        prevZ = *(f32 *)(model + 0x10) + val;
    }

    entry = lbl_8039944C;
    while (*(s16 *)(seq + 0x58) < targetFrame) {
        *(s16 *)(seq + 0x58) += 1;
        frame = *(s16 *)(seq + 0x58);
        if (*(void **)(seq + 0x98) == NULL) {
            val = lbl_803DEFB0;
        } else {
            val = lbl_803DEFB0;
            if (*(s16 *)(seq + 0xdc) != 0) {
                val = objCurveInterpolate(
                    (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xb6) * 8),
                    *(s16 *)(seq + 0xdc) & 0xfff, frame);
            }
        }
        pos.x = *(f32 *)(model + 0x8) + val;
        frame = *(s16 *)(seq + 0x58);
        if (*(void **)(seq + 0x98) == NULL) {
            val = lbl_803DEFB0;
        } else {
            val = lbl_803DEFB0;
            if (*(s16 *)(seq + 0xda) != 0) {
                val = objCurveInterpolate(
                    (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xb4) * 8),
                    *(s16 *)(seq + 0xda) & 0xfff, frame);
            }
        }
        pos.y = *(f32 *)(model + 0xc) + val;
        frame = *(s16 *)(seq + 0x58);
        if (*(void **)(seq + 0x98) == NULL) {
            val = lbl_803DEFB0;
        } else {
            val = lbl_803DEFB0;
            if (*(s16 *)(seq + 0xd8) != 0) {
                val = objCurveInterpolate(
                    (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xb2) * 8),
                    *(s16 *)(seq + 0xd8) & 0xfff, frame);
            }
        }
        pos.z = *(f32 *)(model + 0x10) + val;

        if (*(s16 *)(seq + 0x58) > 0 && mode != 0) {
            if ((s8)seq[0x78] == 1 && (s8)seq[0x7b] == 0 && action != NULL) {
                if (ObjAnim_SampleRootCurvePhase(
                        activeObj, &speed,
                        sqrtf((pos.x - prevX) * (pos.x - prevX) +
                              (pos.z - prevZ) * (pos.z - prevZ))) == 0) {
                    frame = *(s16 *)(seq + 0x58) - 1;
                    if (*(void **)(seq + 0x98) == NULL) {
                        val = lbl_803DEFB0;
                    } else {
                        val = lbl_803DEFB0;
                        if (*(s16 *)(seq + 0xd4) != 0) {
                            val = objCurveInterpolate(
                                (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xae) * 8),
                                *(s16 *)(seq + 0xd4) & 0xfff, frame);
                        }
                    }
                    speed = lbl_803DF030 * val;
                }
            } else {
                frame = *(s16 *)(seq + 0x58) - 1;
                if (*(void **)(seq + 0x98) == NULL) {
                    val = lbl_803DEFB0;
                } else {
                    val = lbl_803DEFB0;
                    if (*(s16 *)(seq + 0xd4) != 0) {
                        val = objCurveInterpolate(
                            (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xae) * 8),
                            *(s16 *)(seq + 0xd4) & 0xfff, frame);
                    }
                }
                speed = lbl_803DF030 * val;
            }

            if (action != NULL) {
                ObjAnim_AdvanceCurrentMove(activeObj, seq + 0xf0, speed, lbl_803DEFC8);
                if (mode != 0) {
                    if (*(f32 *)(seq + 0x20) > lbl_803DEFB0) {
                        if (*(s16 *)(seq + 0xd6) != 0) {
                            frame = *(s16 *)(seq + 0x58) - 1;
                            if (*(void **)(seq + 0x98) != NULL && *(s16 *)(seq + 0xd6) != 0) {
                                rate = objCurveInterpolate(
                                    (ObjCurveKey *)(*(u8 **)(seq + 0x98) +
                                                    *(s16 *)(seq + 0xb0) * 8),
                                    *(s16 *)(seq + 0xd6) & 0xfff, frame);
                            }
                        } else {
                            rate = lbl_803DF034;
                        }
                        if (rate < lbl_803DEFC8) {
                            rate = lbl_803DEFC8;
                        }
                        *(f32 *)(seq + 0x20) = *(f32 *)(seq + 0x20) - lbl_803DEFC8 / rate;
                        if (*(f32 *)(seq + 0x20) < lbl_803DEFB0) {
                            *(f32 *)(seq + 0x20) = lbl_803DEFB0;
                        }
                    }
                }
            } else {
                *(f32 *)(activeObj + 0x98) = *(f32 *)(activeObj + 0x98) + speed;
                while (*(f32 *)(activeObj + 0x98) > lbl_803DEFC8) {
                    *(f32 *)(activeObj + 0x98) = *(f32 *)(activeObj + 0x98) - lbl_803DEFC8;
                }
                while (*(f32 *)(activeObj + 0x98) < lbl_803DEFB0) {
                    *(f32 *)(activeObj + 0x98) = *(f32 *)(activeObj + 0x98) + lbl_803DEFC8;
                }
            }
        }

        prevX = pos.x;
        prevZ = pos.z;

        stop = 0;
        lbl_803DD0C0 = 0;
        while (stop == 0 && *(s16 *)(seq + 0x66) < *(s16 *)(seq + 0x62)) {
            cmd = *(u8 **)(seq + 0x94) + *(s16 *)(seq + 0x66) * 4;
            opcode = (s8)cmd[0];
            if (opcode == 0) {
                if (*(s16 *)(seq + 0x58) >= *(s16 *)(cmd + 2)) {
                    *(s16 *)(seq + 0x68) = *(s16 *)(cmd + 2);
                    *(s16 *)(seq + 0x66) = *(s16 *)(seq + 0x66) + 1;
                } else {
                    stop = 1;
                }
            } else {
                if (*(s16 *)(seq + 0x58) >= *(s16 *)(seq + 0x68)) {
                    if (opcode != 0xf) {
                        *(s16 *)(seq + 0x68) = *(s16 *)(seq + 0x68) + cmd[1];
                    }
                    *(s16 *)(seq + 0x66) = *(s16 *)(seq + 0x66) + 1;
                    if (ObjSeq_ExecuteActionCommand(obj, action, &cmd, flags, &out) != 0) {
                        return;
                    }
                    activeObj = *(u8 **)*(u8 **)(obj + 0xb8);
                    if (activeObj == NULL) {
                        activeObj = obj;
                    }
                    action = *(u8 **)(*(u8 **)(activeObj + 0x7c) + (s8)activeObj[0xad] * 4);
                } else {
                    stop = 1;
                }
            }
        }

        for (i = 0; i < lbl_803DD0C0; i++) {
            if (seqDoSubCmd0B(obj, activeObj, seq, *(u8 **)(entry + i * 8),
                              *(s16 *)(entry + i * 8 + 6), *(s16 *)(entry + i * 8 + 4), 1,
                              0) != 0) {
                i = lbl_803DD0C0;
            }
            activeObj = *(u8 **)*(u8 **)(obj + 0xb8);
            if (activeObj == NULL) {
                activeObj = obj;
            }
            action = *(u8 **)(*(u8 **)(activeObj + 0x7c) + (s8)activeObj[0xad] * 4);
        }
        lbl_803DD0C0 = 0;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void objSeqUpdateMoreCurves(u8 *obj, u8 *seqObj, u8 *seq, int frame)
{
    u8 *model;
    u8 *walk;
    s16 *vec;
    s16 *vec2;
    u8 *tex1;
    u8 *tex2;
    u8 *tex5;
    int *modelIds;
    int vol;
    int i;
    int k;
    int slots;
    int scroll;
    f32 val;

    model = *(u8 **)(obj + 0x4c);
    *(f32 *)(obj + 0xc) = *(f32 *)(model + 0x8);
    *(f32 *)(obj + 0x10) = *(f32 *)(model + 0xc);
    *(f32 *)(obj + 0x14) = *(f32 *)(model + 0x10);
    *(s16 *)(obj + 2) = 0;
    *(s16 *)(obj + 0) = 0;
    *(s16 *)(obj + 4) = 0;
    if ((*(s16 *)(seq + 0x6e) & 0x20) != 0) {
        seqObj[0x36] = 0xff;
    }
    lbl_803DD0CC = lbl_803DEFB0;
    lbl_803DD0C8 = lbl_803DEFB0;
    lbl_803DD0C4 = lbl_803DEFB0;

    if (*(void **)(seq + 0x98) != NULL) {
        if (*(void **)(seq + 0x98) == NULL) {
            val = lbl_803DEFB0;
        } else {
            val = lbl_803DEFB0;
            if (*(s16 *)(seq + 0xe6) != 0) {
                val = objCurveInterpolate(
                    (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xc0) * 8),
                    *(s16 *)(seq + 0xe6) & 0xfff, frame);
            }
        }
        vol = (int)val;

        walk = seq;
        for (i = 0; i < 3; i++) {
            if (*(s16 *)(walk + 0x30) != 0) {
                Sfx_IsPlayingFromObject(seqObj, (u16)*(s16 *)(walk + 0x38));
            }
            walk += 2;
        }

        if (vol > 0 && *(s16 *)(seq + 0x36) != 0) {
            if (Sfx_IsPlayingFromObject(seqObj, (u16)*(s16 *)(seq + 0x3e)) != 0) {
                Sfx_SetObjectSfxVolume(seqObj, (u16)*(s16 *)(seq + 0x3e), (u8)vol,
                                       lbl_803DF038);
            }
        }

        if (*(void **)(seq + 0x98) == NULL) {
            val = lbl_803DEFB0;
        } else {
            val = lbl_803DEFB0;
            if (*(s16 *)(seq + 0xd0) != 0) {
                val = objCurveInterpolate(
                    (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xaa) * 8),
                    *(s16 *)(seq + 0xd0) & 0xfff, frame);
            }
        }
        *(s16 *)(obj + 0) = (int)(lbl_803DF03C * val);

        if (*(void **)(seq + 0x98) == NULL) {
            val = lbl_803DEFB0;
        } else {
            val = lbl_803DEFB0;
            if (*(s16 *)(seq + 0xd2) != 0) {
                val = objCurveInterpolate(
                    (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xac) * 8),
                    *(s16 *)(seq + 0xd2) & 0xfff, frame);
            }
        }
        *(s16 *)(obj + 2) = (int)(lbl_803DF03C * val);

        if (*(void **)(seq + 0x98) == NULL) {
            val = lbl_803DEFB0;
        } else {
            val = lbl_803DEFB0;
            if (*(s16 *)(seq + 0xce) != 0) {
                val = objCurveInterpolate(
                    (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xa8) * 8),
                    *(s16 *)(seq + 0xce) & 0xfff, frame);
            }
        }
        *(s16 *)(obj + 4) = (int)(lbl_803DF03C * val);

        if (*(void **)(seq + 0x98) == NULL) {
            val = lbl_803DEFB0;
        } else {
            val = lbl_803DEFB0;
            if (*(s16 *)(seq + 0xdc) != 0) {
                val = objCurveInterpolate(
                    (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xb6) * 8),
                    *(s16 *)(seq + 0xdc) & 0xfff, frame);
            }
        }
        lbl_803DD0CC = val;

        if (*(void **)(seq + 0x98) == NULL) {
            val = lbl_803DEFB0;
        } else {
            val = lbl_803DEFB0;
            if (*(s16 *)(seq + 0xda) != 0) {
                val = objCurveInterpolate(
                    (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xb4) * 8),
                    *(s16 *)(seq + 0xda) & 0xfff, frame);
            }
        }
        lbl_803DD0C8 = val;

        if (*(void **)(seq + 0x98) == NULL) {
            val = lbl_803DEFB0;
        } else {
            val = lbl_803DEFB0;
            if (*(s16 *)(seq + 0xd8) != 0) {
                val = objCurveInterpolate(
                    (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xb2) * 8),
                    *(s16 *)(seq + 0xd8) & 0xfff, frame);
            }
        }
        lbl_803DD0C4 = val;

        lbl_803DD120 = lbl_803DD0CC;
        lbl_803DD11C = lbl_803DD0C8;
        lbl_803DD118 = lbl_803DD0C4;
        lbl_803DD116 = *(s16 *)obj;
        lbl_803DD114 = 1;
        *(f32 *)(obj + 0xc) = *(f32 *)(model + 0x8) + lbl_803DD0CC;
        *(f32 *)(obj + 0x10) = *(f32 *)(model + 0xc) + lbl_803DD0C8;
        *(f32 *)(obj + 0x14) = *(f32 *)(model + 0x10) + lbl_803DD0C4;

        if (*(s16 *)(seq + 0xde) != 0) {
            if (*(void **)(seq + 0x98) == NULL) {
                val = lbl_803DEFB0;
            } else {
                val = lbl_803DEFB0;
                if (*(s16 *)(seq + 0xde) != 0) {
                    val = objCurveInterpolate(
                        (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xb8) * 8),
                        *(s16 *)(seq + 0xde) & 0xfff, frame);
                }
            }
            if ((s8)seq[0x7b] != 0) {
                if (val < lbl_803DF040) {
                    val = lbl_803DF040;
                }
                if (val > MTRCallback) {
                    val = lbl_803DF044;
                }
                lbl_803DD088 = 1;
                lbl_803DD0D0 = val;
            } else {
                *(f32 *)(seq + 0x10) = val;
            }
        }

        if ((*(s16 *)(seq + 0x6e) & 0x20) != 0 && *(s16 *)(seq + 0xc8) != 0) {
            if (*(void **)(seq + 0x98) == NULL) {
                val = lbl_803DEFB0;
            } else {
                val = lbl_803DEFB0;
                if (*(s16 *)(seq + 0xc8) != 0) {
                    val = objCurveInterpolate(
                        (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xa2) * 8),
                        *(s16 *)(seq + 0xc8) & 0xfff, frame);
                }
            }
            if (val < lbl_803DEFB0) {
                val = lbl_803DEFB0;
            }
            if (val > DBGCallback) {
                val = DBGCallback;
            }
            seqObj[0x36] = (u8)(int)val;
        }

        if (*(s16 *)(seq + 0xca) != 0) {
            if (*(void **)(seq + 0x98) == NULL) {
                val = lbl_803DEFB0;
            } else {
                val = lbl_803DEFB0;
                if (*(s16 *)(seq + 0xca) != 0) {
                    val = objCurveInterpolate(
                        (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xa4) * 8),
                        *(s16 *)(seq + 0xca) & 0xfff, frame);
                }
            }
            (*(void (*)(f32))(*(int *)((char *)*gSHthorntailAnimationInterface + 0x28)))(
                lbl_803DEFFC * val);
        }

        if ((*(s16 *)(seq + 0x6e) & 0x10) != 0 && *(s16 *)(seq + 0xcc) != 0) {
            if (*(void **)(seq + 0x98) == NULL) {
                val = lbl_803DEFB0;
            } else {
                val = lbl_803DEFB0;
                if (*(s16 *)(seq + 0xcc) != 0) {
                    val = objCurveInterpolate(
                        (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xa6) * 8),
                        *(s16 *)(seq + 0xcc) & 0xfff, frame);
                }
            }
            *(f32 *)(seqObj + 8) = val * *(f32 *)(*(u8 **)(seqObj + 0x50) + 4);
        }

        if ((*(s16 *)(seq + 0x6e) & 8) != 0) {
            vec = objModelGetVecFn_800395d8(seqObj, 0);
            if (vec != NULL) {
                if (*(s16 *)(seq + 0xc4) != 0) {
                    if (*(void **)(seq + 0x98) == NULL) {
                        val = lbl_803DEFB0;
                    } else {
                        val = lbl_803DEFB0;
                        if (*(s16 *)(seq + 0xc4) != 0) {
                            val = objCurveInterpolate(
                                (ObjCurveKey *)(*(u8 **)(seq + 0x98) +
                                                *(s16 *)(seq + 0x9e) * 8),
                                *(s16 *)(seq + 0xc4) & 0xfff, frame);
                        }
                    }
                } else {
                    val = lbl_803DEFB0;
                }
                vec[0] = (s16)(*(s16 *)(seq + 0x116) + (int)(lbl_803DF03C * val));

                if (*(s16 *)(seq + 0xc6) != 0) {
                    if (*(void **)(seq + 0x98) == NULL) {
                        val = lbl_803DEFB0;
                    } else {
                        val = lbl_803DEFB0;
                        if (*(s16 *)(seq + 0xc6) != 0) {
                            val = objCurveInterpolate(
                                (ObjCurveKey *)(*(u8 **)(seq + 0x98) +
                                                *(s16 *)(seq + 0xa0) * 8),
                                *(s16 *)(seq + 0xc6) & 0xfff, frame);
                        }
                    }
                } else {
                    val = lbl_803DEFB0;
                }
                vec[1] = (s16)(*(s16 *)(seq + 0x114) + (int)(lbl_803DF03C * val));

                if (*(s16 *)(seq + 0xc2) != 0) {
                    if (*(void **)(seq + 0x98) == NULL) {
                        val = lbl_803DEFB0;
                    } else {
                        val = lbl_803DEFB0;
                        if (*(s16 *)(seq + 0xc2) != 0) {
                            val = objCurveInterpolate(
                                (ObjCurveKey *)(*(u8 **)(seq + 0x98) +
                                                *(s16 *)(seq + 0x9c) * 8),
                                *(s16 *)(seq + 0xc2) & 0xfff, frame);
                        }
                    }
                } else {
                    val = lbl_803DEFB0;
                }
                vec[2] = (int)(lbl_803DF03C * val);

                if ((*(s16 *)(seq + 0x6e) & 0x400) != 0) {
                    slots = ((SeqByte136 *)(seq + 0x136))->modelSlot;
                    modelIds = seqFn_800394a0();
                    if (slots == 0) {
                        slots = 9;
                    }
                    if (vec != NULL) {
                        for (k = 1; k < slots; k++) {
                            vec2 = objModelGetVecFn_800395d8(seqObj, modelIds[k]);
                            if (vec2 != NULL) {
                                vec2[1] = vec[1];
                                vec2[0] = vec[0];
                                vec2[2] = vec[2];
                            }
                        }
                    }
                }
            }
        }

        if ((*(s16 *)(seq + 0x6e) & 0x200) != 0) {
            vec = objModelGetVecFn_800395d8(seqObj, 1);
            if (vec != NULL) {
                if (*(s16 *)(seq + 0xe4) != 0) {
                    if (*(void **)(seq + 0x98) == NULL) {
                        val = lbl_803DEFB0;
                    } else {
                        val = lbl_803DEFB0;
                        if (*(s16 *)(seq + 0xe4) != 0) {
                            val = objCurveInterpolate(
                                (ObjCurveKey *)(*(u8 **)(seq + 0x98) +
                                                *(s16 *)(seq + 0xbe) * 8),
                                *(s16 *)(seq + 0xe4) & 0xfff, frame);
                        }
                    }
                } else {
                    val = lbl_803DEFB0;
                }
                vec[0] = (int)(lbl_803DF03C * val);
            }
        }

        if ((*(s16 *)(seq + 0x6e) & 0x40) != 0) {
            tex1 = (u8 *)objFindTexture((int)seqObj, 1, 0);
            tex2 = (u8 *)objFindTexture((int)seqObj, 0, 0);
            if (tex1 != NULL || tex2 != NULL) {
                if (*(s16 *)(seq + 0xe0) != 0) {
                    if (*(void **)(seq + 0x98) == NULL) {
                        val = lbl_803DEFB0;
                    } else {
                        val = lbl_803DEFB0;
                        if (*(s16 *)(seq + 0xe0) != 0) {
                            val = objCurveInterpolate(
                                (ObjCurveKey *)(*(u8 **)(seq + 0x98) +
                                                *(s16 *)(seq + 0xba) * 8),
                                *(s16 *)(seq + 0xe0) & 0xfff, frame);
                        }
                    }
                } else {
                    val = lbl_803DEFB0;
                }
                scroll = (int)(lbl_803DF004 * val);
                if (tex1 != NULL) {
                    *(s16 *)(tex1 + 8) = scroll;
                }
                if (tex2 != NULL) {
                    *(s16 *)(tex2 + 8) = (s16)-scroll;
                }

                if (*(s16 *)(seq + 0xe2) != 0) {
                    if (*(void **)(seq + 0x98) == NULL) {
                        val = lbl_803DEFB0;
                    } else {
                        val = lbl_803DEFB0;
                        if (*(s16 *)(seq + 0xe2) != 0) {
                            val = objCurveInterpolate(
                                (ObjCurveKey *)(*(u8 **)(seq + 0x98) +
                                                *(s16 *)(seq + 0xbc) * 8),
                                *(s16 *)(seq + 0xe2) & 0xfff, frame);
                        }
                    }
                } else {
                    val = lbl_803DEFB0;
                }
                scroll = (s16)-(int)(lbl_803DF004 * val);
                if (tex1 != NULL) {
                    *(s16 *)(tex1 + 0xa) = scroll;
                }
                if (tex2 != NULL) {
                    *(s16 *)(tex2 + 0xa) = scroll;
                }
            }

            tex5 = (u8 *)objFindTexture((int)seqObj, 5, 0);
            tex2 = (u8 *)objFindTexture((int)seqObj, 4, 0);
            if (tex5 != NULL) {
                *(int *)tex5 = (s16)seq[0x8d] << 8;
            }
            if (tex2 != NULL) {
                *(int *)tex2 = (s16)seq[0x8e] << 8;
            }
        }
    } else {
        lbl_803DD120 = lbl_803DEFB0;
        lbl_803DD11C = lbl_803DEFB0;
        lbl_803DD118 = lbl_803DEFB0;
        lbl_803DD116 = 0;
        lbl_803DD114 = 1;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int ObjSeq_ExecuteActionCommand(u8 *obj, u8 *action, u8 **cmdPtr, int flags, void *out)
{
    u8 *base = lbl_80396918;
    u8 *cmd;
    u8 *model;
    u8 *seq;
    u8 *activeObj;
    u8 *animState;
    u8 *act2;
    u8 *st2;
    u8 *entry;
    s8 noExec;
    int doUpdate;
    s8 flag8;
    int opcode;
    int sub;
    int restart;
    int reps;
    int val;
    int slot;
    int minRot;
    f32 blend;
    f32 t;

    (void)out;

    cmd = *cmdPtr;
    noExec = (s8)(flags & 1);
    doUpdate = (s8)(flags & 2);
    flag8 = (s8)(flags & 8);
    if (noExec == 0) {
        doUpdate = 1;
    }
    seq = *(u8 **)(obj + 0xb8);
    model = *(u8 **)(obj + 0x4c);
    activeObj = *(u8 **)seq;
    if (activeObj == NULL) {
        activeObj = obj;
    }

    opcode = (s8)cmd[0];
    switch (opcode) {
    case 2:
        if (flag8 != 0) {
            break;
        }
        *(s16 *)(seq + 0x6c) = (s16)(*(s16 *)(cmd + 2) & 0xfff);
        if (*(s16 *)(activeObj + 0x44) == 1 && *(s16 *)(seq + 0x6c) < 4) {
            *(s16 *)(seq + 0x6c) += 0x531;
        }
        seq[0x8c] = (*(s16 *)(cmd + 2) >> 8) & 0xf0;
        if (action == NULL) {
            break;
        }
        animState = *(u8 **)(action + 0x2c);
        if (*(s16 *)(activeObj + 0xa0) == *(s16 *)(seq + 0x6c)) {
            if ((s8)animState[0x60] == 0) {
                restart = 1;
            } else {
                restart = 0;
            }
        } else {
            restart = 1;
        }
        if (doUpdate == 0) {
            break;
        }
        if (restart == 0) {
            break;
        }
        if ((*(s16 *)(seq + 0x6e) & 4) == 0) {
            break;
        }
        if (action == NULL) {
            break;
        }
        *(f32 *)(animState + 4) = *(f32 *)(activeObj + 0x98) * *(f32 *)(animState + 0x14);
        if (*(s16 *)(seq + 0xd6) != 0) {
            sub = *(s16 *)(seq + 0x58) - 1;
            if (*(void **)(seq + 0x98) != NULL && *(s16 *)(seq + 0xd6) != 0) {
                objCurveInterpolate(
                    (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xb0) * 8),
                    *(s16 *)(seq + 0xd6) & 0xfff, sub);
            }
        }
        if (*(s16 *)(activeObj + 0x44) == 1) {
            act2 = *(u8 **)(*(u8 **)(activeObj + 0x7c) + (s8)activeObj[0xad] * 4);
            animState = *(u8 **)(act2 + 0x2c);
            *(s16 *)(animState + 0x64) = -1;
            *(s16 *)(animState + 0x5a) = 0;
            *(s16 *)(animState + 0x5c) = 0;
            st2 = *(u8 **)(act2 + 0x30);
            if (st2 != NULL) {
                *(s16 *)(st2 + 0x64) = -1;
                *(s16 *)(st2 + 0x58) = 0;
                *(s16 *)(st2 + 0x5a) = 0;
                *(s16 *)(st2 + 0x5c) = 0;
            }
        }
        *(f32 *)(seq + 0x20) = lbl_803DEFC8;
        ObjAnim_SetCurrentMove(activeObj, *(s16 *)(seq + 0x6c), 0,
                               (f32)seq[0x8c] * lbl_803DF02C);
        break;
    case 1:
        if (flag8 != 0) {
            break;
        }
        if ((s8)seq[0x7b] != 0 && (s8)base[(s8)seq[0x57] + 0x3a40] != 0) {
            seq[0x78] = 0;
            break;
        }
        seq[0x78] = (s8)(1 - seq[0x78]);
        break;
    case 7:
        seq[0x7a] = (s8)(1 - seq[0x7a]);
        break;
    case 3:
        if (flag8 != 0) {
            break;
        }
        if ((flags & 4) != 0) {
            break;
        }
        activeObj = ObjSeq_ToggleCommand3Target(obj, seq, model);
        *(s16 *)(activeObj + 0xa2) = -1;
        break;
    case 0xb:
        if (doUpdate != 0 && *(s16 *)(cmd + 2) > 0 && lbl_803DD0C0 < 0x14) {
            entry = base + lbl_803DD0C0 * 8;
            *(u8 **)(entry + 0x2b34) = cmd + 4;
            *(s16 *)(entry + 0x2b3a) = *(s16 *)(seq + 0x58);
            reps = *(s16 *)(cmd + 2);
            lbl_803DD0C0 = lbl_803DD0C0 + 1;
            *(s16 *)(entry + 0x2b38) = reps;
        }
        *(s16 *)(seq + 0x66) = *(s16 *)(seq + 0x66) + *(s16 *)(cmd + 2);
        break;
    case 4:
        if (flag8 != 0) {
            break;
        }
        if (doUpdate == 0) {
            break;
        }
        if (action == NULL) {
            break;
        }
        if (*(u8 *)(*(u8 **)action + 0xf9) == 0) {
            break;
        }
        blend = (f32)(int)((*(s16 *)(cmd + 2) >> 8) & 0xff);
        if (lbl_803DEFB0 == blend) {
            t = lbl_803DEFC8;
        } else {
            t = lbl_803DEFC8 / blend;
        }
        sub = *(s16 *)(cmd + 2) & 0xff;
        if (sub < 0xf) {
            ObjModel_SetBlendChannelTargets(action, 2,
                                            (s8)(*(u8 **)(action + 0x28))[0x2d], sub - 1, 0,
                                            t);
        } else {
            ObjModel_SetBlendChannelTargets(action, 0,
                                            (s8)(*(u8 **)(action + 0x28))[0xd], sub - 1, 0,
                                            t);
        }
        break;
    case 0xe:
        if (flag8 != 0) {
            break;
        }
        (*(void (*)(int, int, int, int))(*(int *)(*gGameUIInterface + 0x38)))(
            *(s16 *)(cmd + 2), 0x14, 0x8c, 0);
        break;
    case 0xd:
        if (noExec != 0) {
            break;
        }
        if (((*(s16 *)(cmd + 2) >> 12) & 0xf) == 8) {
            break;
        }
        if ((s8)lbl_803DD113 < 10) {
            entry = base + (s8)lbl_803DD113 * 8;
            *(u8 **)(entry + 0x3ca4) = activeObj;
            *(s8 *)(entry + 0x3caa) = (s8)((*(s16 *)(cmd + 2) >> 12) & 0xf);
            if ((s8)*(entry + 0x3caa) == 0xb || (s8)*(entry + 0x3caa) == 0xc) {
                val = *(s16 *)(cmd + 6);
                slot = (s8)lbl_803DD113;
                lbl_803DD113 = lbl_803DD113 + 1;
                *(s16 *)(base + slot * 8 + 0x3ca8) = val;
            } else {
                val = (s16)(*(s16 *)(cmd + 2) & 0xfff);
                lbl_803DD113 = lbl_803DD113 + 1;
                *(s16 *)(entry + 0x3ca8) = val;
            }
        }
        break;
    case 0:
        break;
    }

    if (noExec != 0) {
        return 0;
    }

    if ((s8)lbl_803DD112 != 0 || (s8)lbl_803DD111 != 0) {
        if ((s8)cmd[0] == 0xd) {
            switch ((*(s16 *)(cmd + 2) >> 12) & 0xf) {
            case 2:
                getEnvfxAct(activeObj, activeObj, *(s16 *)(cmd + 2) & 0xfff, 0);
                break;
            case 6:
                warpToMap(*(s16 *)(cmd + 2) & 0xfff, 0);
                break;
            case 5:
                break;
            }
        }
        return 0;
    }

    switch ((s8)cmd[0]) {
    case 6:
        if (flag8 != 0) {
            break;
        }
        if ((base[(s8)seq[0x57] + 0x3538] & 0x10) == 0) {
            break;
        }
        if ((s8)base[(s8)seq[0x57] + 0x3c4c] == 3) {
            break;
        }
        if (((*(s16 *)(cmd + 2) >> 12) & 0xf) != 0xf) {
            Sfx_PlayFromObject(obj, (u16)(*(s16 *)(cmd + 2) & 0xfff));
        } else {
            Sfx_PlayFromObject(obj, (u16)(*(s16 *)(cmd + 2) & 0xfff));
            *(s16 *)(seq + 0x36) = -1;
            *(s16 *)(seq + 0x3e) = (s16)(*(s16 *)(cmd + 2) & 0xfff);
        }
        break;
    case 0xd:
        switch ((*(s16 *)(cmd + 2) >> 12) & 0xf) {
        case 0:
            if ((base[(s8)seq[0x57] + 0x3538] & 0x10) != 0) {
                val = (*(s16 *)(cmd + 2) & 0xfff) + 1;
                if (val == 0xd9 || val == 0x92) {
                    Music_Trigger(val, 1);
                }
            }
            break;
        case 2:
            getEnvfxAct(activeObj, activeObj, *(s16 *)(cmd + 2) & 0xfff, 0);
            break;
        case 6:
            if (flag8 != 0) {
                break;
            }
            warpToMap(*(s16 *)(cmd + 2) & 0xfff, 0);
            break;
        case 7:
            break;
        case 8:
            if (flag8 != 0) {
                break;
            }
            seq[0x8d] = (u8)(*(s16 *)(cmd + 2) & 0xfff);
            seq[0x8e] = seq[0x8d];
            break;
        case 0xe:
            if (flag8 != 0) {
                break;
            }
            seq[0x8d] = (u8)(*(s16 *)(cmd + 2) & 0xfff);
            break;
        case 0xf:
            if (flag8 != 0) {
                break;
            }
            seq[0x8e] = (u8)(*(s16 *)(cmd + 2) & 0xfff);
            break;
        }
        break;
    case 0xf:
        if (flag8 != 0) {
            break;
        }
        if ((base[(s8)seq[0x57] + 0x3538] & 0x10) == 0) {
            break;
        }
        if ((s8)base[(s8)seq[0x57] + 0x3c4c] == 3) {
            break;
        }
        if (((*(s16 *)(cmd + 2) >> 12) & 0xf) != 0xf) {
            minRot = 0x7fff;
            slot = 0;
            if (*(s16 *)(seq + 0x30) < 0x7fff) {
                slot = 0;
                minRot = *(s16 *)(seq + 0x30);
            }
            if (*(s16 *)(seq + 0x32) < (s16)minRot) {
                slot = 1;
                minRot = *(s16 *)(seq + 0x32);
            }
            if (*(s16 *)(seq + 0x34) < (s16)minRot) {
                slot = 2;
            }
        } else {
            slot = 3;
        }
        entry = seq + slot * 2;
        if (*(s16 *)(entry + 0x30) > 0) {
            Sfx_RemoveLoopedObjectSound(obj, (u16)*(s16 *)(entry + 0x38));
        }
        cmd[1] = cmd[5];
        cmd[4] = 0x63;
        *(s16 *)(entry + 0x30) = *(s16 *)(cmd + 6);
        *(s16 *)(seq + slot * 2 + 0x38) = (s16)(*(s16 *)(cmd + 2) & 0xfff);
        Sfx_AddLoopedObjectSound(obj, (u16)*(s16 *)(seq + slot * 2 + 0x38));
        break;
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int ObjSeq_update(u8 *obj, f32 t)
{
    u8 *base = lbl_80396918;
    u8 *activeObj;
    u8 *action;
    u8 *cmd;
    f32 scratch[2];
    u8 *model;
    u8 *seq;
    u8 *p;
    u8 *entry;
    int runs;
    int step;
    int slot;
    int i;
    int k;
    int stop;
    int opcode;
    int found;
    int pressed;
    int targetFrame;
    int restart;
    int aInt;
    f32 val;
    f32 rate;
    f32 fval;
    f32 prevX;
    f32 prevZ;
    f32 px;
    f32 pz;
    int (*cb)(void *, u8 *);

    (void)t;

    runs = 0;
    step = lbl_803DB411;
    model = *(u8 **)(obj + 0x4c);
    if (model == NULL) {
        return 1;
    }

    seq = *(u8 **)(obj + 0xb8);
    if ((seq[0x7f] & 2) != 0) {
        setJoypadDisabled();
    }
    activeObj = *(u8 **)seq;
    lbl_803DD0DA = 0;
    lbl_803DD114 = 0;
    lbl_803DD112 = 0;
    lbl_803DD111 = 0;

    if (seq[0x7e] == 3) {
        if (*(void **)seq != NULL) {
            *(void **)(activeObj + 0xc0) = obj;
            *(u16 *)(activeObj + 0xb0) |= 0x1000;
        }
        return 0;
    }

    slot = (s8)seq[0x57];
    if (base[slot + 0x338c] == 1) {
        *(s16 *)(seq + 0x58) = *(s16 *)(base + slot * 2 + 0x3694);
        *(s16 *)(seq + 0x5a) = *(s16 *)(seq + 0x58);
        ObjSeq_RefreshActionCursor(obj, activeObj, seq);
    } else {
        *(s16 *)(seq + 0x58) = (int)*(f32 *)(base + slot * 4 + 0x3894);
    }

    p = seq + 6;
    for (i = 3; i != 0; i--) {
        p -= 2;
        if (*(s16 *)(p + 0x30) > 0) {
            *(s16 *)(p + 0x30) = *(s16 *)(p + 0x30) - framesThisStep;
            if (*(s16 *)(p + 0x30) <= 0) {
                *(s16 *)(p + 0x30) = 0;
                Sfx_RemoveLoopedObjectSound(obj, (u16)*(s16 *)(p + 0x38));
            }
        }
    }
    base[(s8)seq[0x57] + 0x3cf4] = 0;

    do {
        lbl_803DD113 = 0;
        if (seq[0x7e] == 0) {
            obj[0x36] = 0;
            return 1;
        }

        activeObj = obj;
        if (*(void **)seq != NULL) {
            activeObj = *(u8 **)seq;
            *(void **)(activeObj + 0xc0) = obj;
            *(u16 *)(activeObj + 0xb0) |= 0x1000;
        } else if ((s8)seq[0x7b] == 0 && (s8)seq[0x56] < 4) {
            *(s8 *)(seq + 0x56) = -1;
        }

        slot = (s8)seq[0x57];
        if ((s8)base[slot + 0x3c4c] != 0 && (s8)base[slot + 0x39e8] != 0) {
            *(s16 *)(seq + 0x58) = *(s16 *)(seq + 0x58) - (s8)base[slot + 0x39e8];
            if (*(s16 *)(seq + 0x58) < 0) {
                *(s16 *)(seq + 0x58) = 0;
            }
            *(s16 *)(seq + 0x5a) = (s16)(*(s16 *)(seq + 0x58) - 1);
            objSeqUpdateCurves(obj, activeObj, seq, 1);
        }

        lbl_803DD0D8 = 0;
        if (activeObj != obj) {
            objCallSeqFn(activeObj, obj, seq, base[(s8)seq[0x57] + 0x3c4c]);
            lbl_803DD0D8 = 1;
        }

        if ((seq[0x90] & 1) != 0) {
            base[(s8)seq[0x57] + 0x3b9c] = 1;
        }
        if ((seq[0x90] & 2) != 0) {
            base[(s8)seq[0x57] + 0x3b9c] = 0;
        }
        if ((seq[0x90] & 4) != 0) {
            base[(s8)seq[0x57] + 0x3b44] = 1;
        }
        if ((seq[0x90] & 8) != 0) {
            base[(s8)seq[0x57] + 0x3b44] = 0;
        }
        if ((seq[0x90] & 0x10) != 0) {
            base[(s8)seq[0x57] + 0x3a40] = 1;
        }
        if ((seq[0x90] & 0x20) != 0) {
            base[(s8)seq[0x57] + 0x3a40] = 0;
        }

        if (seq[0x7e] == 2) {
            ObjSeq_SetupInitialPlaybackState(obj, &activeObj, seq, model, (void **)&action);
            return 0;
        }

        if ((s8)base[(s8)seq[0x57] + 0x3c4c] == 1) {
            step = 0;
        } else if ((s8)base[(s8)seq[0x57] + 0x3c4c] == 2) {
            *(s16 *)(seq + 0x58) = *(s16 *)(seq + 0x5c);
            lbl_803DD112 = 1;
        } else if ((s8)base[(s8)seq[0x57] + 0x3c4c] == 3) {
            found = objSeqFindConditional(seq, obj);
            if (found > -1) {
                base[(s8)seq[0x57] + 0x3cf4] = 1;
                *(s16 *)(seq + 0x58) = (s16)found;
                *(s16 *)(seq + 0x5a) = *(s16 *)(seq + 0x58);
            }
        }

        if (*(void **)seq != NULL && *(s16 *)(*(u8 **)seq + 0xb4) != -1 &&
            (base[(s8)seq[0x57] + 0x3538] & 0x10) == 0) {
            (*(void (*)(int, int))(*(int *)(*gCameraInterface + 0x5c)))(0x41, 1);
        }

        slot = (s8)seq[0x57];
        if (base[slot + 0x3590] != 0) {
            *(s16 *)(seq + 0x1a) = *(s16 *)(base + slot * 2 + 0x35e8);
        }

        if ((s8)seq[0x7c] != 0) {
            if (seqEvalCondition((s8)seq[0x7c] - 1, seq, (int)model) == 0) {
                seq[0x7c] = 0;
            } else {
                *(f32 *)(base + (s8)seq[0x57] * 4 + 0x3740) = (f32)*(s16 *)(seq + 0x58);
                return 0;
            }
        }

        *(s16 *)(seq + 0x58) = (s16)(*(s16 *)(seq + 0x58) + step);
        if (*(s16 *)(seq + 0x58) > *(s16 *)(seq + 0x5c)) {
            *(s16 *)(seq + 0x58) = *(s16 *)(seq + 0x5c);
        }
        targetFrame = *(s16 *)(seq + 0x58);
        objSeqUpdateMoreCurves(obj, activeObj, seq, targetFrame);
        *(f32 *)(obj + 0xc) = *(f32 *)(obj + 0xc) + *(f32 *)(seq + 4);
        *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x10) + *(f32 *)(seq + 8);
        *(f32 *)(obj + 0x14) = *(f32 *)(obj + 0x14) + *(f32 *)(seq + 0xc);
        *(u16 *)(obj + 4) = *(s16 *)(obj + 4) + *(s16 *)(seq + 0x18);
        *(u16 *)(obj + 2) = *(s16 *)(obj + 2) + *(s16 *)(seq + 0x16);
        *(u16 *)(obj + 0) = *(s16 *)(obj + 0) + *(s16 *)(seq + 0x14);

        action = *(u8 **)(*(u8 **)(activeObj + 0x7c) + (s8)activeObj[0xad] * 4);
        lbl_803DD0C0 = 0;
        if (action != NULL) {
            if (*(void **)(seq + 0x98) == NULL) {
                val = lbl_803DEFB0;
            } else {
                val = lbl_803DEFB0;
                if (*(s16 *)(seq + 0xdc) != 0) {
                    val = objCurveInterpolate(
                        (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xb6) * 8),
                        *(s16 *)(seq + 0xdc) & 0xfff, *(s16 *)(seq + 0x5a));
                }
            }
            prevX = *(f32 *)(model + 0x8) + val;
            if (*(void **)(seq + 0x98) == NULL) {
                val = lbl_803DEFB0;
            } else {
                val = lbl_803DEFB0;
                if (*(s16 *)(seq + 0xd8) != 0) {
                    val = objCurveInterpolate(
                        (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xb2) * 8),
                        *(s16 *)(seq + 0xd8) & 0xfff, *(s16 *)(seq + 0x5a));
                }
            }
            prevZ = *(f32 *)(model + 0x10) + val;
        }
        *(s16 *)(seq + 0x58) = *(s16 *)(seq + 0x5a);

        while (*(s16 *)(seq + 0x58) < targetFrame) {
            *(s16 *)(seq + 0x58) += 1;
            if (*(void **)(seq + 0x98) == NULL) {
                val = lbl_803DEFB0;
            } else {
                val = lbl_803DEFB0;
                if (*(s16 *)(seq + 0xdc) != 0) {
                    val = objCurveInterpolate(
                        (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xb6) * 8),
                        *(s16 *)(seq + 0xdc) & 0xfff, *(s16 *)(seq + 0x58));
                }
            }
            px = *(f32 *)(model + 0x8) + val;
            if (*(void **)(seq + 0x98) == NULL) {
                val = lbl_803DEFB0;
            } else {
                val = lbl_803DEFB0;
                if (*(s16 *)(seq + 0xd8) != 0) {
                    val = objCurveInterpolate(
                        (ObjCurveKey *)(*(u8 **)(seq + 0x98) + *(s16 *)(seq + 0xb2) * 8),
                        *(s16 *)(seq + 0xd8) & 0xfff, *(s16 *)(seq + 0x58));
                }
            }
            pz = *(f32 *)(model + 0x10) + val;

            if (*(s16 *)(seq + 0x58) > 0 && (*(s16 *)(seq + 0x6e) & 4) != 0) {
                if ((s8)seq[0x78] == 1 && (s8)seq[0x7b] == 0 && action != NULL) {
                    if (ObjAnim_SampleRootCurvePhase(
                            activeObj, &scratch[1],
                            sqrtf((px - prevX) * (px - prevX) +
                                  (pz - prevZ) * (pz - prevZ))) == 0) {
                        i = *(s16 *)(seq + 0x58) - 1;
                        if (*(void **)(seq + 0x98) == NULL) {
                            val = lbl_803DEFB0;
                        } else {
                            val = lbl_803DEFB0;
                            if (*(s16 *)(seq + 0xd4) != 0) {
                                val = objCurveInterpolate(
                                    (ObjCurveKey *)(*(u8 **)(seq + 0x98) +
                                                    *(s16 *)(seq + 0xae) * 8),
                                    *(s16 *)(seq + 0xd4) & 0xfff, i);
                            }
                        }
                        scratch[1] = lbl_803DF030 * val;
                    }
                } else {
                    i = *(s16 *)(seq + 0x58) - 1;
                    if (*(void **)(seq + 0x98) == NULL) {
                        val = lbl_803DEFB0;
                    } else {
                        val = lbl_803DEFB0;
                        if (*(s16 *)(seq + 0xd4) != 0) {
                            val = objCurveInterpolate(
                                (ObjCurveKey *)(*(u8 **)(seq + 0x98) +
                                                *(s16 *)(seq + 0xae) * 8),
                                *(s16 *)(seq + 0xd4) & 0xfff, i);
                        }
                    }
                    scratch[1] = lbl_803DF030 * val;
                }

                if (action != NULL) {
                    ObjAnim_AdvanceCurrentMove(activeObj, seq + 0xf0, scratch[1],
                                               lbl_803DEFC8);
                    if (*(f32 *)(seq + 0x20) > lbl_803DEFB0) {
                        if (*(s16 *)(seq + 0xd6) != 0) {
                            i = *(s16 *)(seq + 0x58) - 1;
                            if (*(void **)(seq + 0x98) != NULL && *(s16 *)(seq + 0xd6) != 0) {
                                rate = objCurveInterpolate(
                                    (ObjCurveKey *)(*(u8 **)(seq + 0x98) +
                                                    *(s16 *)(seq + 0xb0) * 8),
                                    *(s16 *)(seq + 0xd6) & 0xfff, i);
                            }
                        } else {
                            rate = lbl_803DF034;
                        }
                        if (rate < lbl_803DEFC8) {
                            rate = lbl_803DEFC8;
                        }
                        *(f32 *)(seq + 0x20) = *(f32 *)(seq + 0x20) - lbl_803DEFC8 / rate;
                        if (*(f32 *)(seq + 0x20) < lbl_803DEFB0) {
                            *(f32 *)(seq + 0x20) = lbl_803DEFB0;
                        }
                    }
                } else {
                    *(f32 *)(activeObj + 0x98) = *(f32 *)(activeObj + 0x98) + scratch[1];
                    while (*(f32 *)(activeObj + 0x98) > lbl_803DEFC8) {
                        *(f32 *)(activeObj + 0x98) =
                            *(f32 *)(activeObj + 0x98) - lbl_803DEFC8;
                    }
                    while (*(f32 *)(activeObj + 0x98) < lbl_803DEFB0) {
                        *(f32 *)(activeObj + 0x98) =
                            *(f32 *)(activeObj + 0x98) + lbl_803DEFC8;
                    }
                }
            }

            prevX = px;
            prevZ = pz;

            stop = 0;
            while (stop == 0 && *(s16 *)(seq + 0x66) < *(s16 *)(seq + 0x62)) {
                cmd = *(u8 **)(seq + 0x94) + *(s16 *)(seq + 0x66) * 4;
                opcode = (s8)cmd[0];
                if (opcode == 0) {
                    if (*(s16 *)(seq + 0x58) >= *(s16 *)(cmd + 2)) {
                        *(s16 *)(seq + 0x68) = *(s16 *)(cmd + 2);
                        *(s16 *)(seq + 0x66) = *(s16 *)(seq + 0x66) + 1;
                    } else {
                        stop = 1;
                    }
                } else {
                    if (*(s16 *)(seq + 0x58) >= *(s16 *)(seq + 0x68)) {
                        if (opcode != 0xf) {
                            *(s16 *)(seq + 0x68) = *(s16 *)(seq + 0x68) + cmd[1];
                        }
                        *(s16 *)(seq + 0x66) = *(s16 *)(seq + 0x66) + 1;
                        if (ObjSeq_ExecuteActionCommand(obj, action, &cmd, 0, 0) != 0) {
                            targetFrame = *(s16 *)(seq + 0x58);
                        }
                        activeObj = *(u8 **)*(u8 **)(obj + 0xb8);
                        if (activeObj == NULL) {
                            activeObj = obj;
                        }
                        action = *(u8 **)(*(u8 **)(activeObj + 0x7c) +
                                          (s8)activeObj[0xad] * 4);
                    } else {
                        stop = 1;
                    }
                }
            }
        }

        for (k = 0; k < 10; k++) {
            opcode = seq[k + 0x12c];
            if (opcode == 0) {
                continue;
            }
            switch (opcode) {
            case 0x12:
                if ((getButtonsJustPressed(0) & 0x100) != 0) {
                    pressed = 1;
                } else {
                    pressed = 0;
                }
                break;
            case 0x13:
                if ((getButtonsJustPressed(0) & 0x200) != 0) {
                    pressed = 1;
                } else {
                    pressed = 0;
                }
                break;
            case 0x1a:
                pressed = isTalkingToNpc() == 0;
                break;
            default:
                cb = *(int (**)(void *, u8 *))(seq + 0xec);
                if (cb != NULL) {
                    pressed = cb(*(void **)(seq + 0x110), obj);
                } else {
                    pressed = 0;
                }
                break;
            }
            if (pressed != 0) {
                base[(s8)seq[0x57] + 0x3cf4] = 1;
                *(s16 *)(seq + 0x58) = *(s16 *)(seq + k * 2 + 0x118);
                *(s16 *)(seq + 0x5a) = *(s16 *)(seq + 0x58);
                seq[0x12c] = 0;
                seq[0x12d] = 0;
                seq[0x12e] = 0;
                seq[0x12f] = 0;
                seq[0x130] = 0;
                seq[0x131] = 0;
                seq[0x132] = 0;
                seq[0x133] = 0;
                seq[0x134] = 0;
                seq[0x135] = 0;
                break;
            }
        }

        if ((s8)lbl_803DD0D8 == 0 && activeObj != obj) {
            objCallSeqFn(activeObj, obj, seq, base[(s8)seq[0x57] + 0x3c4c]);
        }

        if (seq[0x90] != 0) {
            restart = 0;
            if ((seq[0x90] & 0x40) != 0) {
                restart = 1;
                seq[0x90] = seq[0x90] & ~0x40;
                *(s16 *)(seq + 0x58) = (s16)*(int *)(seq + 0x74);
                *(s16 *)(seq + 0x5a) = *(s16 *)(seq + 0x58);
            }
            seq[0x90] = 0;
            base[(s8)seq[0x57] + 0x3cf4] = (s8)restart;
        }

        seq[0x8b] = 0;
        seq[0x80] = 0;
        if (action != NULL && (*(s16 *)(seq + 0x6e) & 4) != 0) {
            *(s16 *)(*(u8 **)(action + 0x2c) + 0x58) =
                (u16)(int)(SendMailData * *(f32 *)(seq + 0x20));
        }
        objAnimCurvFn_800849e8(obj, seq);
        if ((s8)seq[0x7a] == 1 &&
            hitDetectFn_800658a4(obj, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10),
                                 *(f32 *)(obj + 0x14), scratch, 0) == 0) {
            *(f32 *)(obj + 0x10) =
                *(f32 *)(obj + 0x10) +
                ((*(f32 *)(obj + 0x10) - scratch[0]) - *(f32 *)(model + 0xc));
        }
        *(u16 *)obj = *(s16 *)obj + *(s16 *)(seq + 0x1a);
        objAnimFn_8008718c(obj, activeObj, seq);
        objSeqDoBgCmds0D(seq, activeObj, 0);

        for (k = 0; k < lbl_803DD0C0; k++) {
            entry = base + k * 8 + 0x2b34;
            if (seqDoSubCmd0B(obj, activeObj, seq, *(u8 **)entry, *(s16 *)(entry + 6),
                              *(s16 *)(entry + 4), 0, 0) != 0) {
                k = lbl_803DD0C0;
            }
            activeObj = *(u8 **)*(u8 **)(obj + 0xb8);
            if (activeObj == NULL) {
                activeObj = obj;
            }
            action = *(u8 **)(*(u8 **)(activeObj + 0x7c) + (s8)activeObj[0xad] * 4);
        }

        if (lbl_803DD070 != 0) {
            lbl_803DD070 = seqStreamFn_8008023c(lbl_803DB720) == 0;
        }
        *(s16 *)(seq + 0x5a) = *(s16 *)(seq + 0x58);

        if ((s8)lbl_803DD0DA != 0) {
            activeObj = *(u8 **)*(u8 **)(obj + 0xb8);
            if (activeObj == NULL) {
                activeObj = obj;
            }
            action = *(u8 **)(*(u8 **)(activeObj + 0x7c) + (s8)activeObj[0xad] * 4);
            animatedObjFreeAndSavePlayerPos(obj, activeObj, seq);
        } else {
            slot = (s8)seq[0x57];
            if ((s8)base[slot + 0x3cf4] != 0) {
                *(s16 *)(base + slot * 2 + 0x3694) = *(s16 *)(seq + 0x58);
                base[(s8)seq[0x57] + 0x338c] = 2;
                *(f32 *)(base + (s8)seq[0x57] * 4 + 0x3740) = (f32)*(s16 *)(seq + 0x58);
            }
            slot = (s8)seq[0x57];
            if (lbl_803DEFF0 == *(f32 *)(base + slot * 4 + 0x3740)) {
                if (lbl_803DB724 == slot) {
                    fval = lbl_803DD074;
                    aInt = (int)fval;
                    fval = fval - RecvDataLeng;
                    lbl_803DD074 = fval;
                    if (aInt != (int)fval) {
                        step--;
                        if (fval <= lbl_803DEFB0) {
                            lbl_803DB724 = -1;
                        }
                    }
                }
                *(f32 *)(base + (s8)seq[0x57] * 4 + 0x3740) =
                    (f32)step + *(f32 *)(base + (s8)seq[0x57] * 4 + 0x3894);
            }
        }

        if ((s8)lbl_803DD0DA != 0) {
            break;
        }
        if (*(s16 *)(seq + 0x58) >= *(s16 *)(seq + 0x5c)) {
            break;
        }
    } while (runs-- != 0);

    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void ObjSeq_SetupInitialPlaybackState(u8 *obj, u8 **seqObj, u8 *seq, u8 *sourceObj, void **outAction)
{
    u8 *activeObj;
    s16 *modelVec;
    f32 groundY[2];
    long long time;
    u8 *historyBase;

    historyBase = lbl_80396918;
    if ((s8)seq[0x7b] != 0) {
        lbl_803DD108 = 1;
        lbl_803DD100 = 0x5a;
        lbl_803DD10C = 0x42;
    }

    *(s16 *)(seq + 0x58) = *(s16 *)(seq + 0x5e);
    *(s16 *)(seq + 0x5a) = -0x3c;
    objSeqUpdateMoreCurves(obj, *seqObj, seq, 0);
    objSeqUpdateCurves(obj, *seqObj, seq, 1);

    activeObj = *(u8 **)(*(u8 **)(obj + 0xb8));
    if (activeObj == NULL) {
        activeObj = obj;
    }
    *outAction = *(void **)(*(u8 **)(activeObj + 0x7c) + (s8)activeObj[0xad] * 4);
    *seqObj = activeObj;

    ObjSeq_UpdateCurvePosition(obj, seq);
    if ((s8)seq[0x7a] == 1 &&
        hitDetectFn_800658a4(obj, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10),
                             *(f32 *)(obj + 0x14), groundY, 0) == 0) {
        *(f32 *)(obj + 0x10) =
            *(f32 *)(obj + 0x10) + ((*(f32 *)(obj + 0x10) - groundY[0]) - *(f32 *)(sourceObj + 0xc));
    }

    *(u16 *)obj = *(s16 *)obj + *(s16 *)(seq + 0x1a);
    if (*seqObj != obj && (s8)lbl_803DD0D8 == 0) {
        objCallSeqFn(*seqObj, obj, seq, *(u8 *)(historyBase + (s8)seq[0x57] + 0x3c4c));
    }

    objAnimFn_8008718c(obj, *seqObj, seq);
    seq[0x8d] = 0;
    seq[0x8e] = 0;
    seq[0x7e] = 1;
    *(s16 *)(seq + 0x5a) = *(s16 *)(seq + 0x58);
    if ((s8)lbl_803DD0DA != 0) {
        animatedObjFreeAndSavePlayerPos(obj, *seqObj, seq);
    }

    *(f32 *)(historyBase + (s8)seq[0x57] * 4 + 0x3740) = (f32)*(s16 *)(seq + 0x58);
    *(s16 *)(historyBase + (s8)seq[0x57] * 2 + 0x2be0) = *(s16 *)(seq + 0x58);
    time = OSGetTime();
    *(long long *)(historyBase + (s8)seq[0x57] * 8 + 0x2f38) = time;
    time = OSGetTime();
    *(long long *)(historyBase + (s8)seq[0x57] * 8 + 0x2c90) = time;

    if (*seqObj != NULL) {
        objModelClearVecFn_8003aa40(*seqObj);
        if (*(s16 *)(*seqObj + 0x44) == 1) {
            modelVec = objModelGetVecFn_800395d8(obj, 1);
            if (modelVec != NULL) {
                modelVec[0] = 0;
                modelVec[1] = 0;
                modelVec[2] = 0;
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void objAnimFn_8008718c(u8 *obj, u8 *seqObj, u8 *seq)
{
    s16 basePitch;
    s16 baseYaw;
    s16 baseRoll;
    f32 baseX;
    f32 baseY;
    f32 baseZ;

    if (*(void **)(seqObj + 0x30) == *(void **)(obj + 0x30) || (s8)lbl_803DD114 == 0) {
        baseX = *(f32 *)(obj + 0xc);
        baseY = *(f32 *)(obj + 0x10);
        baseZ = *(f32 *)(obj + 0x14);
        basePitch = *(s16 *)(obj + 0);
    } else {
        baseX = lbl_803DD120;
        baseY = lbl_803DD11C;
        baseZ = lbl_803DD118;
        basePitch = lbl_803DD116;
    }

    baseYaw = *(s16 *)(obj + 2);
    baseRoll = *(s16 *)(obj + 4);
    if (seqObj != obj) {
        if ((*(s16 *)(seq + 0x6e) & 1) != 0) {
            if ((s8)seq[0x56] == 2) {
                *(f32 *)(seqObj + 0xc) = *(f32 *)(seq + 0x40) * *(f32 *)(seq + 0x4c) + baseX;
                *(f32 *)(seqObj + 0x10) = *(f32 *)(seq + 0x44) * *(f32 *)(seq + 0x4c) + baseY;
                *(f32 *)(seqObj + 0x14) = *(f32 *)(seq + 0x48) * *(f32 *)(seq + 0x4c) + baseZ;
            } else {
                *(f32 *)(seqObj + 0xc) = baseX;
                *(f32 *)(seqObj + 0x10) = baseY;
                *(f32 *)(seqObj + 0x14) = baseZ;
            }
        }
        if ((*(s16 *)(seq + 0x6e) & 2) != 0) {
            if ((s8)seq[0x56] == 2) {
                *(s16 *)(seqObj + 0) =
                    (s16)(basePitch + (s32)((f32)*(s16 *)(seq + 0x50) * *(f32 *)(seq + 0x4c)));
                *(s16 *)(seqObj + 2) =
                    (s16)(baseYaw + (s32)((f32)*(s16 *)(seq + 0x52) * *(f32 *)(seq + 0x4c)));
                *(s16 *)(seqObj + 4) =
                    (s16)(baseRoll + (s32)((f32)*(s16 *)(seq + 0x54) * *(f32 *)(seq + 0x4c)));
            } else {
                *(s16 *)(seqObj + 0) = basePitch;
                *(s16 *)(seqObj + 2) = baseYaw;
                *(s16 *)(seqObj + 4) = baseRoll;
            }
        }
    }

    if ((s8)seq[0x7b] != 0 && (s8)seq[0x78] != 0) {
        lbl_803DD0B8 = obj;
        lbl_803DD0B6 = framesThisStep;
    }
    Obj_GetWorldPosition(seqObj, (f32 *)(seqObj + 0x18), (f32 *)(seqObj + 0x1c),
                         (f32 *)(seqObj + 0x20));
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int seqEvalCondition(int condition, u8 *seq, int obj)
{
    int tailState;
    int result;

    result = 0;

    switch (condition) {
    case 0:
        if (*(s16 *)(seq + 0x60) <= 0) {
            result = 1;
        }
        break;
    case 1:
        if (*(s16 *)(seq + 0x60) > 0) {
            result = 1;
        }
        break;
    case 2:
        if ((*(int (**)(int *))((u8 *)(*gSHthorntailAnimationInterface) + 0x24))(&tailState) == 0) {
            result = 1;
        }
        break;
    case 3:
        if ((*(int (**)(int *))((u8 *)(*gSHthorntailAnimationInterface) + 0x24))(&tailState) != 0) {
            result = 1;
        }
        break;
    case 4:
        if (lbl_8039A45C[(s8)seq[0x57]] == 0) {
            result = 1;
        }
        break;
    case 5:
        if (lbl_8039A45C[(s8)seq[0x57]] == 1) {
            result = 1;
        }
        break;
    case 6:
        if (lbl_8039A4B4[(s8)seq[0x57]] == 0) {
            result = 1;
        }
        break;
    case 7:
        if (lbl_8039A4B4[(s8)seq[0x57]] != 0) {
            result = 1;
        }
        break;
    case 8:
        if (seqGlobal1 <= 0) {
            result = 1;
        }
        break;
    case 9:
        if (seqGlobal1 > 0) {
            result = 1;
        }
        break;
    case 10:
        if (seqGlobal2 <= 0) {
            result = 1;
        }
        break;
    case 11:
        if (seqGlobal2 > 0) {
            result = 1;
        }
        break;
    case 12:
        if (isGameTimerDisabled() != 0) {
            result = 1;
        }
        break;
    case 13:
        if (isGameTimerDisabled() == 0) {
            result = 1;
        }
        break;
    case 14:
        if (seqGlobal3 != 0) {
            result = 1;
        }
        break;
    case 15:
        if (seqGlobal3 == 0) {
            result = 1;
        }
        break;
    case 16:
    case 17:
    default:
        result = 1;
        break;
    }
    return result;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void ObjSeq_setXrot(int index, int xrot)
{
    s16 xrot16;

    lbl_80399EA8[index] = 1;
    xrot16 = xrot;
    lbl_80399F00[index] = xrot16;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int ObjSeq_getBool(int index)
{
    if (index < 0 || index >= 0x55) {
        return 0;
    }
    return lbl_8039A45C[index];
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void ObjSeq_setFlag(int index, int value)
{
    s8 flag;

    if (index < 0) {
        return;
    }
    if (index >= 0x55) {
        return;
    }
    flag = value;
    lbl_8039A45C[index] = flag;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void ObjSeq_addBgCmd(int index, int xrot, int yrot)
{
    s8 count;
    s16 shortIndex;
    s16 shortXrot;
    s16 shortYrot;

    if (index < 0) {
        return;
    }
    if (index >= 0x55) {
        return;
    }

    count = lbl_803DD0BC;
    if (count >= 0x1e) {
        return;
    }

    shortIndex = index;
    shortYrot = yrot;
    lbl_80399398[count * 3] = shortIndex;
    lbl_80399398[count * 3 + 2] = shortYrot;
    shortXrot = xrot;
    lbl_803DD0BC++;
    lbl_80399398[count * 3 + 1] = shortXrot;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void ObjSeq_objLoadAnimData(u8 *seq, u8 *obj)
{
    u8 *base = lbl_80396918;
    int animId;
    int fileOffset;
    struct {
        char tag[4];
        s16 size;
        s16 count;
    } hdr;

    if (*(s16 *)(obj + 0x18) == -1) {
        return;
    }

    *(s16 *)(seq + 0x64) = 0;
    *(s16 *)(seq + 0x62) = 0;
    animId = *(s16 *)(obj + 0x18);
    if ((animId & 0x8000) != 0) {
        getTabEntry(lbl_803DD0D4, 0xf, ((animId & 0x7ff0) >> 4) * 2, 8);
        animId = *(s16 *)lbl_803DD0D4 + (animId & 0xf);
    } else {
        animId = animId + 1;
    }

    if (getTableFileEntry(0xe, animId, &fileOffset) == 0) {
        fn_80137948(sObjLoadAnimdataNullACRomTabWarning);
        return;
    }

    loadAndDecompressDataFile(0xd, &hdr, fileOffset, 8, 0, 0, 0);
    if (strncmp(hdr.tag, &sSeqAAnimDataTag, 4) != 0 &&
        strncmp(hdr.tag, &sSeqBAnimDataTag, 4) != 0) {
        fn_80137948(sObjLoadAnimdataNullACRomTabWarning);
        return;
    }

    *(s16 *)(seq + 0x62) = hdr.count;
    if (hdr.size == 0) {
        fn_80137948(sObjLoadAnimdataNullACRomTabWarning);
        return;
    }

    *(void **)(seq + 0x94) = mmAlloc(hdr.size, 0x11, 0);
    if (*(void **)(seq + 0x94) == NULL) {
        fn_80137948(sObjLoadAnimdataNullACRomTabWarning);
        return;
    }

    loadAndDecompressDataFile(0xd, *(void **)(seq + 0x94), fileOffset + 8, hdr.size, 0, 0, 0);
    *(s16 *)(seq + 0x64) = (s16)(((hdr.size >> 2) - hdr.count) >> 1);
    *(void **)(seq + 0x98) = *(u8 **)(seq + 0x94) + hdr.count * 4;

    seq[0x57] = obj[0x1f];
    if ((s8)seq[0x57] > -1) {
        base[(s8)seq[0x57] + 0x3b9c] = 0;
        base[(s8)seq[0x57] + 0x3b44] = 0;
        base[(s8)seq[0x57] + 0x3a40] = 0;
    }

    if ((s8)obj[0x22] != 0) {
        seq[0x7e] = 2;
    } else {
        seq[0x7e] = 0;
    }
    ObjSeq_seqState_init(seq);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void ObjSeq_seqState_free(u8 *seq)
{
    void *ptr;

    ptr = *(void **)(seq + 0x94);
    if (ptr != NULL) {
        mm_free(ptr);
        *(void **)(seq + 0x94) = NULL;
        *(void **)(seq + 0x98) = NULL;
    }
    ptr = *(void **)(seq + 0x2c);
    if (ptr != NULL) {
        mm_free(ptr);
        *(void **)(seq + 0x2c) = NULL;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void ObjSeq_seqState_init(u8 *seq)
{
    int animIndex;
    int runLength;
    int track;
    int animCount;
    u8 *animEntry;
    int commandIndex;
    u8 *command;

    for (track = 0; track < 0x13; track++) {
        *(s16 *)(seq + 0xc2 + track * 2) = 0;
    }

    track = 0;
    animIndex = 0;
    while (animIndex < *(s16 *)(seq + 0x64)) {
        runLength = 0;
        animCount = *(s16 *)(seq + 0x64);
        while (animIndex + runLength < animCount) {
            animEntry = *(u8 **)(seq + 0x98) + (animIndex + runLength) * 8;
            if (track == ((s8)animEntry[5] & 0x1f)) {
                runLength++;
            } else {
                break;
            }
        }
        *(s16 *)(seq + 0xc2 + track * 2) = runLength;
        *(s16 *)(seq + 0x9c + track * 2) = animIndex;
        track++;
        animIndex += runLength;
    }

    *(s16 *)(seq + 0x5c) = 1000;
    commandIndex = 0;
    while (commandIndex < 2 && commandIndex < *(s16 *)(seq + 0x62)) {
        command = *(u8 **)(seq + 0x94) + commandIndex * 4;
        if ((s8)command[0] == -1) {
            *(s16 *)(seq + 0x5c) = *(s16 *)(command + 2) + 1;
        }
        commandIndex++;
    }
}
#pragma scheduling reset
#pragma peephole reset

void fn_80081940(void)
{
}

int fn_80081944(void)
{
    return 0;
}

int fn_8008194C(void)
{
    return 0;
}

void fn_80081954(int value)
{
    lbl_803DD084 = value;
}

int fn_8008195C(void)
{
    return lbl_803DD084;
}

int fn_80081964(void)
{
    return 1;
}

typedef struct SeqRunRec {
    s16 slot;
    s16 flags;
    s16 count;
} SeqRunRec;

typedef struct SeqRunTables {
    u8 pad0[0x2a80];
    SeqRunRec recs[0x1e];
    u8 pad1[0x800];
    u8 marks[0xb0];
    int handles[0x55];
    u8 cmdFlags[0x58];
    u8 counts[0x58];
    s16 headings[0x55];
    u8 pad2[0xae];
    f32 dists[0x55];
    f32 frames[0x55];
    u8 pad3[0xb0];
    s16 modes[0x55];
} SeqRunTables;

#pragma peephole off
#pragma scheduling off
int objRunSeq(int seqIdx, u8 *obj, int flags)
{
    u8 *base;
    u8 *walk2;
    u8 *walk;
    int packed;
    u8 *mon;
    int i;
    int idx;
    int count;
    int first;
    int bit;
    int objId;
    int slot;
    u8 *hdr;
    u8 *parent;
    u8 *srcSeq;
    u8 *setup;
    u8 *seq;
    int size;
    s16 heading;
    int camArg;
    u8 *player;
    int doCam;
    u8 *newObj;
    u8 *slotPtr;
    u8 *buf;
    u8 *blk;
    u8 *p;
    s16 *mapTbl;
    int j;
    int k;
    int v;
    int seqFlags;
    int found;
    int cur;
    int n;
    s16 val;
    u32 objIdU;
    u32 mapFlags;
    u32 trackId;
    f32 x;
    f32 y;
    f32 z;

    base = lbl_80396918;
    srcSeq = *(u8 **)(obj + 0x4c);
    camArg = 0;
    doCam = 0;
    player = Obj_GetPlayerObject();

    if (seqIdx == -1) {
        return -1;
    }
    if (seqIdx < 0 || seqIdx >= *(u8 *)(*(u8 **)(obj + 0x50) + 0x5e)) {
        return -1;
    }

    for (i = 0x19; i < 0x55; i++) {
        if (*(s16 *)((base + i * 2) + 0x3a98) == 0) {
            slot = i;
            *(s16 *)((base + i * 2) + 0x3a98) = 1;
            blk = base + i * 0x80;
            for (j = 0; j < 16; j++) {
                *(u8 **)blk = NULL;
                blk += 8;
            }
            i = 0x56;
        }
    }
    if (i == 0x55) {
        return -1;
    }

    mapTbl = *(s16 **)(*(u8 **)(obj + 0x50) + 0x1c);
    if (mapTbl != NULL) {
        seqIdx = mapTbl[seqIdx];
    }

    cur = *(s16 *)(obj + 0xb4);
    if (cur != -1 && lbl_803DD07C == NULL) {
        endObjSequence(cur);
    }

    val = seqIdx + 1;
    slotPtr = base + slot * 2;
    slotPtr += 0x3a98;
    *(s16 *)slotPtr = val;
    lbl_803DB714 = -1;
    lbl_803DB718 = -1;

    mon = base + 0x3d4c;
    walk = mon;
    n = (s8)lbl_803DD124;
    for (i = 0; i < n; i++) {
        if (*(u8 **)walk == obj) {
            found = 1;
            goto checked;
        }
        walk += 8;
    }
    found = 0;
checked:
    if (found == 0) {
        lbl_803DB714 = seqIdx;
    }

    hdr = mmAlloc(0x20, 0x11, 0);
    getTabEntry(hdr, 0x3c, seqIdx * 2, 8);
    first = *(s16 *)hdr;
    count = *(s16 *)(hdr + 2) - first;
    size = count << 3;
    buf = mmAlloc(size, 0x11, 0);
    getTabEntry(buf, 0x3b, first * 8, size);
    mm_free(hdr);

    if (lbl_803DD07C != NULL) {
        obj = lbl_803DD07C;
    }
    *(s16 *)(obj + 0xb4) = slot;
    parent = *(u8 **)(obj + 0x30);
    x = *(f32 *)(obj + 0xc);
    y = *(f32 *)(obj + 0x10);
    z = *(f32 *)(obj + 0x14);
    if (lbl_803DD0B4.active) {
        parent = NULL;
        x = *(f32 *)(obj + 0x18);
        y = *(f32 *)(obj + 0x1c);
        z = *(f32 *)(obj + 0x20);
    }
    heading = *(s16 *)obj;
    if (lbl_803DD078 != 0) {
        x -= *(f32 *)(obj + 8) *
             (*(f32 *)(obj + 0xa8) * fn_80293E80((lbl_803DEFE8 * (f32)*(s16 *)obj) / lbl_803DEFEC));
        z -= *(f32 *)(obj + 8) *
             (*(f32 *)(obj + 0xa8) * sin((lbl_803DEFE8 * (f32)*(s16 *)obj) / lbl_803DEFEC));
    }

    i = 0;
    base[*(s16 *)(obj + 0xb4) + 0x3538] = 0;
    base[*(s16 *)(obj + 0xb4) + 0x3334] = 0;
    lbl_8030ECF8[*(s16 *)(obj + 0xb4)] = 0;
    ((SeqRunTables *)base)->handles[*(s16 *)(obj + 0xb4)] = *(s16 *)(obj + 0x46);

    walk = buf;
    bit = 1;
    for (; i < count; i++) {
        if ((flags & (bit << i)) && (*(u16 *)(walk + 4) & 0x4000)) {
            objIdU = *(u16 *)(walk + 6);
            if (objIdU == 0x1f || objIdU == 0) {
                if (fn_80296C2C(Obj_GetPlayerObject()) == 0) {
                    return -1;
                }
            }
        }
        walk += 8;
    }

    idx = 0;
    walk2 = buf;
    packed = ((seqIdx & 0x7ff) << 4) | 0x8000;
    for (; idx < count; idx++) {
        if (flags & (1 << idx)) {
            setup = Obj_AllocObjectSetup(0x28, 6);
            objId = *(u16 *)(walk2 + 6);
            if (objId == 0x1f || objId == 0) {
                u8 *pp = Obj_GetPlayerObject();
                *(u16 *)(pp + 0xb0) |= 0x1000;
            }
            if (objId == 0xffff) {
                *(s16 *)setup = 6;
                *(s16 *)(setup + 0x1c) = *(s16 *)(obj + 0x46) + 4;
                if (*(s16 *)(obj + 0x46) == 0x443 && lbl_803DB72C != -1) {
                    *(s16 *)(setup + 0x1c) = lbl_803DB72C + 4;
                }
                *(u16 *)(walk2 + 4) |= 0x8000;
            } else if (objId == 0xfffe) {
                *(s16 *)setup = 0x1e;
                *(s16 *)(setup + 0x1c) = 3;
                curSeqNo = slot;
            } else {
                if (*(u16 *)(walk2 + 4) & 0x4000) {
                    *(s16 *)setup = 6;
                    if (objId == 0x443) {
                        if (lbl_803DB72C != -1) {
                            *(s16 *)(setup + 0x1c) = lbl_803DB72C + 4;
                        } else {
                            *(s16 *)(setup + 0x1c) = objId + 4;
                        }
                    } else {
                        *(s16 *)(setup + 0x1c) = objId + 4;
                    }
                } else {
                    *(s16 *)setup = objId;
                    *(s16 *)(setup + 0x1c) = 0;
                }
            }
            if (*(u16 *)(walk2 + 4) & 0x8000) {
                setup[0x20] = 0;
                setup[0x21] = 0;
            } else {
                setup[0x20] = 1;
                setup[0x21] = 1;
            }
            if (idx == 0 && (*(u16 *)(walk2 + 4) & 0x1000) && player != NULL) {
                fn_80297284(player);
            }
            *(s16 *)(setup + 0x18) = packed | (idx & 0xf);
            *(s16 *)(setup + 0x1a) = -1;
            if (idx != 0) {
                if (lbl_803DD0D9 != 0 && *(s16 *)setup == 0x1e) {
                    *(f32 *)(setup + 8) = x + *(f32 *)(base + 0x2bd4);
                    *(f32 *)(setup + 0xc) = y + *(f32 *)(base + 0x2bd8);
                    *(f32 *)(setup + 0x10) = z + *(f32 *)(base + 0x2bdc);
                    lbl_803DD0D9 = 0;
                } else {
                    *(f32 *)(setup + 8) = x;
                    *(f32 *)(setup + 0xc) = y;
                    *(f32 *)(setup + 0x10) = z;
                }
            } else {
                *(f32 *)(setup + 8) = *(f32 *)(obj + 0xc);
                *(f32 *)(setup + 0xc) = *(f32 *)(obj + 0x10);
                *(f32 *)(setup + 0x10) = *(f32 *)(obj + 0x14);
            }
            *(s8 *)(setup + 0x1f) = (s8)slot;
            setup[0x22] = 1;
            setup[0x24] = (*(u16 *)(walk2 + 4) & 0xf00) >> 8;
            setup[4] = 2;
            setup[5] = 1;
            if (srcSeq != NULL) {
                setup[5] = setup[5] | (srcSeq[5] & 0x18);
            }
            if (*(s16 *)setup == 0x1e) {
                setup[4] = 1;
            }
            if (*(s16 *)setup == 0x443 && lbl_803DB72C != -1) {
                *(s16 *)setup = lbl_803DB72C;
            }
            newObj = Obj_SetupObject(setup, 5, -1, -1, parent);
            *(s16 *)(newObj + 0xb4) = -2;
            seq = *(u8 **)(newObj + 0xb8);
            *(s16 *)(seq + 0x1a) = heading;
            *(s16 *)(seq + 0x6e) = -1;
            *(s16 *)(seq + 0x6e) = *(s16 *)(seq + 0x6e) & ~0x400;
            seq[0x12c] = 0;
            seq[0x12d] = 0;
            seq[0x12e] = 0;
            seq[0x12f] = 0;
            if (*(u16 *)(walk2 + 4) & 1) {
                *(s16 *)(seq + 0x6e) = *(s16 *)(seq + 0x6e) & ~1;
            }
            if (*(u16 *)(walk2 + 4) & 2) {
                *(s16 *)(seq + 0x6e) = *(s16 *)(seq + 0x6e) & ~2;
            }
            if (*(u16 *)(walk2 + 4) & 4) {
                *(s16 *)(seq + 0x1a) = 0;
            }
            if (*(u16 *)(walk2 + 4) & 8) {
                *(s16 *)(seq + 0x6e) = *(s16 *)(seq + 0x6e) & ~0x100;
            }
            if (*(u16 *)(walk2 + 4) & 0x80) {
                seq[0x7f] = seq[0x7f] | 4;
            }
            if (*(u16 *)(walk2 + 4) & 0x40) {
                seq[0x7f] = seq[0x7f] | 2;
            }
            if (*(u16 *)(walk2 + 4) & 0x2000) {
                if (idx == 0 && player != NULL) {
                    fn_8029726C(player);
                }
                if (lbl_803DD064 == 0 || lbl_803DD064 == *(s16 *)(obj + 0xb4)) {
                    lbl_803DD064 = *(s16 *)(obj + 0xb4);
                    curSeqNo = slot;
                }
                seq[0x56] = 4;
                if (camArg == 0) {
                    camArg = (*(u16 *)(walk2 + 4) & 0xf00) >> 8;
                }
                doCam = 1;
            } else {
                *(s8 *)(seq + 0x56) = -1;
            }
            if ((objId == 0x1f || objId == 0) && (*(s16 *)(seq + 0x6e) & 1)) {
                fn_80297254(player);
            }
            *(int *)(seq + 0x10c) = *(int *)walk2;
            *(s16 *)(seq + 0x70) = *(s16 *)(seq + 0x6e);
            if (idx == 0) {
                ((SeqRunTables *)base)->cmdFlags[*(s16 *)(obj + 0xb4)] = *(u16 *)(walk2 + 4);
                ((SeqRunTables *)base)->handles[*(s16 *)(obj + 0xb4)] =
                    *(int *)(*(u8 **)(newObj + 0x4c) + 0x14);
                mapFlags = *(u32 *)(*(u8 **)(obj + 0x50) + 0x44);
                if ((mapFlags & 0x40) && !(mapFlags & 0x8000)) {
                    parent = obj;
                    z = y = x = lbl_803DEFB0;
                    heading = 0;
                }
            }
        }
        walk2 += 8;
    }

    ((SeqRunTables *)base)->headings[*(s16 *)(obj + 0xb4)] = heading;
    j = 0;
    base[*(s16 *)(obj + 0xb4) + 0x3590] = 0;
    base[*(s16 *)(obj + 0xb4) + 0x338c] = 0;
    n = (s8)lbl_803DD124;
    for (; j < n; j++) {
        if (*(u8 **)mon == obj) {
            seqFlags = *(int *)(base + j * 8 + 0x3d50);
            lbl_803DD124 -= 1;
            p = base + j * 8 + 0x3d4c;
            for (k = 0; k < (s8)lbl_803DD124 - j; k++) {
                v = *(int *)(p + 8);
                *(int *)p = v;
                *(int *)(p + 4) = v;
                p += 8;
            }
            goto gotFlags;
        }
        mon += 8;
    }
    seqFlags = 0;
gotFlags:
    if (seqFlags != 0) {
        base[*(s16 *)(obj + 0xb4) + 0x3538] |= 0x10;
    } else {
        lbl_803DD070 = 0;
        trackId = (u32)(*(s16 *)slotPtr - 1) & 0x3fff;
        lbl_803DD068 = trackId;
        if (AudioStream_Play(trackId, streamCb_80080384) == 0) {
            if (lbl_803DB714 != -1) {
                gameTextLoadTaskText(lbl_803DB714);
                lbl_803DB714 = -1;
            }
        } else {
            lbl_803DB720 = slot;
            lbl_803DB71C = lbl_803DB714;
            lbl_803DB724 = -1;
            lbl_803DD074 = lbl_803DEFB0;
            lbl_803DB728 = -1;
        }
    }

    ((SeqRunTables *)base)->dists[*(s16 *)(obj + 0xb4)] = (f32)seqFlags;
    ((SeqRunTables *)base)->frames[*(s16 *)(obj + 0xb4)] = (f32)seqFlags;

    if (slot >= 0 && slot < 0x55) {
        if (lbl_803DD0BC < 0x1e) {
            ((SeqRunTables *)base)->recs[lbl_803DD0BC].slot = slot;
            ((SeqRunTables *)base)->recs[lbl_803DD0BC].count = count;
            ((SeqRunTables *)base)->recs[lbl_803DD0BC++].flags = seqFlags;
        }
    }

    if (doCam != 0) {
        cameraFocusNpc(camArg, obj);
    }
    mm_free(buf);
    lbl_803DD078 = 0;
    lbl_803DD0B4.active = 0;
    return slot;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int fn_8008196C(u8 *obj)
{
    int objectCount;
    void *unused;
    void **objects;
    u8 *seqObj;
    u8 *model;
    u8 *found;
    int j;
    u8 *entry;
    u8 *slotBase;
    u8 *candidate;
    int objType;
    int i;
    u8 *linked;
    f32 bestDist;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distSq;

    objects = ObjList_GetObjects(&unused, &objectCount);
    seqObj = *(u8 **)(obj + 0xb8);
    model = *(u8 **)(obj + 0x4c);
    if (*(s16 *)(obj + 0x44) == 0x11) {
        *(void **)seqObj = NULL;
        return -1;
    }

    switch (*(s16 *)(model + 0x1c)) {
    case 0:
        *(void **)seqObj = NULL;
        break;
    case 1:
        *(void **)seqObj = Obj_GetPlayerObject();
        break;
    case 2:
        *(void **)seqObj = getTrickyObject();
        break;
    case 3:
        *(void **)seqObj = NULL;
        *(s8 *)(seqObj + 0x7b) = (s8)(*(s16 *)(model + 0x1c) - 2);
        if (lbl_803DD064 != 0) {
            lbl_803DD064 = 0;
        }
        if ((lbl_80399E50[(s8)seqObj[0x57]] & 0x10) == 0) {
            (*(void (*)(int, int))(*(int *)(*gCameraInterface + 0x5c)))(0x41, 1);
        }
        break;
    default:
        *(void **)seqObj = NULL;
        objType = *(s16 *)(model + 0x1c) - 4;
        if (objType == 0x1f || objType == 0) {
            *(void **)seqObj = Obj_GetPlayerObject();
        } else if (*(int *)(seqObj + 0x10c) != 0) {
            *(void **)seqObj = ObjList_FindObjectById(*(int *)(seqObj + 0x10c));
        } else {
            bestDist = lbl_803DEFF0;
            for (i = 0; i < objectCount; i++) {
                candidate = objects[i];
                slotBase = lbl_80396918 + (s8)seqObj[0x57] * 0x80;
                entry = slotBase;
                for (j = 0; j < 16; j++) {
                    if (*(u8 **)entry == candidate) {
                        linked = *(u8 **)(slotBase + j * 8 + 4);
                        goto check;
                    }
                    entry += 8;
                }
                linked = NULL;
            check:
                if (linked == obj) {
                    *(void **)seqObj = candidate;
                    break;
                }
                if (linked == NULL) {
                    if (*(s16 *)(candidate + 0x46) == objType) {
                        dx = *(f32 *)(obj + 0xc) - *(f32 *)(candidate + 0xc);
                        dy = *(f32 *)(obj + 0x10) - *(f32 *)(candidate + 0x10);
                        dz = *(f32 *)(obj + 0x14) - *(f32 *)(candidate + 0x14);
                        distSq = dx * dx + dy * dy + dz * dz;
                        if (bestDist < lbl_803DEFB0 || distSq < bestDist) {
                            bestDist = distSq;
                            *(void **)seqObj = candidate;
                        }
                    }
                }
            }
        }
        break;
    }

    found = *(u8 **)seqObj;
    if (found != NULL) {
        if ((s8)seqObj[0x57] < 0x19) {
            if (*(s16 *)(found + 0xb4) != -1) {
                endObjSequence(*(s16 *)(found + 0xb4));
            }
        }
        return *(s16 *)(*(u8 **)seqObj + 0x48);
    }
    return -1;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void *objFindForSeqFn_80081bf0(u8 *obj)
{
    void *unused;
    int objectCount;
    void **objects;
    int targetId;
    int objectType;
    f32 bestDistSq;
    void *bestObj;
    int i;
    u8 *candidate;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distSq;

    targetId = *(int *)(*(u8 **)(obj + 0xb8) + 0x10c);
    if (targetId != 0) {
        return ObjList_FindObjectById(targetId);
    }

    objects = ObjList_GetObjects(&unused, &objectCount);
    objectType = *(s16 *)(*(u8 **)(obj + 0x4c) + 0x1c) - 4;
    if (objectType == 0x1f || objectType == 0) {
        return Obj_GetPlayerObject();
    }
    if (objectType == 0x24 || objectType == 0x25) {
        return getTrickyObject();
    }

    bestDistSq = lbl_803DEFF0;
    bestObj = NULL;
    for (i = 0; i < objectCount; i++) {
        candidate = objects[i];
        if (*(s16 *)(candidate + 0x46) == objectType) {
            dx = *(f32 *)(obj + 0xc) - *(f32 *)(candidate + 0xc);
            dy = *(f32 *)(obj + 0x10) - *(f32 *)(candidate + 0x10);
            dz = *(f32 *)(obj + 0x14) - *(f32 *)(candidate + 0x14);
            distSq = dx * dx + dy * dy + dz * dz;
            if (bestDistSq < lbl_803DEFB0 || distSq < bestDistSq) {
                bestDistSq = distSq;
                bestObj = candidate;
            }
        }
    }
    return bestObj;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void ObjSeq_RefreshActionCursor(void *obj, void *seqFile, u8 *seq)
{
    int stop;
    int actionIndex;
    u8 *command;
    s8 opcode;
    s16 repeatCount;

    if (*(void **)(seq + 0x94) == NULL) {
        return;
    }

    *(s16 *)(seq + 0x68) = -1;
    *(s16 *)(seq + 0x66) = 0;
    *(f32 *)(seq + 0x20) = lbl_803DEFB0;
    stop = 0;
    while (stop == 0 && *(s16 *)(seq + 0x66) < *(s16 *)(seq + 0x62)) {
        actionIndex = *(s16 *)(seq + 0x66);
        command = *(u8 **)(seq + 0x94) + actionIndex * 4;
        opcode = command[0];
        if (opcode == 0) {
            if (*(s16 *)(seq + 0x58) >= *(s16 *)(command + 2)) {
                *(s16 *)(seq + 0x68) = *(s16 *)(command + 2);
                *(s16 *)(seq + 0x66) = *(s16 *)(seq + 0x66) + 1;
            } else {
                stop = 1;
            }
        } else if (opcode == 0xb && (repeatCount = *(s16 *)(command + 2)) > 0) {
            if (*(s16 *)(seq + 0x58) >= *(s16 *)(seq + 0x68)) {
                *(s16 *)(seq + 0x68) = *(s16 *)(seq + 0x68) + command[1];
                *(s16 *)(seq + 0x66) = (s16)(*(s16 *)(seq + 0x66) + repeatCount + 1);
            } else {
                stop = 1;
            }
        } else if (*(s16 *)(seq + 0x58) >= *(s16 *)(seq + 0x68)) {
            if (opcode != 0xf) {
                *(s16 *)(seq + 0x68) = *(s16 *)(seq + 0x68) + command[1];
            }
            *(s16 *)(seq + 0x66) = *(s16 *)(seq + 0x66) + 1;
        } else {
            stop = 1;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void objSeq_onMapSetup(void)
{
    u8 *base = lbl_80396918;
    u8 *flagsB = base + 0x3b9c;
    u8 *flagsA = base + 0x3b44;
    s16 *modes = (s16 *)(base + 0x3a98);
    u8 *actions = base + 0x3c4c;
    u8 *results = base + 0x3bf4;
    u8 *states = base + 0x3a40;
    u8 *pending = base + 0x39e8;
    f32 *frames = (f32 *)(base + 0x3894);
    f32 *dists = (f32 *)(base + 0x3740);
    u8 *counts = base + 0x3590;
    int *handles = (int *)(base + 0x33e4);
    u8 *marks = base + 0x338c;
    int i = 0;

    {
        for (; i < 0x50; i += 8) {
            flagsB[0] = 0;
            flagsA[0] = 0;
            modes[0] = 0;
            actions[0] = 0;
            results[0] = 0;
            states[0] = 0;
            pending[0] = 0;
            frames[0] = lbl_803DEFB0;
            dists[0] = lbl_803DEFF0;
            counts[0] = 0;
            handles[0] = 0;
            marks[0] = 0;
            flagsB[1] = 0;
            flagsA[1] = 0;
            modes[1] = 0;
            actions[1] = 0;
            results[1] = 0;
            states[1] = 0;
            pending[1] = 0;
            frames[1] = lbl_803DEFB0;
            dists[1] = lbl_803DEFF0;
            counts[1] = 0;
            handles[1] = 0;
            marks[1] = 0;
            flagsB[2] = 0;
            flagsA[2] = 0;
            modes[2] = 0;
            actions[2] = 0;
            results[2] = 0;
            states[2] = 0;
            pending[2] = 0;
            frames[2] = lbl_803DEFB0;
            dists[2] = lbl_803DEFF0;
            counts[2] = 0;
            handles[2] = 0;
            marks[2] = 0;
            flagsB[3] = 0;
            flagsA[3] = 0;
            modes[3] = 0;
            actions[3] = 0;
            results[3] = 0;
            states[3] = 0;
            pending[3] = 0;
            frames[3] = lbl_803DEFB0;
            dists[3] = lbl_803DEFF0;
            counts[3] = 0;
            handles[3] = 0;
            marks[3] = 0;
            flagsB[4] = 0;
            flagsA[4] = 0;
            modes[4] = 0;
            actions[4] = 0;
            results[4] = 0;
            states[4] = 0;
            pending[4] = 0;
            frames[4] = lbl_803DEFB0;
            dists[4] = lbl_803DEFF0;
            counts[4] = 0;
            handles[4] = 0;
            marks[4] = 0;
            flagsB[5] = 0;
            flagsA[5] = 0;
            modes[5] = 0;
            actions[5] = 0;
            results[5] = 0;
            states[5] = 0;
            pending[5] = 0;
            frames[5] = lbl_803DEFB0;
            dists[5] = lbl_803DEFF0;
            counts[5] = 0;
            handles[5] = 0;
            marks[5] = 0;
            flagsB[6] = 0;
            flagsA[6] = 0;
            modes[6] = 0;
            actions[6] = 0;
            results[6] = 0;
            states[6] = 0;
            pending[6] = 0;
            frames[6] = lbl_803DEFB0;
            dists[6] = lbl_803DEFF0;
            counts[6] = 0;
            handles[6] = 0;
            marks[6] = 0;
            flagsB[7] = 0;
            flagsA[7] = 0;
            modes[7] = 0;
            actions[7] = 0;
            results[7] = 0;
            states[7] = 0;
            pending[7] = 0;
            frames[7] = lbl_803DEFB0;
            dists[7] = lbl_803DEFF0;
            counts[7] = 0;
            handles[7] = 0;
            marks[7] = 0;
            flagsB += 8;
            flagsA += 8;
            modes += 8;
            actions += 8;
            results += 8;
            states += 8;
            pending += 8;
            frames += 8;
            dists += 8;
            counts += 8;
            handles += 8;
            marks += 8;
        }
    }

    for (; i < 0x55; i++) {
        base[i + 0x3b9c] = 0;
        base[i + 0x3b44] = 0;
        *(s16 *)(base + i * 2 + 0x3a98) = 0;
        base[i + 0x3c4c] = 0;
        base[i + 0x3bf4] = 0;
        base[i + 0x3a40] = 0;
        base[i + 0x39e8] = 0;
        *(f32 *)(base + i * 4 + 0x3894) = lbl_803DEFB0;
        *(f32 *)(base + i * 4 + 0x3740) = lbl_803DEFF0;
        base[i + 0x3590] = 0;
        *(int *)(base + i * 4 + 0x33e4) = 0;
        base[i + 0x338c] = 0;
    }

    lbl_803DD124 = 0;
    lbl_803DD10C = 0;
    lbl_803DD110 = 0;
    lbl_803DD0DC = lbl_803DEFB0;
    lbl_803DD0B8 = NULL;
    lbl_803DD0F8 = 0;
    lbl_803DD0BC = 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void ObjSeq_release(void)
{
    mm_free(lbl_803DD0D4);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void ObjSeq_initialise(void)
{
    lbl_803DD0D4 = mmAlloc(0x10, 0x11, 0);
    objSeq_onMapSetup();
    lbl_803DD108 = 1;
    lbl_803DD100 = 0x5a;
    lbl_803DD10C = 0x42;
    objSeqInitFn_80080078(lbl_8030ECA8, 5);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int fn_800882C8(int index)
{
    int changed;

    changed = lbl_80399EA8[index];
    lbl_80399EA8[index] = 0;
    return changed;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_80088730(u8 *out)
{
    u8 *src;

    out[0] = lbl_803DB748;
    src = &lbl_803DB748;
    out[1] = src[1];
    out[2] = src[2];
    out[3] = src[3];
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void RomCurveInterp_BuildSegmentTimeTable(RomCurveInterpState *out, RomCurveNode *curve, RomCurveNode *next, f32 t,
                                          int flag) {
    f32 curveScale;
    f32 nextScale;
    f32 xPoints[4];
    f32 yPoints[4];
    f32 zPoints[4];
    f32 xSamples[9];
    f32 ySamples[9];
    f32 zSamples[9];
    f32 *times;
    f32 dx;
    f32 dy;
    f32 dz;
    int i;

    curveScale = ROM_CURVE_NODE_SCALE(curve);
    nextScale = ROM_CURVE_NODE_SCALE(next);

    xPoints[0] = curve->x;
    xPoints[1] = next->x;
    xPoints[2] = curveScale * fn_80293E80(ROM_CURVE_NODE_ANGLE(curve->yaw));
    xPoints[3] = nextScale * fn_80293E80(ROM_CURVE_NODE_ANGLE(next->yaw));

    yPoints[0] = curve->y;
    yPoints[1] = next->y;
    yPoints[2] = curveScale * fn_80293E80(ROM_CURVE_NODE_ANGLE(curve->pitch));
    yPoints[3] = nextScale * fn_80293E80(ROM_CURVE_NODE_ANGLE(next->pitch));

    zPoints[0] = curve->z;
    zPoints[1] = next->z;
    zPoints[2] = curveScale * sin(ROM_CURVE_NODE_ANGLE(curve->yaw));
    zPoints[3] = nextScale * sin(ROM_CURVE_NODE_ANGLE(next->yaw));

    Curve_SampleSegmentPoints(xPoints, yPoints, zPoints, xSamples, ySamples, zSamples, 8,
                     Curve_BuildHermiteCoeffs);

    times = &out->fromTime;
    times[0] = lbl_803DEFB0;
    for (i = 0; i < 8; i++) {
        dx = xSamples[i + 1] - xSamples[i];
        dy = ySamples[i + 1] - ySamples[i];
        dz = zSamples[i + 1] - zSamples[i];
        times[i + 1] = times[i] + sqrtf(dx * dx + dy * dy + dz * dz);
    }
    if ((s8)flag == 1) {
        t -= out->toTime;
    }
    for (i = 0; i <= 8; i++) {
        times[i] += t;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void RomCurveInterp_UpdateSegmentWindow(RomCurveInterpState *state, f32 t) {
    RomCurveNode *node;
    RomCurveNode *prev;
    int found;
    int i;
    int mask;
    int val;
    f32 thr;

    node = NULL;
    if (t < state->fromTime) {
        node = (RomCurveNode *)(*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(state->fromNodeId);
    }
    if (node != NULL) {
        while (t < (thr = state->fromTime)) {
            mask = 1;
            for (i = 0; i < 4; i++) {
                val = node->links[i];
                if (val > -1 && (node->directionMask & mask) != 0) {
                    found = val;
                    i = 5;
                }
                mask <<= 1;
            }
            if (i != 6) {
                state->toTime = thr;
                state->toNodeId = state->fromNodeId;
                state->fromNodeId = -1;
                return;
            }
            state->toNodeId = state->fromNodeId;
            state->fromNodeId = found;
            prev = node;
            node = (RomCurveNode *)(*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(state->fromNodeId);
            RomCurveInterp_BuildSegmentTimeTable(state, node, prev, state->fromTime, 1);
        }
    }
    node = (RomCurveNode *)(*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(state->toNodeId);
    if (node == NULL) {
        return;
    }
    while (t >= (thr = state->toTime)) {
        mask = 1;
        for (i = 0; i < 4; i++) {
            val = node->links[i];
            if (val > -1 && (node->directionMask & mask) == 0) {
                found = val;
                i = 5;
            }
            mask <<= 1;
        }
        if (i != 6) {
            state->fromTime = thr;
            state->fromNodeId = state->toNodeId;
            state->toNodeId = -1;
            return;
        }
        state->fromNodeId = state->toNodeId;
        state->toNodeId = found;
        prev = node;
        node = (RomCurveNode *)(*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(state->toNodeId);
        RomCurveInterp_BuildSegmentTimeTable(state, prev, node, state->toTime, 0);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void RomCurveInterp_InitFromNode(RomCurveInterpState *out, int id) {
    RomCurveNode *curve;
    int i;
    int mask;
    int found;
    int val;

    out->fromNodeId = id;
    out->toNodeId = -1;
    curve = (RomCurveNode *)(*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(out->fromNodeId);
    mask = 1;
    for (i = 0; i < 4; i++) {
        val = curve->links[i];
        if (val > -1 && (curve->directionMask & mask) == 0) {
            found = val;
            i = 5;
        }
        mask <<= 1;
    }
    if (i != 6) {
        out->fromNodeId = -1;
    } else {
        out->toNodeId = found;
        RomCurveInterp_BuildSegmentTimeTable(out, curve,
                                             (RomCurveNode *)(*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(out->toNodeId),
                                             lbl_803DEFB0, 0);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int RomCurveInterp_EvaluateOffsetPosition(RomCurveInterpState *state, f32 *offset, f32 *outPos, s16 *outAngle,
                                          int ignoreY) {
    RomCurveNode *from;
    RomCurveNode *to;
    f32 t;
    f32 fromScale;
    f32 toScale;
    f32 xPoints[4];
    f32 yPoints[4];
    f32 zPoints[4];
    f32 xTangent;
    f32 yTangent;
    f32 zTangent;
    f32 segmentT;
    f32 length;
    f32 scale;
    f32 angle;
    f32 *times;
    int segment;
    int i;

    t = offset[2];
    RomCurveInterp_UpdateSegmentWindow(state, t);
    from = (RomCurveNode *)(*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(state->fromNodeId);
    if (from != NULL && state->toNodeId > -1) {
        to = (RomCurveNode *)(*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(state->toNodeId);
        times = &state->fromTime;
        i = 0;
        while (i < 9 && t >= times[i]) {
            i++;
        }
        segment = i - 1;
        segmentT = ((f32)segment +
                    (t - times[segment]) / (times[segment + 1] - times[segment])) *
                   lbl_803DF01C;

        fromScale = ROM_CURVE_NODE_SCALE(from);
        toScale = ROM_CURVE_NODE_SCALE(to);

        xPoints[0] = from->x;
        xPoints[1] = to->x;
        xPoints[2] = fromScale * fn_80293E80(ROM_CURVE_NODE_ANGLE(from->yaw));
        xPoints[3] = toScale * fn_80293E80(ROM_CURVE_NODE_ANGLE(to->yaw));

        yPoints[0] = from->y;
        yPoints[1] = to->y;
        yPoints[2] = fromScale * fn_80293E80(ROM_CURVE_NODE_ANGLE(from->pitch));
        yPoints[3] = toScale * fn_80293E80(ROM_CURVE_NODE_ANGLE(to->pitch));

        zPoints[0] = from->z;
        zPoints[1] = to->z;
        zPoints[2] = fromScale * sin(ROM_CURVE_NODE_ANGLE(from->yaw));
        zPoints[3] = toScale * sin(ROM_CURVE_NODE_ANGLE(to->yaw));

        outPos[0] = Curve_EvalHermite(segmentT, xPoints, &xTangent);
        if ((s8)ignoreY == 0) {
            outPos[1] = Curve_EvalHermite(segmentT, yPoints, &yTangent);
        }
        outPos[2] = Curve_EvalHermite(segmentT, zPoints, &zTangent);

        length = sqrtf(xTangent * xTangent + zTangent * zTangent);
        if (length > lbl_803DF020) {
            scale = offset[0] / length;
            *outAngle = (s16)(getAngle(xTangent, zTangent) - 0x8000);
            xTangent *= scale;
            zTangent *= scale;
            outPos[0] += zTangent;
            outPos[2] -= xTangent;
            if ((s8)ignoreY == 0) {
                outPos[1] += offset[1];
            }
        }
        return 1;
    }

    if (from == NULL) {
        from = (RomCurveNode *)(*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(state->toNodeId);
    }
    if (from == NULL) {
        return 0;
    }
    outPos[0] = from->x;
    if ((s8)ignoreY == 0) {
        outPos[1] = from->y + offset[1];
    }
    outPos[2] = from->z;
    angle = ROM_CURVE_NODE_ANGLE(from->yaw);
    outPos[0] += offset[0] * sin(angle);
    outPos[2] += offset[0] * fn_80293E80(angle);
    *outAngle = (s16)(((s32)from->yaw << 8) - 0x8000);
    return 1;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void ObjSeq_UpdateCurvePosition(u8 *obj, u8 *seq) {
    u8 *base;
    RomCurveNode *node;
    f32 outPos[3];
    f32 offset[3];
    f32 dx;
    f32 dy;
    f32 dz;
    f32 angleSin;
    f32 angleCos;
    f32 x;
    f32 y;
    f32 z;

    base = *(u8 **)(obj + 0x4c);
    if (base == NULL) {
        return;
    }

    if (*(s32 *)(seq + 0x28) < 0) {
        dx = *(f32 *)(obj + 0x0c) - *(f32 *)(base + 0x08);
        dz = *(f32 *)(obj + 0x14) - *(f32 *)(base + 0x10);
        angleCos = fn_80293E80((lbl_803DEFE8 * (f32)*(s16 *)(seq + 0x1a)) / lbl_803DEFEC);
        angleSin = sin((lbl_803DEFE8 * (f32)*(s16 *)(seq + 0x1a)) / lbl_803DEFEC);
        *(f32 *)(obj + 0x0c) = angleCos * dz + (angleSin * dx + *(f32 *)(base + 0x08));
        *(f32 *)(obj + 0x14) = -(angleCos * dx - (angleSin * dz + *(f32 *)(base + 0x10)));
        return;
    }

    node = (RomCurveNode *)(*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(*(s32 *)(seq + 0x28));
    if (node == NULL) {
        return;
    }

    x = *(f32 *)(obj + 0x0c);
    dx = x - *(f32 *)(base + 0x08);
    y = *(f32 *)(obj + 0x10);
    dy = y - *(f32 *)(base + 0x0c);
    z = *(f32 *)(obj + 0x14);
    dz = z - *(f32 *)(base + 0x10);
    offset[0] = dx;
    offset[1] = dy;
    offset[2] = dz;
    outPos[0] = x;
    outPos[1] = y;
    outPos[2] = z;

    if (node->links[0] < 0) {
        *(f32 *)(obj + 0x0c) = outPos[0];
        *(f32 *)(obj + 0x10) = outPos[1];
        *(f32 *)(obj + 0x14) = outPos[2];
        return;
    }

    if (RomCurveInterp_EvaluateOffsetPosition(*(RomCurveInterpState **)(seq + 0x2c), offset, outPos,
                                              (s16 *)(seq + 0x1a), seq[0x7a]) != 0) {
        *(f32 *)(obj + 0x0c) = outPos[0];
        *(f32 *)(obj + 0x10) = outPos[1];
        *(f32 *)(obj + 0x14) = outPos[2];
        return;
    }

    angleCos = fn_80293E80((lbl_803DEFE8 * (f32)*(s16 *)(seq + 0x1a)) / lbl_803DEFEC);
    angleSin = sin((lbl_803DEFE8 * (f32)*(s16 *)(seq + 0x1a)) / lbl_803DEFEC);
    *(f32 *)(obj + 0x0c) = angleCos * offset[2] + (angleSin * offset[0] + *(f32 *)(base + 0x08));
    *(f32 *)(obj + 0x14) = -(angleCos * offset[0] - (angleSin * offset[2] + *(f32 *)(base + 0x10)));
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void animatedObjFreeAndSavePlayerPos(u8 *obj, u8 *seqObj, u8 *seq) {
    void (*callback)(void *ctx, u8 *obj);
    u8 *player;
    int clearBit;

    callback = *(void (**)(void *, u8 *))(seq + 0xe8);
    if (callback != NULL) {
        callback(*(void **)(seq + 0x110), obj);
        *(void **)(seq + 0xe8) = NULL;
    }

    if ((s8)seq[0x57] == lbl_803DB720) {
        AudioStream_CancelPrepared();
        lbl_803DB720 = -1;
    }

    if (seq[0x7e] != 0) {
        if ((s8)seq[0x7b] != 0) {
            seq[0x7b] = 0;
        }
        if (*(void **)seq != NULL) {
            *(void **)(seqObj + 0xc0) = NULL;
            *(u16 *)(seqObj + 0xb0) &= ~0x1000;
            *(void **)seq = NULL;
        }
    }

    if ((((u32)seq[0x136] >> 2) & 1U) != 0U) {
        player = Obj_GetPlayerObject();
        ((MapEventInterface *)*gMapEventInterface)->triggerEvent(
            (int)(player + 0xc), *(s16 *)player, 0, getCurMapLayer());
        clearBit = 0;
        seq[0x136] = (seq[0x136] & (u8)~4) | ((clearBit & 1) << 2);
    }

    seq[0x7e] = 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
f32 objCurveInterpolate(ObjCurveKey *keys, int count, int frame) {
    int index;
    int mode;
    int prevIndex;
    ObjCurveKey *key;
    ObjCurveKey *prev;
    f32 values[4];
    f32 span;
    f32 deltaPrev;
    f32 deltaNext;
    f32 t;

    if (count <= 0) {
        return lbl_803DEFB0;
    }

    index = 0;
    key = keys;
    while (index < count && key->frame < frame) {
        key++;
        index++;
    }

    if (index == count) {
        return keys[count - 1].value;
    }
    if (index == 0) {
        return keys[0].value;
    }
    key = &keys[index];
    if (frame == key->frame) {
        t = keys[index].value;
        mode = keys[index].tangentAndMode & 3;
        if (mode > 1 && index < count - 1) {
            t = key[1].value;
        }
        return t;
    }

    prevIndex = index - 1;
    prev = &keys[prevIndex];
    mode = prev->tangentAndMode & 3;
    values[0] = prev->value;
    if (mode == 0) {
        deltaNext = prev[1].value - values[0];
        if (prevIndex > 0) {
            deltaPrev = values[0] - prev[-1].value;
        } else {
            deltaPrev = deltaNext;
        }
        if (deltaNext < lbl_803DEFB0) {
            deltaNext = -deltaNext;
        }
        if (deltaPrev < lbl_803DEFB0) {
            deltaPrev = -deltaPrev;
        }
        values[2] = (deltaNext + deltaPrev) * lbl_803DF000 *
                    (f32)((s8)prev->tangentAndMode >> 2);
    }

    span = (f32)(keys[prevIndex + 1].frame - keys[prevIndex].frame);
    if (index < count) {
        key = &keys[index];
        values[1] = key->value;
        if (mode == 0) {
            index++;
            if (index < count) {
                deltaPrev = key[1].value - values[1];
            } else {
                deltaPrev = deltaNext;
            }
            if (deltaPrev < lbl_803DEFB0) {
                deltaPrev = -deltaPrev;
            }
            values[3] = (deltaNext + deltaPrev) * lbl_803DF000 *
                        (f32)((s8)key->tangentAndMode >> 2);
        }
    }

    if (span > lbl_803DEFB0) {
        t = (f32)(frame - keys[prevIndex].frame) / span;
        if (mode == 0) {
            return Curve_EvalHermite(t, values, NULL);
        }
        if (mode == 1) {
            return t * (values[1] - values[0]) + values[0];
        }
    }
    return values[1];
}
#pragma scheduling reset
#pragma peephole reset
