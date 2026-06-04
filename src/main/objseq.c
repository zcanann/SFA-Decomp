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
void ObjSeq_update(u8 *obj, f32 t);

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
void *objSeqCmd3(u8 *obj, u8 *seq, u8 *src)
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
                objAnimCurvFn_800849e8(obj, seq);
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
void objSeqSetupFn_80085b34(u8 *obj, u8 **seqObj, u8 *seq, u8 *sourceObj, void **outAction)
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

    objAnimCurvFn_800849e8(obj, seq);
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
void seq_findAction(void *obj, void *seqFile, u8 *seq)
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
void curveFn_80083e00(RomCurveInterpState *out, RomCurveNode *curve, RomCurveNode *next, f32 t,
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
                     curveFn_80010d54);

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
void romCurveFn_80084190(RomCurveInterpState *state, f32 t) {
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
            curveFn_80083e00(state, node, prev, state->fromTime, 1);
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
        curveFn_80083e00(state, prev, node, state->toTime, 0);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void curveFindFn_800843c4(RomCurveInterpState *out, int id) {
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
        curveFn_80083e00(out, curve,
                         (RomCurveNode *)(*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(out->toNodeId),
                         lbl_803DEFB0, 0);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int romCurveFn_800844b8(RomCurveInterpState *state, f32 *offset, f32 *outPos, s16 *outAngle,
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
    romCurveFn_80084190(state, t);
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

        outPos[0] = curveFn_80010dc0(segmentT, xPoints, &xTangent);
        if ((s8)ignoreY == 0) {
            outPos[1] = curveFn_80010dc0(segmentT, yPoints, &yTangent);
        }
        outPos[2] = curveFn_80010dc0(segmentT, zPoints, &zTangent);

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
void objAnimCurvFn_800849e8(u8 *obj, u8 *seq) {
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

    if (romCurveFn_800844b8(*(RomCurveInterpState **)(seq + 0x2c), offset, outPos,
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
            return curveFn_80010dc0(t, values, NULL);
        }
        if (mode == 1) {
            return t * (values[1] - values[0]) + values[0];
        }
    }
    return values[1];
}
#pragma scheduling reset
#pragma peephole reset
