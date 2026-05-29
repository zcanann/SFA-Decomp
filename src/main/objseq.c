#include "main/sky_80080E58_shared.h"

void ObjSeq_setCamVars(int camA, int camB, int camC, int camD)
{
    lbl_803DD10C = camA;
    lbl_803DD108 = camB;
    lbl_803DD104 = camC;
    lbl_803DD100 = camD;
}

#pragma peephole off
#pragma scheduling off
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

    curveFn_80010018(xPoints, yPoints, zPoints, xSamples, ySamples, zSamples, 8,
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
    if (node != NULL) {
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
        ((void (*)(void *, s16, int, int))(*(int *)(*gMapEventInterface + 0x1c)))(
            player + 0xc, *(s16 *)player, 0, getCurMapLayer());
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
