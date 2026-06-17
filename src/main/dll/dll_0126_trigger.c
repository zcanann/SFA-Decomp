#include "main/dll/DR/hightop.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"

typedef struct TriggerPlacement
{
    u8 pad0[0x38 - 0x0];
    s16 unk38;
    u8 pad3A[0x46 - 0x3A];
    u16 unk46;
} TriggerPlacement;

typedef struct ObjInterpretSeqPlacement
{
    u8 pad0[0x2 - 0x0];
    s8 unk2;
    u8 pad3[0x4 - 0x3];
    s16 unk4;
    u8 unk6;
    u8 pad7[0x8 - 0x7];
} ObjInterpretSeqPlacement;

typedef struct TriggerState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    u32 unk8;
    u8 padC[0x1C - 0xC];
    f32 unk1C;
    f32 unk20;
    f32 unk24;
    f32 unk28;
    f32 unk2C;
    f32 unk30;
    u8 pad34[0x80 - 0x34];
    s16 unk80;
    s16 unk82;
    s16 unk84;
    s16 unk86;
    s16 unk88;
    u8 pad8A[0xAC - 0x8A];
} TriggerState;

extern undefined4 getLActions();
extern undefined8 FUN_80006728();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80017648();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern int FUN_8001769c();
extern undefined4 FUN_800178bc();
extern undefined4 FUN_80017a78();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017af0();
extern int FUN_80017b00();
extern int ObjGroup_FindNearestObject();
extern undefined4 FUN_80040da0();
extern undefined4 FUN_80041c10();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80043030();
extern int FUN_8005337c();
extern undefined4 FUN_80053754();
extern undefined4 FUN_80053b3c();
extern undefined4 FUN_80053b70();
extern int FUN_80056600();
extern undefined4 FUN_800569f4();
extern undefined4 FUN_80056a20();
extern undefined4 FUN_8005cff0();
extern undefined4 FUN_8005d0ac();
extern undefined4 FUN_8005d114();
extern undefined4 FUN_8005d17c();
extern undefined4 FUN_8006f498();
extern undefined4 FUN_800723a0();
extern undefined4 FUN_80080f10();
extern undefined4 FUN_80080f28();
extern undefined4 FUN_80080f3c();
extern uint FUN_80080f40();
extern undefined4 FUN_80125b7c();
extern undefined4 FUN_80198e08();
extern int objFn_80198fa4();
extern undefined4 FUN_801991bc();
extern undefined4 FUN_8019959c();
extern undefined4 FUN_80199744();
extern int FUN_8020a6fc();
extern undefined4 FUN_8020a908();
extern undefined8 FUN_8028682c();
extern int FUN_8028683c();
extern undefined4 FUN_80286878();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80294bd4();
extern int FUN_80294dbc();
extern uint countLeadingZeros();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6e4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd704;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e4d68;
extern f64 DOUBLE_803e4d88;
extern f32 lbl_803E4D70;
extern f32 lbl_803E4D94;
extern f32 lbl_803E4D98;
extern f32 lbl_803E4D9C;

#pragma scheduling on
#pragma peephole on
extern void Sfx_StopFromObject(void* obj, int sfxId);
extern void objSetSlot(void* obj, int slot);
extern int GameBit_Get(int eventId);
extern f32 lbl_803E40F8;
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int* gPlayerShadowInterface;
extern void OSReport(const char* fmt, ...);
extern int Obj_GetPlayerObject(void);
extern void fn_80295918(int obj, int b, f32 a);
extern void setDrawCloudsAndLights(int v);
extern void gameFlagFn_8005ce6c(int v);
extern void setDrawLights(int v);
extern void fn_8006FC00(int v);
extern void skyFn_80088c94(int a, int b);
extern void gameFlagFn_8005cd24(int v);
extern void timeOfDayFn_80055000(void);
extern void timeOfDayFn_80055038(void);
extern int getSkyStructField24C(void);
extern void skyFn_80088e54(int b, f32 a);
extern void getEnvfxAct(int obj, int target, int effectId, int flags);
extern int ObjList_GetObjects(int* first, int* count);
extern int getTablesBinEntry(int idx);
extern int getLoadedTexture(int idx);
extern void crash(int a, int b, int c, int d, int e, int f, int g, int h);
extern void textureFree(int tex);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern void GameBit_Set(int bit, int val);
extern int getCurMapLayer(void);
extern int getTrickyObject(void);
extern void mapLoadDataFiles(int map);
extern void loadModelAndAnimTabs(void);
extern void mapUnload(int map, int flags);
extern void lockLevel(int a, int b);
extern void unlockLevel(int a, int b, int c);
extern void gameTextFn_80125ba4(int id);
extern int getArwing(void);
extern void defragMemory(int v);
extern void timer_addDuration(int timer, int dur);
extern void envFxFn_800887cc(void);
extern void goToNextMapLayer(void);
extern void goToPrevMapLayer(void);
extern f32 lbl_803E40D8;
extern f32 lbl_803E40FC;
extern f32 lbl_803E4100;
extern int fn_802972A8(void);
extern int return1_800202BC(void);
extern int fn_80198B68(int obj, int p2);
extern void objSeqFn_801992ec(int obj, int target);
extern void fn_80198DE8(int obj, int target);
extern void fn_80198A00(int obj, int target);
extern void objSeqMoveFn_80199188(int obj, int target);
extern f32 lbl_803E4104;
extern u8 framesThisStep;

undefined4 objInterpretSeq_v11_unused(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                                      undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                                      undefined4 param_9, undefined4 param_10, undefined4 param_11, int param_12,
                                      int param_13, undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    byte opFlags;
    undefined2 stateIdx;
    ushort scaleRaw;
    double prevResult;
    short delta;
    uint flagBits;
    short* objSeq;
    uint flagVal;
    uint flagReg;
    int iResult;
    byte subOp;
    int* idList;
    short* childSeq;
    int childObj;
    undefined4 srcA;
    undefined4 srcB;
    int objBase;
    byte opIndex;
    byte* seqFlags;
    char mode;
    byte* opPtr;
    double tmpF1a;
    double tmpF1b;
    double tmpF1c;
    double resultVal;
    double tmpF1d;
    double tmpF1e;
    undefined8 tmpResult;
    int local_38;
    int local_34[13];

    tmpResult = FUN_8028682c();
    objSeq = (short*)((ulonglong)tmpResult >> 0x20);
    objBase = (int)tmpResult;
    seqFlags = *(byte**)(objSeq + 0x5c);
    opPtr = (byte*)(*(int*)(objSeq + 0x26) + 0x18);
    opIndex = 0;
    resultVal = tmpF1a;
    do
    {
        prevResult = DOUBLE_803e4d68;
        mode = (char)param_11;
        if (7 < opIndex)
        {
            if (mode < '\x01')
            {
                if (mode < '\0')
                {
                    *seqFlags = *seqFlags | 2;
                }
            }
            else
            {
                *seqFlags = *seqFlags | 1;
                FUN_80017698((int)*(short*)(seqFlags + 0x80), 1);
            }
            FUN_80286878();
            return;
        }
        if ((opPtr[1] != 0) && ((subOp = *seqFlags, (subOp & 4) == 0 || ((*opPtr & 0x20) != 0))))
        {
            opFlags = *opPtr;
            if ((opFlags & 0x10) == 0)
            {
                if (mode == '\x01')
                {
                    if ((opFlags & 1) != 0)
                    {
                        if ((subOp & 1) != 0)
                        {
                            opFlags = opFlags & 4;
                        joined_r0x80199a04:
                            if (opFlags == 0) goto switchD_80199a5c_caseD_0;
                        }
                        goto code_r0x80199a48;
                    }
                }
                else if ((mode == -1) && ((opFlags & 2) != 0))
                {
                    if ((subOp & 2) != 0)
                    {
                        opFlags = opFlags & 8;
                        goto joined_r0x80199a04;
                    }
                    goto code_r0x80199a48;
                }
            }
            else if ((opFlags & 1) == 0)
            {
                if (((opFlags & 2) == 0) || (mode < '\x01')) goto code_r0x80199a48;
            }
            else if (-1 < mode)
            {
            code_r0x80199a48:
                switch (opPtr[1])
                {
                case 1:
                    subOp = opPtr[2];
                    if (subOp == 9)
                    {
                        iResult = FUN_80017a98();
                        if (iResult != 0)
                        {
                            resultVal = (double)FUN_80294bd4((double)lbl_803E4D70, iResult, 10);
                        }
                    }
                    else if (subOp < 9)
                    {
                        if ((7 < subOp) && (iResult = FUN_80017a98(), iResult != 0))
                        {
                            resultVal = (double)FUN_80294bd4((double)lbl_803E4D70, iResult, 1);
                        }
                    }
                    else if (subOp == 0xb)
                    {
                        iResult = FUN_80017a98();
                        if (iResult != 0)
                        {
                            resultVal = (double)FUN_80294bd4((double)lbl_803E4D94, iResult, 1);
                        }
                    }
                    else if ((subOp < 0xb) && (iResult = FUN_80017a98(), iResult != 0))
                    {
                        resultVal = (double)FUN_80294bd4((double)lbl_803E4D70, iResult, 0xb);
                    }
                    break;
                case 4:
                    if (mode < '\0')
                    {
                        resultVal = (double)FUN_80006810((int)objSeq, *(short*)(opPtr + 2));
                    }
                    else
                    {
                        resultVal = (double)FUN_80006824((uint)objSeq, *(ushort*)(opPtr + 2));
                    }
                    break;
                case 5:
                    resultVal = (double)*(float*)(seqFlags + 4);
                    break;
                case 6:
                    resultVal = (double)(**(code**)(*DAT_803dd6d0 + 0x24))(opPtr[2], opPtr[3], 0);
                    break;
                case 8:
                    switch (opPtr[2])
                    {
                    case 0:
                        if (1 < opPtr[3])
                        {
                            opPtr[3] = 1;
                        }
                        resultVal = (double)FUN_8005d17c((uint)opPtr[3]);
                        break;
                    case 1:
                        if (1 < opPtr[3])
                        {
                            opPtr[3] = 1;
                        }
                        resultVal = (double)FUN_8005d114((uint)opPtr[3]);
                        break;
                    case 2:
                        if (1 < opPtr[3])
                        {
                            opPtr[3] = 1;
                        }
                        resultVal = (double)FUN_8005d0ac((uint)opPtr[3]);
                        break;
                    case 3:
                        if (1 < opPtr[3])
                        {
                            opPtr[3] = 1;
                        }
                        resultVal = (double)(**(code**)(*DAT_803dd6e4 + 0x1c))(opPtr[3]);
                        break;
                    case 4:
                        resultVal = (double)(**(code**)(*DAT_803dd704 + 0xc))(opPtr[3]);
                        break;
                    case 5:
                        resultVal = (double)FUN_8006f498((uint)opPtr[3]);
                        break;
                    case 6:
                        if (opPtr[3] == 0)
                        {
                            resultVal = (double)FUN_80080f28(7, '\0');
                        }
                        else
                        {
                            resultVal = (double)FUN_80080f28(7, '\x01');
                        }
                        break;
                    case 7:
                        if (opPtr[3] == 0)
                        {
                            resultVal = (double)FUN_8005cff0(0);
                        }
                        else
                        {
                            resultVal = (double)FUN_8005cff0(1);
                        }
                        break;
                    case 8:
                        if (opPtr[3] == 0)
                        {
                            resultVal = (double)FUN_80053b3c();
                        }
                        else
                        {
                            resultVal = (double)FUN_80053b70();
                        }
                        break;
                    case 9:
                        flagBits = FUN_80080f40();
                        local_34[2] = (int)opPtr[3];
                        local_34[1] = 0x43300000;
                        resultVal = (double)FUN_80080f3c((double)(float)((double)CONCAT44(0x43300000, local_34[2]) -
                                                          DOUBLE_803e4d88), flagBits ^ 1);
                        break;
                    case 10:
                        local_34[2] = (int)opPtr[3];
                        local_34[1] = 0x43300000;
                        resultVal = (double)FUN_80080f3c((double)(float)((double)CONCAT44(0x43300000, local_34[2]) -
                                                          DOUBLE_803e4d88), 0);
                        break;
                    case 0xb:
                        local_34[2] = (int)opPtr[3];
                        local_34[1] = 0x43300000;
                        resultVal = (double)FUN_80080f3c((double)(float)((double)CONCAT44(0x43300000, local_34[2]) -
                                                          DOUBLE_803e4d88), 1);
                    }
                    break;
                case 10:
                    FUN_80006728(resultVal, param_2, param_3, param_4, param_5, param_6, param_7, param_8, objSeq, objBase,
                                 (uint) * (ushort*)(opPtr + 2), param_12, param_13, param_14, param_15, param_16);
                    resultVal = (double)FUN_800723a0();
                    break;
                case 0xb:
                    subOp = opPtr[2];
                    if (subOp == 2)
                    {
                        (*gObjectTriggerInterface)->setFlag(opPtr[3], 0);
                    }
                    else if (subOp < 2)
                    {
                        if (subOp == 0)
                        {
                        LAB_80199dec:
                            iResult = ObjGroup_FindNearestObject(0xf, objSeq, (float*)0x0);
                            resultVal = tmpF1b;
                            if (iResult != 0)
                            {
                                (*gObjectTriggerInterface)->runSequence(opPtr[3], (void*)iResult, -1);
                                resultVal = tmpF1b;
                            }
                        }
                        else
                        {
                            (*gObjectTriggerInterface)->setFlag(opPtr[3], 1);
                        }
                    }
                    else if (subOp < 4) goto LAB_80199dec;
                    break;
                case 0xc:
                    scaleRaw = *(ushort*)(opPtr + 2);
                    iResult = FUN_80017b00(&local_38, local_34);
                    for (; local_38 < local_34[0]; local_38 = local_38 + 1)
                    {
                        childObj = *(int*)(iResult + local_38 * 4);
                        childSeq = *(short**)(childObj + 0x4c);
                        if (childSeq == (short*)0x0) goto LAB_80199ef0;
                        delta = *childSeq;
                        if (delta == 0x54)
                        {
                        LAB_80199ed4:
                            if ((int)childSeq[0x1c] == (uint)scaleRaw)
                            {
                                resultVal = (double)objInterpretSeq_v11_unused(
                                    resultVal, param_2, param_3, param_4, param_5, param_6, param_7
                                    , param_8, childObj, objBase, param_11, param_12, param_13,
                                    param_14, param_15, param_16);
                            }
                        }
                        else if (delta < 0x54)
                        {
                            if ((delta < 0x51) && (0x4a < delta)) goto LAB_80199ed4;
                        }
                        else if (delta == 0x230) goto LAB_80199ed4;
                    LAB_80199ef0:
                        ;
                    }
                    break;
                case 0xd:
                    param_14 = 0;
                    param_13 = param_12;
                    getLActions(resultVal, param_2, param_3, param_4, param_5, param_6, param_7, param_8, objSeq, objBase,
                                (uint) * (ushort*)(opPtr + 2), param_11, param_12, 0, param_15, param_16);
                    break;
                case 0x10:
                    iResult = FUN_80017a98();
                    resultVal = (double)FUN_80017a78(iResult, (uint)opPtr[2]);
                    break;
                case 0x11:
                    resultVal = (double)FUN_80017698(0x4e3, (uint) * (ushort*)(opPtr + 2));
                    break;
                case 0x12:
                    subOp = opPtr[2];
                    flagReg = (uint)subOp << 8 & 0x3f00 | (uint)opPtr[3];
                    flagVal = FUN_80017690(flagReg);
                    flagBits = ((uint)subOp << 8) >> 0xe;
                    if (flagBits == 0)
                    {
                        flagVal = 0;
                    }
                    else if (flagBits == 1)
                    {
                        flagVal = 0xffffffff;
                    }
                    else if (flagBits == 2)
                    {
                        flagVal = ~flagVal;
                    }
                    resultVal = (double)FUN_80017698(flagReg, flagVal);
                    break;
                case 0x13:
                    resultVal = (double)(**(code**)(*DAT_803dd72c + 0x50))
                        ((int)*(char*)(objSeq + 0x56), *(undefined2*)(opPtr + 2), 1);
                    break;
                case 0x14:
                    resultVal = (double)(**(code**)(*DAT_803dd72c + 0x50))
                        ((int)*(char*)(objSeq + 0x56), *(undefined2*)(opPtr + 2), 0);
                    break;
                case 0x15:
                    idList = (int*)FUN_80017af0(*(ushort*)(opPtr + 2) + 2);
                    if (idList != (int*)0x0)
                    {
                        for (; *idList != -1; idList = idList + 1)
                        {
                            iResult = FUN_8005337c(*idList);
                            if (iResult == 0)
                            {
                                param_13 = 0;
                                param_14 = 0;
                                param_15 = 0;
                                param_16 = 0;
                                resultVal = (double)FUN_80017648();
                            }
                        }
                    }
                    break;
                case 0x16:
                    idList = (int*)FUN_80017af0(*(ushort*)(opPtr + 2) + 2);
                    if (idList != (int*)0x0)
                    {
                        for (; *idList != -1; idList = idList + 1)
                        {
                            iResult = FUN_8005337c(*idList);
                            if (iResult != 0)
                            {
                                resultVal = (double)FUN_80053754();
                            }
                        }
                    }
                    break;
                case 0x18:
                    resultVal = (double)(**(code**)(*DAT_803dd72c + 0x44))
                        ((int)*(char*)(objSeq + 0x56), *(undefined2*)(opPtr + 2));
                    break;
                case 0x1a:
                    resultVal = (double)(**(code**)(*DAT_803dd72c + 0x50))(opPtr[3], opPtr[2], 1);
                    break;
                case 0x1b:
                    resultVal = (double)(**(code**)(*DAT_803dd72c + 0x50))(opPtr[3], opPtr[2], 0);
                    break;
                case 0x1c:
                    subOp = opPtr[2];
                    if (subOp == 2)
                    {
                        flagBits = countLeadingZeros((uint)opPtr[3]);
                        resultVal = (double)FUN_80017698(0x3af, flagBits >> 5);
                    }
                    else if (subOp < 2)
                    {
                        if (subOp == 0)
                        {
                            flagBits = countLeadingZeros((uint)opPtr[3]);
                            resultVal = (double)FUN_80017698(0x3ab, flagBits >> 5);
                        }
                        else
                        {
                            flagBits = countLeadingZeros((uint)opPtr[3]);
                            resultVal = (double)FUN_80017698(0x3ac, flagBits >> 5);
                        }
                    }
                    else if (subOp < 4)
                    {
                        subOp = opPtr[3];
                        if (subOp == 1)
                        {
                            tmpResult = FUN_80017698(0x3b0, 0);
                            srcA = FUN_80017a98();
                            srcB = FUN_80017a98();
                            tmpResult = FUN_80006728(tmpResult, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                                  srcB, srcA, 0x134, 0, param_13, param_14, param_15, param_16);
                            srcA = FUN_80017a98();
                            srcB = FUN_80017a98();
                            tmpResult = FUN_80006728(tmpResult, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                                  srcB, srcA, 0x135, 0, param_13, param_14, param_15, param_16);
                            srcA = FUN_80017a98();
                            srcB = FUN_80017a98();
                            tmpResult = FUN_80006728(tmpResult, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                                  srcB, srcA, 0x142, 0, param_13, param_14, param_15, param_16);
                            resultVal = (double)FUN_80080f10(tmpResult, param_2, param_3, param_4, param_5, param_6, param_7,
                                                          param_8);
                        }
                        else if (subOp == 0)
                        {
                            tmpResult = FUN_80017698(0x3b0, 1);
                            srcA = FUN_80017a98();
                            srcB = FUN_80017a98();
                            tmpResult = FUN_80006728(tmpResult, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                                  srcB, srcA, 0x134, 0, param_13, param_14, param_15, param_16);
                            srcA = FUN_80017a98();
                            srcB = FUN_80017a98();
                            tmpResult = FUN_80006728(tmpResult, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                                  srcB, srcA, 0x135, 0, param_13, param_14, param_15, param_16);
                            srcA = FUN_80017a98();
                            srcB = FUN_80017a98();
                            resultVal = (double)FUN_80006728(tmpResult, param_2, param_3, param_4, param_5, param_6, param_7,
                                                          param_8, srcB, srcA, 0x142, 0, param_13, param_14,
                                                          param_15
                                                          , param_16);
                        }
                        else if (subOp < 3)
                        {
                            tmpResult = FUN_80017698(0x3b0, 1);
                            srcA = FUN_80017a98();
                            srcB = FUN_80017a98();
                            tmpResult = FUN_80006728(tmpResult, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                                  srcB, srcA, 0x136, 0, param_13, param_14, param_15, param_16);
                            srcA = FUN_80017a98();
                            srcB = FUN_80017a98();
                            tmpResult = FUN_80006728(tmpResult, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                                  srcB, srcA, 0x137, 0, param_13, param_14, param_15, param_16);
                            srcA = FUN_80017a98();
                            srcB = FUN_80017a98();
                            resultVal = (double)FUN_80006728(tmpResult, param_2, param_3, param_4, param_5, param_6, param_7,
                                                          param_8, srcB, srcA, 0x143, 0, param_13, param_14,
                                                          param_15
                                                          , param_16);
                        }
                    }
                    break;
                case 0x1d:
                    if (opPtr[2] == 0)
                    {
                        FUN_80017698(0x966, 1);
                        FUN_80017698(0x967, 1);
                        resultVal = (double)FUN_80017698(0x968, 1);
                    }
                    else
                    {
                        FUN_80017698(0x966, 0);
                        FUN_80017698(0x967, 0);
                        resultVal = (double)FUN_80017698(0x968, 0);
                    }
                    break;
                case 0x1e:
                    resultVal = (double)(**(code**)(*DAT_803dd72c + 0x44))(opPtr[3], opPtr[2]);
                    break;
                case 0x1f:
                    childSeq = (short*)FUN_80017a98();
                    delta = *objSeq - *childSeq;
                    if (0x8000 < delta)
                    {
                        delta = delta + 1;
                    }
                    if (delta < -0x8000)
                    {
                        delta = delta + -1;
                    }
                    iResult = (int)delta;
                    if (iResult < 0)
                    {
                        iResult = -iResult;
                    }
                    if (iResult < 0x4001)
                    {
                        iResult = FUN_80056600();
                        param_13 = *DAT_803dd72c;
                        resultVal = (double)(**(code**)(param_13 + 0x1c))
                            (objSeq + 6, (int)*objSeq, opPtr[3], iResult);
                    }
                    else
                    {
                        iResult = FUN_80056600();
                        param_13 = *DAT_803dd72c;
                        resultVal = (double)(**(code**)(param_13 + 0x1c))
                        (objSeq + 6, (int)(short)(*objSeq + -0x8000), opPtr[3], iResult
                        );
                    }
                    break;
                case 0x20:
                    if (opPtr[2] == 0)
                    {
                        resultVal = (double)FUN_80056a20();
                    }
                    else
                    {
                        resultVal = (double)FUN_800569f4();
                    }
                    break;
                case 0x21:
                    subOp = opPtr[2];
                    flagBits = (uint)subOp << 8 & 0x1f00 | (uint)opPtr[3];
                    flagReg = FUN_80017690(flagBits);
                    resultVal = (double)FUN_80017698(flagBits, flagReg ^ 1 << (((uint)subOp << 8) >> 0xd));
                    break;
                case 0x22:
                    stateIdx = *(undefined2*)(opPtr + 2);
                    subOp = (**(code**)(*DAT_803dd72c + 0x4c))((int)*(char*)(objSeq + 0x56), stateIdx);
                    resultVal = (double)(**(code**)(*DAT_803dd72c + 0x50))
                        ((int)*(char*)(objSeq + 0x56), stateIdx, subOp ^ 1);
                    break;
                case 0x23:
                    subOp = opPtr[2];
                    if (subOp == 2)
                    {
                        resultVal = (double)(**(code**)(*DAT_803dd72c + 0x28))();
                    }
                    else if (subOp < 2)
                    {
                        if (subOp == 0)
                        {
                            iResult = FUN_80056600();
                            param_13 = *DAT_803dd72c;
                            resultVal = (double)(**(code**)(param_13 + 0x24))(objSeq + 6, (int)*objSeq, iResult, 0);
                        }
                        else
                        {
                            resultVal = (double)(**(code**)(*DAT_803dd72c + 0x2c))();
                        }
                    }
                    else if (subOp < 4)
                    {
                        iResult = FUN_80056600();
                        param_13 = *DAT_803dd72c;
                        resultVal = (double)(**(code**)(param_13 + 0x24))(objSeq + 6, (int)*objSeq, iResult, 1);
                    }
                    break;
                case 0x26:
                    iResult = FUN_80017a90();
                    if (iResult != 0)
                    {
                        subOp = opPtr[2];
                        if (subOp == 2)
                        {
                            childObj = ObjGroup_FindNearestObject(0x32, iResult, (float*)0x0);
                            resultVal = tmpF1d;
                            if (childObj == 0)
                            {
                                childObj = ObjGroup_FindNearestObject(0x31, iResult, (float*)0x0);
                                resultVal = tmpF1e;
                            }
                            if (childObj != 0)
                            {
                                resultVal = (double)(**(code**)(**(int**)(iResult + 0x68) + 0x38))(iResult);
                            }
                        }
                        else if (subOp < 2)
                        {
                            if (subOp == 0)
                            {
                                resultVal = (double)(**(code**)(**(int**)(iResult + 0x68) + 0x3c))();
                            }
                            else
                            {
                                iResult = FUN_80017a90();
                                resultVal = (double)FUN_80017ac8(resultVal, param_2, param_3, param_4, param_5, param_6,
                                                              param_7
                                                              , param_8, iResult);
                            }
                        }
                        else if (subOp == 4)
                        {
                            resultVal = (double)FUN_80017698(0xd00, 1);
                        }
                        else if (subOp < 4)
                        {
                            resultVal = (double)FUN_80017698(0xd00, 0);
                        }
                    }
                    break;
                case 0x27:
                    FUN_80041c10(resultVal, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                 (uint) * (ushort*)(opPtr + 2));
                    FUN_800178bc();
                    resultVal = (double)FUN_800723a0();
                    break;
                case 0x28:
                    FUN_80043030(resultVal, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
                    resultVal = (double)FUN_800723a0();
                    break;
                case 0x2a:
                    FUN_80042bec((uint)opPtr[2], (uint)opPtr[3]);
                    resultVal = (double)FUN_800723a0();
                    break;
                case 0x2b:
                    FUN_80042b9c((uint)opPtr[2], (uint)opPtr[3], 0);
                    resultVal = (double)FUN_800723a0();
                    break;
                case 0x2c:
                    param_2 = (double)lbl_803E4D98;
                    local_34[2] = *(ushort*)(opPtr + 2) ^ 0x80000000;
                    local_34[1] = 0x43300000;
                    **(float**)(objBase + 0xb8) =
                        (float)(param_2 *
                            (double)(float)((double)CONCAT44(0x43300000, local_34[2]) - DOUBLE_803e4d68));
                    resultVal = prevResult;
                    break;
                case 0x2d:
                    iResult = FUN_80017a98();
                    if (iResult == 0)
                    {
                        iResult = FUN_8020a6fc();
                        if (iResult != 0)
                        {
                            resultVal = (double)FUN_80125b7c(resultVal, param_2, param_3, param_4, param_5, param_6, param_7,
                                                          param_8, (uint) * (ushort*)(opPtr + 2));
                        }
                    }
                    else
                    {
                        param_13 = *DAT_803dd6e8;
                        resultVal = (double)(**(code**)(param_13 + 0x38))
                            (*(undefined2*)(opPtr + 2), 0x14, 0x8c, 1);
                    }
                    break;
                case 0x2e:
                    resultVal = (double)FUN_80040da0();
                    break;
                case 0x2f:
                    iResult = ObjGroup_FindNearestObject(0x4c, objSeq, (float*)0x0);
                    resultVal = tmpF1c;
                    if (iResult != 0)
                    {
                        resultVal = (double)FUN_8020a908(iResult, (uint)opPtr[3] * 0x3c);
                    }
                }
            }
        }
    switchD_80199a5c_caseD_0:
        opIndex = opIndex + 1;
        opPtr = opPtr + 4;
    }
    while (true);
}

void FUN_8019ae30(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  undefined4 param_9, undefined4 param_10, float* param_11, undefined4 param_12,
                  int param_13, undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    short seqType;
    bool allSet;
    bool ok;
    int obj;
    int self;
    int target;
    uint mode;
    byte* walker;
    int unaff_r28;
    int childObj;
    short* placement;
    byte* state;
    undefined8 extraout_f1;
    undefined8 extraout_f1_00;
    undefined8 extraout_f1_01;
    undefined8 seqResult;
    float local_28[10];

    obj = FUN_8028683c();
    state = ((GameObject *)obj)->extra;
    placement = *(short**)&((GameObject *)obj)->anim.placementData;
    local_28[0] = lbl_803E4D9C;
    if ((placement[0x1c] < 1) || (*placement == 0xf4))
    {
        seqResult = extraout_f1;
        self = FUN_80017a98();
        if (self == 0)
        {
            self = FUN_8020a6fc();
        }
        else
        {
            target = FUN_80294dbc(self);
            if (target != 0)
            {
                self = target;
            }
        }
        target = FUN_80017a90();
        if ((self != 0) || (target != 0))
        {
            if ((*state & 4) == 0)
            {
                ok = true;
                mode = (uint) * (byte*)((int)placement + 0x43);
                if (mode < 3)
                {
                    if (mode == 1)
                    {
                        if (target == 0)
                        {
                            ok = false;
                        }
                    }
                    else if (mode == 0)
                    {
                        target = self;
                        if (self == 0)
                        {
                            ok = false;
                        }
                    }
                    else
                    {
                        target = unaff_r28;
                        if (mode < 3)
                        {
                            target = (**(code**)(*DAT_803dd6d0 + 0xc))();
                            seqResult = extraout_f1_01;
                        }
                    }
                }
                else
                {
                    param_11 = local_28;
                    target = ObjGroup_FindNearestObject(mode - 1, obj, param_11);
                    seqResult = extraout_f1_00;
                    if (target == 0)
                    {
                        ok = false;
                    }
                }
                if (ok)
                {
                    if ((*state & 0x40) == 0)
                    {
                        *(undefined4*)(state + 0x1c) = *(undefined4*)(state + 0x28);
                        *(undefined4*)(state + 0x20) = *(undefined4*)(state + 0x2c);
                        *(undefined4*)(state + 0x24) = *(undefined4*)(state + 0x30);
                    }
                    else
                    {
                        if (*(byte*)((int)placement + 0x43) == 2)
                        {
                            *(undefined4*)(state + 0x1c) = *(undefined4*)(target + 0x18);
                            *(undefined4*)(state + 0x20) = *(undefined4*)(target + 0x1c);
                            *(undefined4*)(state + 0x24) = *(undefined4*)(target + 0x20);
                        }
                        else if (*(byte*)((int)placement + 0x43) < 2)
                        {
                            *(undefined4*)(state + 0x1c) = *(undefined4*)(target + 0x8c);
                            *(undefined4*)(state + 0x20) = *(undefined4*)(target + 0x90);
                            *(undefined4*)(state + 0x24) = *(undefined4*)(target + 0x94);
                        }
                        else
                        {
                            *(undefined4*)(state + 0x1c) = *(undefined4*)(target + 0x80);
                            *(undefined4*)(state + 0x20) = *(undefined4*)(target + 0x84);
                            *(undefined4*)(state + 0x24) = *(undefined4*)(target + 0x88);
                        }
                        *state = *state & 0xbf;
                    }
                    if (*(byte*)((int)placement + 0x43) < 3)
                    {
                        *(undefined4*)(state + 0x28) = *(undefined4*)(target + 0x18);
                        *(undefined4*)(state + 0x2c) = *(undefined4*)(target + 0x1c);
                        *(undefined4*)(state + 0x30) = *(undefined4*)(target + 0x20);
                    }
                    else
                    {
                        *(undefined4*)(state + 0x28) = *(undefined4*)(target + 0xc);
                        *(undefined4*)(state + 0x2c) = *(undefined4*)(target + 0x10);
                        *(undefined4*)(state + 0x30) = *(undefined4*)(target + 0x14);
                    }
                }
                seqType = *placement;
                if (seqType == 0x50)
                {
                    seqResult = objInterpretSeq_v11_unused(seqResult, param_2, param_3, param_4, param_5, param_6, param_7,
                                                        param_8, obj
                                                        , self, 1, 0, param_13, param_14, param_15, param_16);
                    self = FUN_8001769c();
                    if (self != 0)
                    {
                        FUN_80017ac8(seqResult, param_2, param_3, param_4, param_5, param_6, param_7, param_8, obj);
                    }
                }
                else if (seqType < 0x50)
                {
                    if (seqType == 0x4d)
                    {
                        if (ok)
                        {
                            childObj = *(int *)&((GameObject *)obj)->extra;
                            self = objFn_80198fa4(obj, (float*)(childObj + 0x28));
                            childObj = objFn_80198fa4(obj, (float*)(childObj + 0x1c));
                            if (self == 0)
                            {
                                if (childObj == 0)
                                {
                                    objInterpretSeq_v11_unused(seqResult, param_2, param_3, param_4, param_5, param_6,
                                                               param_7, param_8, obj,
                                                               target, 0xfffffffe, 0, param_13, param_14, param_15,
                                                               param_16);
                                }
                                else
                                {
                                    objInterpretSeq_v11_unused(seqResult, param_2, param_3, param_4, param_5, param_6,
                                                               param_7, param_8, obj,
                                                               target, 0xffffffff, 0, param_13, param_14, param_15,
                                                               param_16);
                                }
                            }
                            else if (childObj == 0)
                            {
                                objInterpretSeq_v11_unused(seqResult, param_2, param_3, param_4, param_5, param_6, param_7,
                                                           param_8, obj,
                                                           target, 1, 0, param_13, param_14, param_15, param_16);
                            }
                            else
                            {
                                objInterpretSeq_v11_unused(seqResult, param_2, param_3, param_4, param_5, param_6, param_7,
                                                           param_8, obj,
                                                           target, 2, 0, param_13, param_14, param_15, param_16);
                            }
                        }
                    }
                    else if (seqType < 0x4d)
                    {
                        if (seqType == 0x4b)
                        {
                            if (ok)
                            {
                                FUN_80199744(obj, target, param_11, param_12, param_13, param_14, param_15, param_16);
                            }
                        }
                        else if (0x4a < seqType)
                        {
                            allSet = true;
                            if (((int)((TriggerState*)state)->unk82 != 0xffffffff) &&
                                (mode = FUN_80017690((int)((TriggerState*)state)->unk82), mode == 0))
                            {
                                allSet = false;
                            }
                            if ((allSet) && (ok))
                            {
                                FUN_801991bc();
                            }
                        }
                    }
                    else if ((seqType < 0x4f) &&
                        (*(uint*)(state + 8) = *(int*)(state + 8) + (uint)DAT_803dc070,
                            (uint)(ushort)
                            placement[0x23] <= *(uint*)(state + 8)
                    )
                    )
                    {
                        objInterpretSeq_v11_unused(seqResult, param_2, param_3, param_4, param_5, param_6, param_7,
                                                   param_8, obj, 0, 1, 0,
                                                   param_13, param_14, param_15, param_16);
                    }
                }
                else if (seqType == 0xf4)
                {
                    if (ok)
                    {
                        FUN_80198e08();
                    }
                }
                else if (seqType < 0xf4)
                {
                    if (seqType == 0x54)
                    {
                        ok = true;
                        target = 0;
                        walker = state;
                        while ((target < 4 && (ok)))
                        {
                            if (((int)*(short*)(walker + 0x82) != 0xffffffff) &&
                                (mode = FUN_80017690((int)*(short*)(walker + 0x82)), mode == 0))
                            {
                                ok = false;
                            }
                            walker = walker + 2;
                            target = target + 1;
                        }
                        if ((ok) && (-1 < (char)state[0x8a]))
                        {
                            state[0x8a] = state[0x8a] & 0x7f | 0x80;
                            objInterpretSeq_v11_unused(seqResult, param_2, param_3, param_4, param_5, param_6, param_7,
                                                       param_8, obj,
                                                       self, 1, 0, param_13, param_14, param_15, param_16);
                        }
                        if (!ok)
                        {
                            state[0x8a] = state[0x8a] & 0x7f;
                        }
                    }
                }
                else if ((seqType == 0x230) && (ok))
                {
                    FUN_8019959c(obj, target, param_11, param_12, param_13, param_14, param_15, param_16);
                }
            }
            else
            {
                objInterpretSeq_v11_unused(seqResult, param_2, param_3, param_4, param_5, param_6, param_7, param_8, obj,
                                           self, 1, 0,
                                           param_13, param_14, param_15, param_16);
                *state = *state & 0xfb;
                *state = *state | 1;
            }
        }
    }
    FUN_80286888();
    return;
}

#pragma scheduling off
#pragma peephole off
void Trigger_render(void)
{
}

void Trigger_update(void)
{
}

void Trigger_release(void)
{
}

void Trigger_initialise(void)
{
}

void Trigger_free(void* obj)
{
    u8 i;
    u8* entry = *(u8**)&((GameObject*)obj)->anim.placementData + 0x18;
    i = 0;

    while (i < 8)
    {
        if ((entry[0] & 3) != 0 && entry[1] != 3 && entry[1] == 4)
        {
            Sfx_StopFromObject(obj, (u16)((entry[2] << 8) | entry[3]));
        }
        i++;
        entry += 4;
    }
}

typedef struct
{
    u8 bit7 : 1;
    u8 lo : 7;
} TriggerFlags8A;

void Trigger_init(u8* obj, u8* params)
{
    u8* sub;
    f32 t;

    objSetSlot(obj, 0x28);
    sub = ((GameObject*)obj)->extra;
    switch (*(s16*)params)
    {
    case 0x4b:
        t = (f32)(s32)(params[0x3a] * 2);
        ((TriggerState*)sub)->unk4 = t * t;
        ((GameObject*)obj)->anim.rotZ = 0;
        ((GameObject*)obj)->anim.rotY = 0;
        *(s16*)obj = (s16)(params[0x3d] << 8);
        ((GameObject*)obj)->anim.rootMotionScale = t / lbl_803E40F8;
        break;
    case 0x4c:
        ((TriggerState*)sub)->unk82 = *(s16*)(params + 0x48);
        objFn_80198fa4(obj, params);
        break;
    case 0x230:
        ((TriggerState*)sub)->unk4 = (f32)(s32)(params[0x3a] * 2);
        ((TriggerState*)sub)->unk4 = ((TriggerState*)sub)->unk4 * ((TriggerState*)sub)->unk4;
        break;
    case 0x4d:
        *(s16*)obj = (s16)(params[0x3d] << 8);
        ((GameObject*)obj)->anim.rotY = (s16)(params[0x3e] << 8);
        ((GameObject*)obj)->anim.rotZ = 0;
        break;
    case 0x54:
        ((TriggerState*)sub)->unk82 = *(s16*)(params + 0x48);
        ((TriggerState*)sub)->unk84 = *(s16*)(params + 0x4a);
        ((TriggerState*)sub)->unk86 = *(s16*)(params + 0x4c);
        ((TriggerState*)sub)->unk88 = *(s16*)(params + 0x4e);
        ((TriggerFlags8A*)(sub + 0x8a))->bit7 = 0;
        break;
    case 0x51:
        break;
    case 0xf4:
        break;
    default:
        break;
    }
    ((TriggerState*)sub)->unk80 = *(s16*)(params + 0x44);
    if (GameBit_Get(((TriggerState*)sub)->unk80) == 1)
    {
        sub[0] = (u8)(sub[0] | 0x04);
    }
    sub[0] = (u8)(sub[0] | 0x40);
}


int Trigger_getExtraSize(void) { return 0xac; }
int Trigger_getObjectTypeId(void) { return 0x0; }

/* cloudprisoncontrol map-event tables (recovered layout; kept raw int[] - the
 * struct-field form flips MWCC's variable-index/walker addressing, banked).
 * lbl_803AC7D8: registered-target list, 8-byte entries (count lbl_803DDB09):
 *   s32 target @0; s16 data @4; u8 unk6 @6 (zeroed on add); u8 pad @7.
 * lbl_803AC878: deferred-message queue, 12-byte entries (count lbl_803DDB08):
 *   s32 message @0; s32 target @4; s32 data @8. */

extern int ObjGroup_FindNearestObject(int group, int obj, int p3);

void objInterpretSeq(int obj, int p2, int p3, int p4)
{
    char* desc = (char*)&gTriggerObjDescriptor;
    u8* state = ((GameObject*)obj)->extra;
    u8* p = (u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x18);
    u8 i = 0;
    u8 b;
    u8 sflags;
    u8 c;
    int t;
    int t2;
    int* tbl;
    u32 op;
    u32 v;
    u32 bit;
    u32 sel;
    s16 d;
    int ang;
    int count;
    int first;
    u16 id;

    while (i < 8)
    {
        if (p[1] != 0 && ((sflags = *state, (sflags & 4) == 0) || (*p & 0x20) != 0))
        {
            b = *p;
            if ((b & 0x10) == 0)
            {
                if ((s8)p3 == 1)
                {
                    if ((b & 1) != 0)
                    {
                        if ((sflags & 1) != 0)
                        {
                            if ((b & 4) == 0)
                            {
                                goto next;
                            }
                        }
                        goto run;
                    }
                }
                else if ((s8)p3 == -1 && (b & 2) != 0)
                {
                    if ((sflags & 2) != 0)
                    {
                        if ((b & 8) == 0)
                        {
                            goto next;
                        }
                    }
                    goto run;
                }
            }
            else if ((b & 1) != 0)
            {
                if ((s8)p3 < 0)
                {
                    goto next;
                }
                goto run;
            }
            else if ((b & 2) == 0 || (s8)p3 <= 0)
            {
            run:
                switch (p[1])
                {
                case 1:
                    switch (p[2])
                    {
                    case 0:
                        break;
                    case 8:
                        t = Obj_GetPlayerObject();
                        if ((void*)t != NULL)
                        {
                            fn_80295918(t, 1, lbl_803E40D8);
                        }
                        break;
                    case 9:
                        t = Obj_GetPlayerObject();
                        if ((void*)t != NULL)
                        {
                            fn_80295918(t, 10, lbl_803E40D8);
                        }
                        break;
                    case 10:
                        t = Obj_GetPlayerObject();
                        if ((void*)t != NULL)
                        {
                            fn_80295918(t, 0xb, lbl_803E40D8);
                        }
                        break;
                    case 0xb:
                        t = Obj_GetPlayerObject();
                        if ((void*)t != NULL)
                        {
                            fn_80295918(t, 1, lbl_803E40FC);
                        }
                        break;
                    }
                    break;
                case 4:
                    if ((s8)p3 >= 0)
                    {
                        Sfx_PlayFromObject(obj, (u16)((p[2] << 8) | p[3]));
                    }
                    else
                    {
                        Sfx_StopFromObject((void*)obj, (u16)((p[2] << 8) | p[3]));
                    }
                    break;
                case 6:
                    (*gCameraInterface)->loadTriggeredCamAction(p[2], p[3], 0);
                    break;
                case 8:
                    switch (p[2])
                    {
                    case 0:
                        if (p[3] > 1)
                        {
                            p[3] = 1;
                        }
                        setDrawCloudsAndLights(p[3]);
                        break;
                    case 1:
                        if (p[3] > 1)
                        {
                            p[3] = 1;
                        }
                        gameFlagFn_8005ce6c(p[3]);
                        break;
                    case 2:
                        if (p[3] > 1)
                        {
                            p[3] = 1;
                        }
                        setDrawLights(p[3]);
                        break;
                    case 3:
                        if (p[3] > 1)
                        {
                            p[3] = 1;
                        }
                        (*gCloudActionInterface)->func09Nop(p[3]);
                        break;
                    case 4:
                        (*(code*)(*gPlayerShadowInterface + 0xc))(p[3]);
                        break;
                    case 5:
                        fn_8006FC00(p[3]);
                        break;
                    case 6:
                        if (p[3] != 0)
                        {
                            skyFn_80088c94(7, 1);
                        }
                        else
                        {
                            skyFn_80088c94(7, 0);
                        }
                        break;
                    case 7:
                        if (p[3] != 0)
                        {
                            gameFlagFn_8005cd24(1);
                        }
                        else
                        {
                            gameFlagFn_8005cd24(0);
                        }
                        break;
                    case 8:
                        if (p[3] != 0)
                        {
                            timeOfDayFn_80055038();
                        }
                        else
                        {
                            timeOfDayFn_80055000();
                        }
                        break;
                    case 9:
                        skyFn_80088e54(getSkyStructField24C() ^ 1, (f32)(u32)p[3]);
                        break;
                    case 10:
                        skyFn_80088e54(0, (f32)(u32)p[3]);
                        break;
                    case 0xb:
                        skyFn_80088e54(1, (f32)(u32)p[3]);
                        break;
                    }
                    break;
                case 5:
                    if (((TriggerState*)state)->unk4 != lbl_803E40D8)
                    {
                        break;
                    }
                    break;
                case 10:
                    getEnvfxAct(obj, p2, (u16)((p[2] << 8) | p[3]), p4);
                    OSReport(desc + 0x68, (int)((GameObject*)obj)->anim.classId, (p[2] << 8) | p[3], p4);
                    break;
                case 0xd:
                    getLActions(obj, p2, (u16)((p[2] << 8) | p[3]), p3, p4, 0);
                    break;
                case 0xb:
                    switch (p[2])
                    {
                    case 0:
                    case 3:
                        t = ObjGroup_FindNearestObject(0xf, obj, 0);
                        if ((void*)t != NULL)
                        {
                            (*gObjectTriggerInterface)
                                ->runSequence(p[3], (void*)t, -1);
                        }
                        break;
                    case 1:
                        (*gObjectTriggerInterface)->setFlag(p[3], 1);
                        break;
                    case 2:
                        (*gObjectTriggerInterface)->setFlag(p[3], 0);
                        break;
                    }
                    break;
                case 0xc:
                    id = (u16)((p[2] << 8) | p[3]);
                    t = ObjList_GetObjects(&first, &count);
                    for (; first < count; first++)
                    {
                        t2 = *(int*)(t + first * 4);
                        tbl = *(int**)(t2 + 0x4c);
                        if (tbl == NULL)
                        {
                            continue;
                        }
                        d = *(s16*)tbl;
                        if (d == 0x54)
                        {
                            goto match;
                        }
                        if (d > 0x54)
                        {
                            if (d == 0x230)
                            {
                                goto match;
                            }
                            continue;
                        }
                        if (d >= 0x51 || d < 0x4b)
                        {
                            continue;
                        }
                    match:
                        if (*(s16*)((char*)tbl + 0x38) == id)
                        {
                            objInterpretSeq(t2, p2, p3, p4);
                        }
                    }
                    break;
                case 0x10:
                    Obj_SetActiveModelIndex(Obj_GetPlayerObject(), p[2]);
                    break;
                case 0x12:
                    op = (u16)((p[2] << 8) | p[3]);
                    bit = op & 0x3fff;
                    v = GameBit_Get(bit);
                    sel = op >> 14 & 3;
                    if (sel == 0)
                    {
                        v = 0;
                    }
                    else if (sel == 1)
                    {
                        v = 0xffffffff;
                    }
                    else if (sel == 2)
                    {
                        v = ~v;
                    }
                    GameBit_Set(bit, v);
                    break;
                case 0x21:
                    op = (u16)((p[2] << 8) | p[3]);
                    bit = op & 0x1fff;
                    GameBit_Set(bit, GameBit_Get(bit) ^ (1 << (op >> 13)));
                    break;
                case 0x13:
                    (*gMapEventInterface)->setObjGroupStatus(
                        (int)((GameObject*)obj)->anim.mapEventSlot, (p[2] << 8) | p[3], 1);
                    break;
                case 0x27:
                    id = (u16)((p[2] << 8) | p[3]);
                    mapLoadDataFiles(id);
                    loadModelAndAnimTabs();
                    OSReport(desc + 0xa8, id);
                    break;
                case 0x28:
                    id = (u16)((p[2] << 8) | p[3]);
                    mapUnload(id, 0x20000000);
                    OSReport(desc + 0xc4, id);
                    break;
                case 0x2e:
                    defragMemory(0);
                    break;
                case 0x2a:
                    lockLevel(p[2], p[3]);
                    OSReport(desc + 0xe0, p[2], p[3]);
                    break;
                case 0x2b:
                    unlockLevel(p[2], p[3], 0);
                    OSReport(desc + 0x114, p[2], p[3]);
                    break;
                case 0x2f:
                    t = ObjGroup_FindNearestObject(0x4c, obj, 0);
                    if ((void*)t != NULL)
                    {
                        timer_addDuration(t, (u32)p[3] * 0x3c);
                    }
                    break;
                case 0x14:
                    (*gMapEventInterface)->setObjGroupStatus(
                        (int)((GameObject*)obj)->anim.mapEventSlot, (p[2] << 8) | p[3], 0);
                    break;
                case 0x22:
                    id = (u16)((p[2] << 8) | p[3]);
                    c = (*gMapEventInterface)->getObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, id);
                    (*gMapEventInterface)->setObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, id, c ^ 1);
                    break;
                case 0x15:
                    if ((tbl = (int*)getTablesBinEntry((u16)((p[2] << 8) | p[3]) + 2)) != NULL)
                    {
                        for (; *tbl != -1; tbl++)
                        {
                            if ((void*)getLoadedTexture(*tbl) == NULL)
                            {
                                crash(0x32, 3, 0, *tbl, 0, 0, 0, 0);
                            }
                        }
                    }
                    break;
                case 0x16:
                    if ((tbl = (int*)getTablesBinEntry((u16)((p[2] << 8) | p[3]) + 2)) != NULL)
                    {
                        for (; *tbl != -1; tbl++)
                        {
                            if ((void*)getLoadedTexture(*tbl) != NULL)
                            {
                                textureFree(*tbl);
                            }
                        }
                    }
                    break;
                case 0x18:
                    (*gMapEventInterface)->setMapAct(
                        (int)((GameObject*)obj)->anim.mapEventSlot, (p[2] << 8) | p[3]);
                    break;
                case 0x1a:
                    (*gMapEventInterface)->setObjGroupStatus(p[3], p[2], 1);
                    break;
                case 0x1b:
                    (*gMapEventInterface)->setObjGroupStatus(p[3], p[2], 0);
                    break;
                case 0x1e:
                    (*gMapEventInterface)->setMapAct(p[3], p[2]);
                    break;
                case 0x11:
                    GameBit_Set(0x4e3, (p[2] << 8) | p[3]);
                    break;
                case 0x1f:
                    t = Obj_GetPlayerObject();
                    d = *(s16*)obj - (u16) * (s16*)t;
                    if (d > 0x8000)
                    {
                        d = (d - 0x10000) + 1;
                    }
                    if (d < -0x8000)
                    {
                        d = (d + 0x10000) - 1;
                    }
                    ang = d;
                    if (ang < 0)
                    {
                        ang = -ang;
                    }
                    if (ang > 0x4000)
                    {
                        (*gMapEventInterface)->savePoint(obj + 0xc,
                                                            (int)(s16)(*(s16*)obj + 0x8000),
                                                            p[3], getCurMapLayer());
                    }
                    else
                    {
                        (*gMapEventInterface)->savePoint(obj + 0xc, (int)*(s16*)obj,
                                                            p[3], getCurMapLayer());
                    }
                    break;
                case 0x20:
                    if (p[2] == 0)
                    {
                        goToNextMapLayer();
                    }
                    else
                    {
                        goToPrevMapLayer();
                    }
                    break;
                case 0x23:
                    switch (((ObjInterpretSeqPlacement*)p)->unk2)
                    {
                    case 0:
                        (*gMapEventInterface)->restartPoint((void*)(obj + 0xc), (int)*(s16*)obj,
                                                                    getCurMapLayer(), 0);
                        break;
                    case 1:
                        (*gMapEventInterface)->clearRestartPoint();
                        break;
                    case 2:
                        (*gMapEventInterface)->gotoRestartPoint();
                        break;
                    case 3:
                        (*gMapEventInterface)->restartPoint((void*)(obj + 0xc), (int)*(s16*)obj,
                                                                    getCurMapLayer(), 1);
                        break;
                    }
                    break;
                case 0x26:
                    t = getTrickyObject();
                    if ((void*)t != NULL)
                    {
                        switch (((ObjInterpretSeqPlacement*)p)->unk2)
                        {
                        case 0:
                            (*(code*)(**(int**)(t + 0x68) + 0x3c))();
                            break;
                        case 1:
                            Obj_FreeObject(getTrickyObject());
                            break;
                        case 2:
                            t2 = ObjGroup_FindNearestObject(0x32, t, 0);
                            if ((void*)t2 == NULL)
                            {
                                t2 = ObjGroup_FindNearestObject(0x31, t, 0);
                            }
                            if ((void*)t2 != NULL)
                            {
                                (*(code*)(**(int**)(t + 0x68) + 0x38))(t);
                            }
                            break;
                        case 3:
                            GameBit_Set(0xd00, 0);
                            break;
                        case 4:
                            GameBit_Set(0xd00, 1);
                            break;
                        }
                    }
                    break;
                case 0x1c:
                    switch (p[2])
                    {
                    case 0:
                        GameBit_Set(0x3ab, p[3] == 0);
                        break;
                    case 1:
                        GameBit_Set(0x3ac, p[3] == 0);
                        break;
                    case 2:
                        GameBit_Set(0x3af, p[3] == 0);
                        break;
                    case 3:
                        switch (p[3])
                        {
                        case 0:
                            GameBit_Set(0x3b0, 1);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x134, 0);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x135, 0);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x142, 0);
                            break;
                        case 1:
                            GameBit_Set(0x3b0, 0);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x134, 0);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x135, 0);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x142, 0);
                            envFxFn_800887cc();
                            break;
                        case 2:
                            GameBit_Set(0x3b0, 1);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x136, 0);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x137, 0);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x143, 0);
                            break;
                        }
                        break;
                    }
                    break;
                case 0x1d:
                    if (p[2] != 0)
                    {
                        GameBit_Set(0x966, 0);
                        GameBit_Set(0x967, 0);
                        GameBit_Set(0x968, 0);
                    }
                    else
                    {
                        GameBit_Set(0x966, 1);
                        GameBit_Set(0x967, 1);
                        GameBit_Set(0x968, 1);
                    }
                    break;
                case 0x2c:
                    **(f32**)(p2 + 0xb8) = lbl_803E4100 * (f32)(s16)((p[2] << 8) | p[3]);
                    break;
                case 0x2d:
                    t = Obj_GetPlayerObject();
                    if ((void*)t != NULL)
                    {
                        (*gGameUIInterface)->showNpcDialogue((p[2] << 8) | p[3], 0x14, 0x8c, 1);
                    }
                    else if ((void*)getArwing() != NULL)
                    {
                        gameTextFn_80125ba4((p[2] << 8) | p[3]);
                    }
                    break;
                }
            }
        }
    next:
        i++;
        p += 4;
    }
    if ((s8)p3 > 0)
    {
        *state |= 1;
        GameBit_Set(((TriggerState*)state)->unk80, 1);
    }
    else if ((s8)p3 < 0)
    {
        *state |= 2;
    }
}

void Trigger_hitDetect(int obj)
{
    u8* state = ((GameObject*)obj)->extra;
    u8* def = *(u8**)&((GameObject*)obj)->anim.placementData;
    int t;
    int tk;
    int target;
    int ok;
    int ok2;
    int r1;
    int r2;
    int i;
    u8* p8;
    u8 c;
    s16 ty;
    f32 dist[1];

    dist[0] = lbl_803E4104;
    if (((TriggerPlacement*)def)->unk38 <= 0 || *(s16*)def == 0xf4)
    {
        t = Obj_GetPlayerObject();
        if ((void*)t != NULL)
        {
            r1 = fn_802972A8();
            if ((void*)r1 != NULL)
            {
                t = r1;
            }
        }
        else
        {
            t = getArwing();
        }
        tk = getTrickyObject();
        if ((void*)t != NULL || (void*)tk != NULL)
        {
            if ((*state & 4) != 0)
            {
                objInterpretSeq(obj, t, 1, 0);
                *state &= ~4;
                *state |= 1;
            }
            else
            {
                ok = 1;
                c = def[0x43];
                if (c > 2)
                {
                    target = ObjGroup_FindNearestObject(c - 1, obj, (int)dist);
                    if ((void*)target == NULL)
                    {
                        ok = 0;
                    }
                }
                else
                {
                    switch (c)
                    {
                    case 0:
                        target = t;
                        if ((void*)t == NULL)
                        {
                            ok = 0;
                        }
                        break;
                    case 1:
                        target = tk;
                        if ((void*)tk == NULL)
                        {
                            ok = 0;
                        }
                        break;
                    case 2:
                        target = (int)(*gCameraInterface)->getCamera();
                        break;
                    }
                }
                if (ok)
                {
                    if ((*state & 0x40) != 0)
                    {
                        if ((s8)def[0x43] == 2)
                        {
                            ((TriggerState*)state)->unk1C = ((GameObject*)target)->anim.worldPosX;
                            ((TriggerState*)state)->unk20 = ((GameObject*)target)->anim.worldPosY;
                            ((TriggerState*)state)->unk24 = ((GameObject*)target)->anim.worldPosZ;
                        }
                        else if ((s8)def[0x43] < 2)
                        {
                            ((TriggerState*)state)->unk1C = ((GameObject*)target)->anim.previousWorldPosX;
                            ((TriggerState*)state)->unk20 = ((GameObject*)target)->anim.previousWorldPosY;
                            ((TriggerState*)state)->unk24 = ((GameObject*)target)->anim.previousWorldPosZ;
                        }
                        else
                        {
                            ((TriggerState*)state)->unk1C = ((GameObject*)target)->anim.previousLocalPosX;
                            ((TriggerState*)state)->unk20 = ((GameObject*)target)->anim.previousLocalPosY;
                            ((TriggerState*)state)->unk24 = ((GameObject*)target)->anim.previousLocalPosZ;
                        }
                        *state &= ~0x40;
                    }
                    else
                    {
                        ((TriggerState*)state)->unk1C = ((TriggerState*)state)->unk28;
                        ((TriggerState*)state)->unk20 = ((TriggerState*)state)->unk2C;
                        ((TriggerState*)state)->unk24 = ((TriggerState*)state)->unk30;
                    }
                    if ((s8)def[0x43] < 3)
                    {
                        ((TriggerState*)state)->unk28 = ((GameObject*)target)->anim.worldPosX;
                        ((TriggerState*)state)->unk2C = ((GameObject*)target)->anim.worldPosY;
                        ((TriggerState*)state)->unk30 = ((GameObject*)target)->anim.worldPosZ;
                    }
                    else
                    {
                        ((TriggerState*)state)->unk28 = ((GameObject*)target)->anim.localPosX;
                        ((TriggerState*)state)->unk2C = ((GameObject*)target)->anim.localPosY;
                        ((TriggerState*)state)->unk30 = ((GameObject*)target)->anim.localPosZ;
                    }
                }
                switch (*(s16*)def)
                {
                case 0x4b:
                    if (ok)
                    {
                        objSeqFn_801992ec(obj, target);
                    }
                    break;
                case 0x230:
                    if (ok)
                    {
                        objSeqMoveFn_80199188(obj, target);
                    }
                    break;
                case 0x4c:
                    ok2 = 1;
                    if (((TriggerState*)state)->unk82 != -1 && (u32)GameBit_Get(((TriggerState*)state)->unk82) == 0)
                    {
                        ok2 = 0;
                    }
                    if (ok2 && ok)
                    {
                        fn_80198DE8(obj, target);
                    }
                    break;
                case 0x4e:
                    ((TriggerState*)state)->unk8 = *(int*)&((TriggerState*)state)->unk8 + framesThisStep;
                    if (((TriggerState*)state)->unk8 >= (u32)((TriggerPlacement*)def)->unk46)
                    {
                        objInterpretSeq(obj, 0, 1, 0);
                    }
                    break;
                case 0x4d:
                    if (ok)
                    {
                        {
                            int extra = *(int*)&((GameObject*)obj)->extra;
                            r1 = fn_80198B68(obj, extra + 0x28);
                            r2 = fn_80198B68(obj, extra + 0x1c);
                        }
                        if (r1 != 0)
                        {
                            if (r2 == 0)
                            {
                                objInterpretSeq(obj, target, 1, 0);
                            }
                            else
                            {
                                objInterpretSeq(obj, target, 2, 0);
                            }
                        }
                        else if (r2 != 0)
                        {
                            objInterpretSeq(obj, target, -1, 0);
                        }
                        else
                        {
                            objInterpretSeq(obj, target, -2, 0);
                        }
                    }
                    break;
                case 0x50:
                    objInterpretSeq(obj, t, 1, 0);
                    if (return1_800202BC() != 0)
                    {
                        Obj_FreeObject(obj);
                    }
                    break;
                case 0x54:
                    ok = 1;
                    i = 0;
                    p8 = state;
                    while (i < 4 && ok)
                    {
                        if (*(s16*)(p8 + 0x82) != -1 && (u32)GameBit_Get(*(s16*)(p8 + 0x82)) == 0)
                        {
                            ok = 0;
                        }
                        p8 += 2;
                        i++;
                    }
                    if (ok && ((TriggerFlags8A*)(state + 0x8a))->bit7 == 0)
                    {
                        ((TriggerFlags8A*)(state + 0x8a))->bit7 = 1;
                        objInterpretSeq(obj, t, 1, 0);
                    }
                    if (!ok)
                    {
                        ((TriggerFlags8A*)(state + 0x8a))->bit7 = 0;
                    }
                    break;
                case 0xf4:
                    if (ok)
                    {
                        fn_80198A00(obj, target);
                    }
                    break;
                }
            }
        }
    }
}
