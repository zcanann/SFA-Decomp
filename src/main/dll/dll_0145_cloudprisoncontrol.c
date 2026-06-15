#include "main/game_object.h"
#include "main/objseq.h"
#include "main/dll/rom_curve_interface.h"

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
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
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
extern s8 lbl_803DBE08;
extern f32 lbl_803E4108;
extern void objRenderFn_8003b8f4(f32);
extern s8 lbl_803DDB08;
extern s8 lbl_803DDB09;
extern int lbl_803DDB0C;
extern int lbl_803AC7D8[];
extern int lbl_803AC878[];

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
                            if (((int)*(short*)(state + 0x82) != 0xffffffff) &&
                                (mode = FUN_80017690((int)*(short*)(state + 0x82)), mode == 0))
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

void Trigger_render(void);

#pragma scheduling off
#pragma peephole off
void cloudprisoncontrol_free(void)
{
}

void cloudprisoncontrol_hitDetect(void)
{
}

void cloudprisoncontrol_release(void)
{
}

int Trigger_getExtraSize(void);
int cloudprisoncontrol_getExtraSize(void) { return 0x0; }
int cloudprisoncontrol_getObjectTypeId(void) { return 0x0; }

void cloudprisoncontrol_initialise(void) { lbl_803DBE08 = 0x1; }

void cloudprisoncontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4108);
}

void cloudprisoncontrol_init(int x) { ObjMsg_AllocQueue(x, 0xa); }

int cfguardian_setScale(int* obj);

/* cloudprisoncontrol map-event tables (recovered layout; kept raw int[] - the
 * struct-field form flips MWCC's variable-index/walker addressing, banked).
 * lbl_803AC7D8: registered-target list, 8-byte entries (count lbl_803DDB09):
 *   s32 target @0; s16 data @4; u8 unk6 @6 (zeroed on add); u8 pad @7.
 * lbl_803AC878: deferred-message queue, 12-byte entries (count lbl_803DDB08):
 *   s32 message @0; s32 target @4; s32 data @8. */

#pragma opt_unroll_loops off
void cloudprisoncontrol_update(int obj)
{
    int target;
    int data;
    int msg[2];
    int found;
    int i;
    int n;
    int idx;
    int dval;
    int* p;
    u32 cnt;

    data = 0;
    if (lbl_803DBE08 != 0)
    {
        lbl_803DDB0C = ((int (*)(int))(*gRomCurveInterface)->slot40)(8);
        lbl_803DBE08 = 0;
    }
    lbl_803DDB08 = 0;
    while (ObjMsg_Pop(obj, msg, &target, &data) != 0)
    {
        switch (msg[0])
        {
        case 0xf0004:
            if (((GameObject*)target)->anim.mapEventSlot == ((GameObject*)obj)->anim.mapEventSlot)
            {
                found = 0;
                p = lbl_803AC7D8;
                dval = data;
                n = lbl_803DDB09;
                for (i = 0; i < n; i++)
                {
                    if (*(u32*)p == (u32)target)
                    {
                        *(s16*)((char*)p + 4) = dval;
                        found = 1;
                    }
                    p += 2;
                }
                if (!found)
                {
                    i = lbl_803DDB09;
                    lbl_803AC7D8[i * 2] = target;
                    *(u8*)((char*)lbl_803AC7D8 + i * 8 + 6) = 0;
                    lbl_803DDB09++;
                    *(s16*)((char*)lbl_803AC7D8 + i * 8 + 4) = data;
                }
                ObjMsg_SendToObject(target, 0xf0003, obj, 0);
            }
            break;
        case 0xf0005:
        case 0xf0006:
        case 0xf0007:
            break;
        case 0xf0008:
            i = 0;
            for (p = lbl_803AC7D8; i < lbl_803DDB09 && *p != target; p += 2)
            {
                i++;
            }
            lbl_803DDB09--;
            n = lbl_803DDB09;
            p = lbl_803AC7D8 + n * 2;
            cnt = n - i;
            if (n > i)
            {
                for (i = 0; i < (int)cnt; i++)
                {
                    p[-2] = p[0];
                    *(s16*)((char*)p - 4) = *(s16*)((char*)p + 4);
                    *(u8*)((char*)p - 2) = *(u8*)((char*)p + 6);
                    p -= 2;
                }
            }
            break;
        default:
            idx = lbl_803DDB08 * 0xc;
            *(int*)((char*)lbl_803AC878 + idx + 4) = target;
            *(int*)((char*)lbl_803AC878 + idx) = msg[0];
            *(int*)((char*)lbl_803AC878 + idx + 8) = data;
            lbl_803DDB08++;
            break;
        }
    }
}
#pragma opt_unroll_loops reset

extern int ObjGroup_FindNearestObject(int group, int obj, int p3);
