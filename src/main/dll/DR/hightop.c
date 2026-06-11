#include "main/dll/DR/hightop.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objanim.h"
#include "main/objseq.h"
#include "main/dll/rom_curve_interface.h"

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
extern undefined4 FUN_80017a7c();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017af0();
extern int FUN_80017b00();
extern int ObjGroup_FindNearestObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 FUN_8003b818();
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
extern undefined4 FUN_80199440();
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

extern uint DAT_803ad438;
extern undefined4 DAT_803ad43c;
extern undefined4 DAT_803ad43e;
extern undefined4 DAT_803ad4d8;
extern undefined4 DAT_803ad4dc;
extern undefined4 DAT_803ad4e0;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dca70;
extern undefined4* DAT_803dd6d0;
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern undefined4* DAT_803dd6e4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd704;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de788;
extern undefined4 DAT_803de789;
extern undefined4 DAT_803de78c;
extern f64 DOUBLE_803e4d68;
extern f64 DOUBLE_803e4d88;
extern f32 lbl_803E4D70;
extern f32 lbl_803E4D90;
extern f32 lbl_803E4D94;
extern f32 lbl_803E4D98;
extern f32 lbl_803E4D9C;

/*
 * --INFO--
 *
 * Function: objInterpretSeq
 * EN v1.0 Address: 0x801993B0
 * EN v1.0 Size: 6644b
 * EN v1.1 Address: 0x8019992C
 * EN v1.1 Size: 3936b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
undefined4 objInterpretSeq_v11_unused(undefined8 arg1, double arg2, double arg3, undefined8 arg4,
                                      undefined8 arg5, undefined8 arg6, undefined8 arg7, undefined8 arg8,
                                      undefined4 arg9, undefined4 arg10, undefined4 arg11, int arg12,
                                      int arg13, undefined4 arg14, undefined4 arg15, undefined4 arg16)
{
    byte bval2;
    undefined2 uval7;
    ushort uval8;
    double fb;
    short sval;
    uint uval4;
    short* ptr2;
    uint uval5;
    uint uval6;
    int val;
    byte bval;
    int* ptr3;
    short* ptr5;
    int val2;
    undefined4 uval2;
    undefined4 uval3;
    int val3;
    byte bval4;
    byte* ptr4;
    char bval3;
    byte* ptr;
    double tmpF1a;
    double tmpF1b;
    double tmpF1c;
    double fa;
    double tmpF1d;
    double tmpF1e;
    undefined8 uval;
    int tmp2;
    int tmp[13];

    uval = FUN_8028682c();
    ptr2 = (short*)((ulonglong)uval >> 0x20);
    val3 = (int)uval;
    ptr4 = *(byte**)(ptr2 + 0x5c);
    ptr = (byte*)(*(int*)(ptr2 + 0x26) + 0x18);
    bval4 = 0;
    fa = tmpF1a;
    do
    {
        fb = DOUBLE_803e4d68;
        bval3 = (char)arg11;
        if (7 < bval4)
        {
            if (bval3 < '\x01')
            {
                if (bval3 < '\0')
                {
                    *ptr4 = *ptr4 | 2;
                }
            }
            else
            {
                *ptr4 = *ptr4 | 1;
                FUN_80017698((int)*(short*)(ptr4 + 0x80), 1);
            }
            FUN_80286878();
            return;
        }
        if ((ptr[1] != 0) && ((bval = *ptr4, (bval & 4) == 0 || ((*ptr & 0x20) != 0))))
        {
            bval2 = *ptr;
            if ((bval2 & 0x10) == 0)
            {
                if (bval3 == '\x01')
                {
                    if ((bval2 & 1) != 0)
                    {
                        if ((bval & 1) != 0)
                        {
                            bval2 = bval2 & 4;
                        joined_r0x80199a04:
                            if (bval2 == 0) goto switchD_80199a5c_caseD_0;
                        }
                        goto code_r0x80199a48;
                    }
                }
                else if ((bval3 == -1) && ((bval2 & 2) != 0))
                {
                    if ((bval & 2) != 0)
                    {
                        bval2 = bval2 & 8;
                        goto joined_r0x80199a04;
                    }
                    goto code_r0x80199a48;
                }
            }
            else if ((bval2 & 1) == 0)
            {
                if (((bval2 & 2) == 0) || (bval3 < '\x01')) goto code_r0x80199a48;
            }
            else if (-1 < bval3)
            {
            code_r0x80199a48:
                switch (ptr[1])
                {
                case 1:
                    bval = ptr[2];
                    if (bval == 9)
                    {
                        val = FUN_80017a98();
                        if (val != 0)
                        {
                            fa = (double)FUN_80294bd4((double)lbl_803E4D70, val, 10);
                        }
                    }
                    else if (bval < 9)
                    {
                        if ((7 < bval) && (val = FUN_80017a98(), val != 0))
                        {
                            fa = (double)FUN_80294bd4((double)lbl_803E4D70, val, 1);
                        }
                    }
                    else if (bval == 0xb)
                    {
                        val = FUN_80017a98();
                        if (val != 0)
                        {
                            fa = (double)FUN_80294bd4((double)lbl_803E4D94, val, 1);
                        }
                    }
                    else if ((bval < 0xb) && (val = FUN_80017a98(), val != 0))
                    {
                        fa = (double)FUN_80294bd4((double)lbl_803E4D70, val, 0xb);
                    }
                    break;
                case 4:
                    if (bval3 < '\0')
                    {
                        fa = (double)FUN_80006810((int)ptr2, *(short*)(ptr + 2));
                    }
                    else
                    {
                        fa = (double)FUN_80006824((uint)ptr2, *(ushort*)(ptr + 2));
                    }
                    break;
                case 5:
                    fa = (double)*(float*)(ptr4 + 4);
                    break;
                case 6:
                    fa = (double)(**(code**)(*DAT_803dd6d0 + 0x24))(ptr[2], ptr[3], 0);
                    break;
                case 8:
                    switch (ptr[2])
                    {
                    case 0:
                        if (1 < ptr[3])
                        {
                            ptr[3] = 1;
                        }
                        fa = (double)FUN_8005d17c((uint)ptr[3]);
                        break;
                    case 1:
                        if (1 < ptr[3])
                        {
                            ptr[3] = 1;
                        }
                        fa = (double)FUN_8005d114((uint)ptr[3]);
                        break;
                    case 2:
                        if (1 < ptr[3])
                        {
                            ptr[3] = 1;
                        }
                        fa = (double)FUN_8005d0ac((uint)ptr[3]);
                        break;
                    case 3:
                        if (1 < ptr[3])
                        {
                            ptr[3] = 1;
                        }
                        fa = (double)(**(code**)(*DAT_803dd6e4 + 0x1c))(ptr[3]);
                        break;
                    case 4:
                        fa = (double)(**(code**)(*DAT_803dd704 + 0xc))(ptr[3]);
                        break;
                    case 5:
                        fa = (double)FUN_8006f498((uint)ptr[3]);
                        break;
                    case 6:
                        if (ptr[3] == 0)
                        {
                            fa = (double)FUN_80080f28(7, '\0');
                        }
                        else
                        {
                            fa = (double)FUN_80080f28(7, '\x01');
                        }
                        break;
                    case 7:
                        if (ptr[3] == 0)
                        {
                            fa = (double)FUN_8005cff0(0);
                        }
                        else
                        {
                            fa = (double)FUN_8005cff0(1);
                        }
                        break;
                    case 8:
                        if (ptr[3] == 0)
                        {
                            fa = (double)FUN_80053b3c();
                        }
                        else
                        {
                            fa = (double)FUN_80053b70();
                        }
                        break;
                    case 9:
                        uval4 = FUN_80080f40();
                        tmp[2] = (int)ptr[3];
                        tmp[1] = 0x43300000;
                        fa = (double)FUN_80080f3c((double)(float)((double)CONCAT44(0x43300000, tmp[2]) -
                                                          DOUBLE_803e4d88), uval4 ^ 1);
                        break;
                    case 10:
                        tmp[2] = (int)ptr[3];
                        tmp[1] = 0x43300000;
                        fa = (double)FUN_80080f3c((double)(float)((double)CONCAT44(0x43300000, tmp[2]) -
                                                          DOUBLE_803e4d88), 0);
                        break;
                    case 0xb:
                        tmp[2] = (int)ptr[3];
                        tmp[1] = 0x43300000;
                        fa = (double)FUN_80080f3c((double)(float)((double)CONCAT44(0x43300000, tmp[2]) -
                                                          DOUBLE_803e4d88), 1);
                    }
                    break;
                case 10:
                    FUN_80006728(fa, arg2, arg3, arg4, arg5, arg6, arg7, arg8, ptr2, val3,
                                 (uint) * (ushort*)(ptr + 2), arg12, arg13, arg14, arg15, arg16);
                    fa = (double)FUN_800723a0();
                    break;
                case 0xb:
                    bval = ptr[2];
                    if (bval == 2)
                    {
                        (*gObjectTriggerInterface)->setFlag(ptr[3], 0);
                    }
                    else if (bval < 2)
                    {
                        if (bval == 0)
                        {
                        LAB_80199dec:
                            val = ObjGroup_FindNearestObject(0xf, ptr2, (float*)0x0);
                            fa = tmpF1b;
                            if (val != 0)
                            {
                                (*gObjectTriggerInterface)->runSequence(ptr[3], (void*)val, -1);
                                fa = tmpF1b;
                            }
                        }
                        else
                        {
                            (*gObjectTriggerInterface)->setFlag(ptr[3], 1);
                        }
                    }
                    else if (bval < 4) goto LAB_80199dec;
                    break;
                case 0xc:
                    uval8 = *(ushort*)(ptr + 2);
                    val = FUN_80017b00(&tmp2, tmp);
                    for (; tmp2 < tmp[0]; tmp2 = tmp2 + 1)
                    {
                        val2 = *(int*)(val + tmp2 * 4);
                        ptr5 = *(short**)(val2 + 0x4c);
                        if (ptr5 == (short*)0x0) goto LAB_80199ef0;
                        sval = *ptr5;
                        if (sval == 0x54)
                        {
                        LAB_80199ed4:
                            if ((int)ptr5[0x1c] == (uint)uval8)
                            {
                                fa = (double)objInterpretSeq_v11_unused(
                                    fa, arg2, arg3, arg4, arg5, arg6, arg7
                                    , arg8, val2, val3, arg11, arg12, arg13,
                                    arg14, arg15, arg16);
                            }
                        }
                        else if (sval < 0x54)
                        {
                            if ((sval < 0x51) && (0x4a < sval)) goto LAB_80199ed4;
                        }
                        else if (sval == 0x230) goto LAB_80199ed4;
                    LAB_80199ef0:
                        ;
                    }
                    break;
                case 0xd:
                    arg14 = 0;
                    arg13 = arg12;
                    getLActions(fa, arg2, arg3, arg4, arg5, arg6, arg7, arg8, ptr2, val3,
                                (uint) * (ushort*)(ptr + 2), arg11, arg12, 0, arg15, arg16);
                    break;
                case 0x10:
                    val = FUN_80017a98();
                    fa = (double)FUN_80017a78(val, (uint)ptr[2]);
                    break;
                case 0x11:
                    fa = (double)FUN_80017698(0x4e3, (uint) * (ushort*)(ptr + 2));
                    break;
                case 0x12:
                    bval = ptr[2];
                    uval6 = (uint)bval << 8 & 0x3f00 | (uint)ptr[3];
                    uval5 = FUN_80017690(uval6);
                    uval4 = ((uint)bval << 8) >> 0xe;
                    if (uval4 == 0)
                    {
                        uval5 = 0;
                    }
                    else if (uval4 == 1)
                    {
                        uval5 = 0xffffffff;
                    }
                    else if (uval4 == 2)
                    {
                        uval5 = ~uval5;
                    }
                    fa = (double)FUN_80017698(uval6, uval5);
                    break;
                case 0x13:
                    fa = (double)(**(code**)(*DAT_803dd72c + 0x50))
                        ((int)*(char*)(ptr2 + 0x56), *(undefined2*)(ptr + 2), 1);
                    break;
                case 0x14:
                    fa = (double)(**(code**)(*DAT_803dd72c + 0x50))
                        ((int)*(char*)(ptr2 + 0x56), *(undefined2*)(ptr + 2), 0);
                    break;
                case 0x15:
                    ptr3 = (int*)FUN_80017af0(*(ushort*)(ptr + 2) + 2);
                    if (ptr3 != (int*)0x0)
                    {
                        for (; *ptr3 != -1; ptr3 = ptr3 + 1)
                        {
                            val = FUN_8005337c(*ptr3);
                            if (val == 0)
                            {
                                arg13 = 0;
                                arg14 = 0;
                                arg15 = 0;
                                arg16 = 0;
                                fa = (double)FUN_80017648();
                            }
                        }
                    }
                    break;
                case 0x16:
                    ptr3 = (int*)FUN_80017af0(*(ushort*)(ptr + 2) + 2);
                    if (ptr3 != (int*)0x0)
                    {
                        for (; *ptr3 != -1; ptr3 = ptr3 + 1)
                        {
                            val = FUN_8005337c(*ptr3);
                            if (val != 0)
                            {
                                fa = (double)FUN_80053754();
                            }
                        }
                    }
                    break;
                case 0x18:
                    fa = (double)(**(code**)(*DAT_803dd72c + 0x44))
                        ((int)*(char*)(ptr2 + 0x56), *(undefined2*)(ptr + 2));
                    break;
                case 0x1a:
                    fa = (double)(**(code**)(*DAT_803dd72c + 0x50))(ptr[3], ptr[2], 1);
                    break;
                case 0x1b:
                    fa = (double)(**(code**)(*DAT_803dd72c + 0x50))(ptr[3], ptr[2], 0);
                    break;
                case 0x1c:
                    bval = ptr[2];
                    if (bval == 2)
                    {
                        uval4 = countLeadingZeros((uint)ptr[3]);
                        fa = (double)FUN_80017698(0x3af, uval4 >> 5);
                    }
                    else if (bval < 2)
                    {
                        if (bval == 0)
                        {
                            uval4 = countLeadingZeros((uint)ptr[3]);
                            fa = (double)FUN_80017698(0x3ab, uval4 >> 5);
                        }
                        else
                        {
                            uval4 = countLeadingZeros((uint)ptr[3]);
                            fa = (double)FUN_80017698(0x3ac, uval4 >> 5);
                        }
                    }
                    else if (bval < 4)
                    {
                        bval = ptr[3];
                        if (bval == 1)
                        {
                            uval = FUN_80017698(0x3b0, 0);
                            uval2 = FUN_80017a98();
                            uval3 = FUN_80017a98();
                            uval = FUN_80006728(uval, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                                                  uval3, uval2, 0x134, 0, arg13, arg14, arg15, arg16);
                            uval2 = FUN_80017a98();
                            uval3 = FUN_80017a98();
                            uval = FUN_80006728(uval, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                                                  uval3, uval2, 0x135, 0, arg13, arg14, arg15, arg16);
                            uval2 = FUN_80017a98();
                            uval3 = FUN_80017a98();
                            uval = FUN_80006728(uval, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                                                  uval3, uval2, 0x142, 0, arg13, arg14, arg15, arg16);
                            fa = (double)FUN_80080f10(uval, arg2, arg3, arg4, arg5, arg6, arg7,
                                                          arg8);
                        }
                        else if (bval == 0)
                        {
                            uval = FUN_80017698(0x3b0, 1);
                            uval2 = FUN_80017a98();
                            uval3 = FUN_80017a98();
                            uval = FUN_80006728(uval, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                                                  uval3, uval2, 0x134, 0, arg13, arg14, arg15, arg16);
                            uval2 = FUN_80017a98();
                            uval3 = FUN_80017a98();
                            uval = FUN_80006728(uval, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                                                  uval3, uval2, 0x135, 0, arg13, arg14, arg15, arg16);
                            uval2 = FUN_80017a98();
                            uval3 = FUN_80017a98();
                            fa = (double)FUN_80006728(uval, arg2, arg3, arg4, arg5, arg6, arg7,
                                                          arg8, uval3, uval2, 0x142, 0, arg13, arg14,
                                                          arg15
                                                          , arg16);
                        }
                        else if (bval < 3)
                        {
                            uval = FUN_80017698(0x3b0, 1);
                            uval2 = FUN_80017a98();
                            uval3 = FUN_80017a98();
                            uval = FUN_80006728(uval, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                                                  uval3, uval2, 0x136, 0, arg13, arg14, arg15, arg16);
                            uval2 = FUN_80017a98();
                            uval3 = FUN_80017a98();
                            uval = FUN_80006728(uval, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                                                  uval3, uval2, 0x137, 0, arg13, arg14, arg15, arg16);
                            uval2 = FUN_80017a98();
                            uval3 = FUN_80017a98();
                            fa = (double)FUN_80006728(uval, arg2, arg3, arg4, arg5, arg6, arg7,
                                                          arg8, uval3, uval2, 0x143, 0, arg13, arg14,
                                                          arg15
                                                          , arg16);
                        }
                    }
                    break;
                case 0x1d:
                    if (ptr[2] == 0)
                    {
                        FUN_80017698(0x966, 1);
                        FUN_80017698(0x967, 1);
                        fa = (double)FUN_80017698(0x968, 1);
                    }
                    else
                    {
                        FUN_80017698(0x966, 0);
                        FUN_80017698(0x967, 0);
                        fa = (double)FUN_80017698(0x968, 0);
                    }
                    break;
                case 0x1e:
                    fa = (double)(**(code**)(*DAT_803dd72c + 0x44))(ptr[3], ptr[2]);
                    break;
                case 0x1f:
                    ptr5 = (short*)FUN_80017a98();
                    sval = *ptr2 - *ptr5;
                    if (0x8000 < sval)
                    {
                        sval = sval + 1;
                    }
                    if (sval < -0x8000)
                    {
                        sval = sval + -1;
                    }
                    val = (int)sval;
                    if (val < 0)
                    {
                        val = -val;
                    }
                    if (val < 0x4001)
                    {
                        val = FUN_80056600();
                        arg13 = *DAT_803dd72c;
                        fa = (double)(**(code**)(arg13 + 0x1c))
                            (ptr2 + 6, (int)*ptr2, ptr[3], val);
                    }
                    else
                    {
                        val = FUN_80056600();
                        arg13 = *DAT_803dd72c;
                        fa = (double)(**(code**)(arg13 + 0x1c))
                        (ptr2 + 6, (int)(short)(*ptr2 + -0x8000), ptr[3], val
                        );
                    }
                    break;
                case 0x20:
                    if (ptr[2] == 0)
                    {
                        fa = (double)FUN_80056a20();
                    }
                    else
                    {
                        fa = (double)FUN_800569f4();
                    }
                    break;
                case 0x21:
                    bval = ptr[2];
                    uval4 = (uint)bval << 8 & 0x1f00 | (uint)ptr[3];
                    uval6 = FUN_80017690(uval4);
                    fa = (double)FUN_80017698(uval4, uval6 ^ 1 << (((uint)bval << 8) >> 0xd));
                    break;
                case 0x22:
                    uval7 = *(undefined2*)(ptr + 2);
                    bval = (**(code**)(*DAT_803dd72c + 0x4c))((int)*(char*)(ptr2 + 0x56), uval7);
                    fa = (double)(**(code**)(*DAT_803dd72c + 0x50))
                        ((int)*(char*)(ptr2 + 0x56), uval7, bval ^ 1);
                    break;
                case 0x23:
                    bval = ptr[2];
                    if (bval == 2)
                    {
                        fa = (double)(**(code**)(*DAT_803dd72c + 0x28))();
                    }
                    else if (bval < 2)
                    {
                        if (bval == 0)
                        {
                            val = FUN_80056600();
                            arg13 = *DAT_803dd72c;
                            fa = (double)(**(code**)(arg13 + 0x24))(ptr2 + 6, (int)*ptr2, val, 0);
                        }
                        else
                        {
                            fa = (double)(**(code**)(*DAT_803dd72c + 0x2c))();
                        }
                    }
                    else if (bval < 4)
                    {
                        val = FUN_80056600();
                        arg13 = *DAT_803dd72c;
                        fa = (double)(**(code**)(arg13 + 0x24))(ptr2 + 6, (int)*ptr2, val, 1);
                    }
                    break;
                case 0x26:
                    val = FUN_80017a90();
                    if (val != 0)
                    {
                        bval = ptr[2];
                        if (bval == 2)
                        {
                            val2 = ObjGroup_FindNearestObject(0x32, val, (float*)0x0);
                            fa = tmpF1d;
                            if (val2 == 0)
                            {
                                val2 = ObjGroup_FindNearestObject(0x31, val, (float*)0x0);
                                fa = tmpF1e;
                            }
                            if (val2 != 0)
                            {
                                fa = (double)(**(code**)(**(int**)(val + 0x68) + 0x38))(val);
                            }
                        }
                        else if (bval < 2)
                        {
                            if (bval == 0)
                            {
                                fa = (double)(**(code**)(**(int**)(val + 0x68) + 0x3c))();
                            }
                            else
                            {
                                val = FUN_80017a90();
                                fa = (double)FUN_80017ac8(fa, arg2, arg3, arg4, arg5, arg6,
                                                              arg7
                                                              , arg8, val);
                            }
                        }
                        else if (bval == 4)
                        {
                            fa = (double)FUN_80017698(0xd00, 1);
                        }
                        else if (bval < 4)
                        {
                            fa = (double)FUN_80017698(0xd00, 0);
                        }
                    }
                    break;
                case 0x27:
                    FUN_80041c10(fa, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                                 (uint) * (ushort*)(ptr + 2));
                    FUN_800178bc();
                    fa = (double)FUN_800723a0();
                    break;
                case 0x28:
                    FUN_80043030(fa, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
                    fa = (double)FUN_800723a0();
                    break;
                case 0x2a:
                    FUN_80042bec((uint)ptr[2], (uint)ptr[3]);
                    fa = (double)FUN_800723a0();
                    break;
                case 0x2b:
                    FUN_80042b9c((uint)ptr[2], (uint)ptr[3], 0);
                    fa = (double)FUN_800723a0();
                    break;
                case 0x2c:
                    arg2 = (double)lbl_803E4D98;
                    tmp[2] = *(ushort*)(ptr + 2) ^ 0x80000000;
                    tmp[1] = 0x43300000;
                    **(float**)(val3 + 0xb8) =
                        (float)(arg2 *
                            (double)(float)((double)CONCAT44(0x43300000, tmp[2]) - DOUBLE_803e4d68));
                    fa = fb;
                    break;
                case 0x2d:
                    val = FUN_80017a98();
                    if (val == 0)
                    {
                        val = FUN_8020a6fc();
                        if (val != 0)
                        {
                            fa = (double)FUN_80125b7c(fa, arg2, arg3, arg4, arg5, arg6, arg7,
                                                          arg8, (uint) * (ushort*)(ptr + 2));
                        }
                    }
                    else
                    {
                        arg13 = *DAT_803dd6e8;
                        fa = (double)(**(code**)(arg13 + 0x38))
                            (*(undefined2*)(ptr + 2), 0x14, 0x8c, 1);
                    }
                    break;
                case 0x2e:
                    fa = (double)FUN_80040da0();
                    break;
                case 0x2f:
                    val = ObjGroup_FindNearestObject(0x4c, ptr2, (float*)0x0);
                    fa = tmpF1c;
                    if (val != 0)
                    {
                        fa = (double)FUN_8020a908(val, (uint)ptr[3] * 0x3c);
                    }
                }
            }
        }
    switchD_80199a5c_caseD_0:
        bval4 = bval4 + 1;
        ptr = ptr + 4;
    }
    while (true);
}


/*
 * --INFO--
 *
 * Function: FUN_8019ae30
 * EN v1.0 Address: 0x8019AE30
 * EN v1.0 Size: 2172b
 * EN v1.1 Address: 0x8019A92C
 * EN v1.1 Size: 1268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019ae30(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  undefined4 param_9, undefined4 param_10, float* param_11, undefined4 param_12,
                  int param_13, undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    short sVar1;
    bool bVar2;
    bool bVar3;
    int iVar4;
    int iVar5;
    int iVar6;
    uint uVar7;
    byte* pbVar8;
    int unaff_r28;
    int iVar9;
    short* psVar10;
    byte* pbVar11;
    undefined8 extraout_f1;
    undefined8 extraout_f1_00;
    undefined8 extraout_f1_01;
    undefined8 uVar12;
    float local_28[10];

    iVar4 = FUN_8028683c();
    pbVar11 = *(byte**)(iVar4 + 0xb8);
    psVar10 = *(short**)(iVar4 + 0x4c);
    local_28[0] = lbl_803E4D9C;
    if ((psVar10[0x1c] < 1) || (*psVar10 == 0xf4))
    {
        uVar12 = extraout_f1;
        iVar5 = FUN_80017a98();
        if (iVar5 == 0)
        {
            iVar5 = FUN_8020a6fc();
        }
        else
        {
            iVar6 = FUN_80294dbc(iVar5);
            if (iVar6 != 0)
            {
                iVar5 = iVar6;
            }
        }
        iVar6 = FUN_80017a90();
        if ((iVar5 != 0) || (iVar6 != 0))
        {
            if ((*pbVar11 & 4) == 0)
            {
                bVar3 = true;
                uVar7 = (uint) * (byte*)((int)psVar10 + 0x43);
                if (uVar7 < 3)
                {
                    if (uVar7 == 1)
                    {
                        if (iVar6 == 0)
                        {
                            bVar3 = false;
                        }
                    }
                    else if (uVar7 == 0)
                    {
                        iVar6 = iVar5;
                        if (iVar5 == 0)
                        {
                            bVar3 = false;
                        }
                    }
                    else
                    {
                        iVar6 = unaff_r28;
                        if (uVar7 < 3)
                        {
                            iVar6 = (**(code**)(*DAT_803dd6d0 + 0xc))();
                            uVar12 = extraout_f1_01;
                        }
                    }
                }
                else
                {
                    param_11 = local_28;
                    iVar6 = ObjGroup_FindNearestObject(uVar7 - 1, iVar4, param_11);
                    uVar12 = extraout_f1_00;
                    if (iVar6 == 0)
                    {
                        bVar3 = false;
                    }
                }
                if (bVar3)
                {
                    if ((*pbVar11 & 0x40) == 0)
                    {
                        *(undefined4*)(pbVar11 + 0x1c) = *(undefined4*)(pbVar11 + 0x28);
                        *(undefined4*)(pbVar11 + 0x20) = *(undefined4*)(pbVar11 + 0x2c);
                        *(undefined4*)(pbVar11 + 0x24) = *(undefined4*)(pbVar11 + 0x30);
                    }
                    else
                    {
                        if (*(byte*)((int)psVar10 + 0x43) == 2)
                        {
                            *(undefined4*)(pbVar11 + 0x1c) = *(undefined4*)(iVar6 + 0x18);
                            *(undefined4*)(pbVar11 + 0x20) = *(undefined4*)(iVar6 + 0x1c);
                            *(undefined4*)(pbVar11 + 0x24) = *(undefined4*)(iVar6 + 0x20);
                        }
                        else if (*(byte*)((int)psVar10 + 0x43) < 2)
                        {
                            *(undefined4*)(pbVar11 + 0x1c) = *(undefined4*)(iVar6 + 0x8c);
                            *(undefined4*)(pbVar11 + 0x20) = *(undefined4*)(iVar6 + 0x90);
                            *(undefined4*)(pbVar11 + 0x24) = *(undefined4*)(iVar6 + 0x94);
                        }
                        else
                        {
                            *(undefined4*)(pbVar11 + 0x1c) = *(undefined4*)(iVar6 + 0x80);
                            *(undefined4*)(pbVar11 + 0x20) = *(undefined4*)(iVar6 + 0x84);
                            *(undefined4*)(pbVar11 + 0x24) = *(undefined4*)(iVar6 + 0x88);
                        }
                        *pbVar11 = *pbVar11 & 0xbf;
                    }
                    if (*(byte*)((int)psVar10 + 0x43) < 3)
                    {
                        *(undefined4*)(pbVar11 + 0x28) = *(undefined4*)(iVar6 + 0x18);
                        *(undefined4*)(pbVar11 + 0x2c) = *(undefined4*)(iVar6 + 0x1c);
                        *(undefined4*)(pbVar11 + 0x30) = *(undefined4*)(iVar6 + 0x20);
                    }
                    else
                    {
                        *(undefined4*)(pbVar11 + 0x28) = *(undefined4*)(iVar6 + 0xc);
                        *(undefined4*)(pbVar11 + 0x2c) = *(undefined4*)(iVar6 + 0x10);
                        *(undefined4*)(pbVar11 + 0x30) = *(undefined4*)(iVar6 + 0x14);
                    }
                }
                sVar1 = *psVar10;
                if (sVar1 == 0x50)
                {
                    uVar12 = objInterpretSeq_v11_unused(uVar12, param_2, param_3, param_4, param_5, param_6, param_7,
                                                        param_8, iVar4
                                                        , iVar5, 1, 0, param_13, param_14, param_15, param_16);
                    iVar5 = FUN_8001769c();
                    if (iVar5 != 0)
                    {
                        FUN_80017ac8(uVar12, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar4);
                    }
                }
                else if (sVar1 < 0x50)
                {
                    if (sVar1 == 0x4d)
                    {
                        if (bVar3)
                        {
                            iVar9 = *(int*)(iVar4 + 0xb8);
                            iVar5 = objFn_80198fa4(iVar4, (float*)(iVar9 + 0x28));
                            iVar9 = objFn_80198fa4(iVar4, (float*)(iVar9 + 0x1c));
                            if (iVar5 == 0)
                            {
                                if (iVar9 == 0)
                                {
                                    objInterpretSeq_v11_unused(uVar12, param_2, param_3, param_4, param_5, param_6,
                                                               param_7, param_8, iVar4,
                                                               iVar6, 0xfffffffe, 0, param_13, param_14, param_15,
                                                               param_16);
                                }
                                else
                                {
                                    objInterpretSeq_v11_unused(uVar12, param_2, param_3, param_4, param_5, param_6,
                                                               param_7, param_8, iVar4,
                                                               iVar6, 0xffffffff, 0, param_13, param_14, param_15,
                                                               param_16);
                                }
                            }
                            else if (iVar9 == 0)
                            {
                                objInterpretSeq_v11_unused(uVar12, param_2, param_3, param_4, param_5, param_6, param_7,
                                                           param_8, iVar4,
                                                           iVar6, 1, 0, param_13, param_14, param_15, param_16);
                            }
                            else
                            {
                                objInterpretSeq_v11_unused(uVar12, param_2, param_3, param_4, param_5, param_6, param_7,
                                                           param_8, iVar4,
                                                           iVar6, 2, 0, param_13, param_14, param_15, param_16);
                            }
                        }
                    }
                    else if (sVar1 < 0x4d)
                    {
                        if (sVar1 == 0x4b)
                        {
                            if (bVar3)
                            {
                                FUN_80199744(iVar4, iVar6, param_11, param_12, param_13, param_14, param_15, param_16);
                            }
                        }
                        else if (0x4a < sVar1)
                        {
                            bVar2 = true;
                            if (((int)*(short*)(pbVar11 + 0x82) != 0xffffffff) &&
                                (uVar7 = FUN_80017690((int)*(short*)(pbVar11 + 0x82)), uVar7 == 0))
                            {
                                bVar2 = false;
                            }
                            if ((bVar2) && (bVar3))
                            {
                                FUN_801991bc();
                            }
                        }
                    }
                    else if ((sVar1 < 0x4f) &&
                        (*(uint*)(pbVar11 + 8) = *(int*)(pbVar11 + 8) + (uint)DAT_803dc070,
                            (uint)(ushort)
                            psVar10[0x23] <= *(uint*)(pbVar11 + 8)
                    )
                    )
                    {
                        objInterpretSeq_v11_unused(uVar12, param_2, param_3, param_4, param_5, param_6, param_7,
                                                   param_8, iVar4, 0, 1, 0,
                                                   param_13, param_14, param_15, param_16);
                    }
                }
                else if (sVar1 == 0xf4)
                {
                    if (bVar3)
                    {
                        FUN_80198e08();
                    }
                }
                else if (sVar1 < 0xf4)
                {
                    if (sVar1 == 0x54)
                    {
                        bVar3 = true;
                        iVar6 = 0;
                        pbVar8 = pbVar11;
                        while ((iVar6 < 4 && (bVar3)))
                        {
                            if (((int)*(short*)(pbVar8 + 0x82) != 0xffffffff) &&
                                (uVar7 = FUN_80017690((int)*(short*)(pbVar8 + 0x82)), uVar7 == 0))
                            {
                                bVar3 = false;
                            }
                            pbVar8 = pbVar8 + 2;
                            iVar6 = iVar6 + 1;
                        }
                        if ((bVar3) && (-1 < (char)pbVar11[0x8a]))
                        {
                            pbVar11[0x8a] = pbVar11[0x8a] & 0x7f | 0x80;
                            objInterpretSeq_v11_unused(uVar12, param_2, param_3, param_4, param_5, param_6, param_7,
                                                       param_8, iVar4,
                                                       iVar5, 1, 0, param_13, param_14, param_15, param_16);
                        }
                        if (!bVar3)
                        {
                            pbVar11[0x8a] = pbVar11[0x8a] & 0x7f;
                        }
                    }
                }
                else if ((sVar1 == 0x230) && (bVar3))
                {
                    FUN_8019959c(iVar4, iVar6, param_11, param_12, param_13, param_14, param_15, param_16);
                }
            }
            else
            {
                objInterpretSeq_v11_unused(uVar12, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar4,
                                           iVar5, 1, 0,
                                           param_13, param_14, param_15, param_16);
                *pbVar11 = *pbVar11 & 0xfb;
                *pbVar11 = *pbVar11 | 1;
            }
        }
    }
    FUN_80286888();
    return;
}


/* Trivial 4b 0-arg blr leaves. */
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

extern void Sfx_StopFromObject(void* obj, int sfxId);
extern void objSetSlot(void* obj, int slot);
extern int GameBit_Get(int eventId);
extern f32 lbl_803E40F8;

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

void cloudprisoncontrol_free(void)
{
}

void cloudprisoncontrol_hitDetect(void)
{
}

void cloudprisoncontrol_release(void)
{
}

/* 8b "li r3, N; blr" returners. */
int Trigger_getExtraSize(void) { return 0xac; }
int Trigger_getObjectTypeId(void) { return 0x0; }
int cloudprisoncontrol_getExtraSize(void) { return 0x0; }
int cloudprisoncontrol_getObjectTypeId(void) { return 0x0; }

/* Pattern wrappers. */
extern s8 lbl_803DBE08;
void cloudprisoncontrol_initialise(void) { lbl_803DBE08 = 0x1; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4108;
extern void objRenderFn_8003b8f4(f32);

void cloudprisoncontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4108);
}

/* call(x, N) wrappers. */
void cloudprisoncontrol_init(int x) { ObjMsg_AllocQueue(x, 0xa); }

int cfguardian_setScale(int* obj)
{
    return (*(u8*)(*(int*)&((GameObject*)obj)->extra + 0xa9b) & 0x2) == 0;
}

extern void Sfx_PlayFromObject(int obj, int sfxId);

void fn_8019AE3C(int p1, int p2, s16* p3)
{
    u8 v;
    int i;

    v = 0;
    for (i = 0; i < *(s8*)(p2 + 0x1b); i++)
    {
        switch (*(s8*)(p2 + i + 0x13))
        {
        case 0:
            if (p3 != NULL)
            {
                Sfx_PlayFromObject(p1, (u16)p3[0]);
            }
            break;
        case 7:
            if (p3 != NULL)
            {
                Sfx_PlayFromObject(p1, (u16)p3[1]);
            }
            break;
        case 1:
            v = 1;
            break;
        case 2:
            v = 2;
            break;
        case 3:
            v = 3;
            break;
        case 4:
            v = 4;
            break;
        case 9:
            Sfx_PlayFromObject(p1, 0xe1);
            break;
        }
    }
    if (v != 0 && p3 != NULL)
    {
        Sfx_PlayFromObject(p1, (u16)p3[2]);
    }
}

extern s8 lbl_803DDB08;
extern s8 lbl_803DDB09;
extern int lbl_803DDB0C;
extern int lbl_803AC7D8[];
extern int lbl_803AC878[];

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

extern int findRomCurvePointNearObject(int obj, int sel, int p3, int p4);
extern int fn_8019B1D8(int obj, void* buf, f32 t, int p4);
extern int Curve_AdvanceAlongPath(int p1);
extern int hitDetectFn_800658a4(f32 x, f32 y, f32 z, int obj, f32* out, int p6);
extern s16 getAngle(f32 a, f32 b);
extern f32 lbl_803E4110;
extern f32 lbl_803E4120;

typedef struct
{
    s16 angle;
    s16 pad[5];
    f32 x;
    f32 y;
    f32 z;
} RomCurveTarget;

int fn_8019AF64(int obj, int p2, f32 t, int p3, int p4)
{
    int ret;
    int moved;
    u8 sel;
    int pt;
    s16 v;
    int cmd[2];
    RomCurveTarget tgt;
    f32 ground;

    moved = 1;
    ret = 0;
    ground = lbl_803E4110;
    if (((GameObject*)obj)->unkF4 == -1)
    {
        return 1;
    }
    if (((GameObject*)obj)->unkF4 == 0)
    {
        sel = p3;
        pt = findRomCurvePointNearObject(obj, sel, 0, 2);
        tgt.x = *(f32*)(pt + 8);
        tgt.y = *(f32*)(pt + 0xc);
        tgt.z = *(f32*)(pt + 0x10);
        tgt.angle = *(s8*)(pt + 0x2c) << 8;
        if (fn_8019B1D8(obj, &tgt.angle, t, p4) != 0)
        {
            cmd[0] = 0x19;
            cmd[1] = 0x15;
            (*gRomCurveInterface)->initCurve((void*)p2, (void*)obj, lbl_803E4120, cmd, sel);
            ((GameObject*)obj)->unkF4 = 1;
            moved = 1;
        }
    }
    else
    {
        ret = 0;
        if (Curve_AdvanceAlongPath(p2) != 0 || *(int*)(p2 + 0x10) != 0)
        {
            ret = (*gRomCurveInterface)->goNextPoint((void*)p2);
        }
        ((GameObject*)obj)->anim.localPosX = *(f32*)(p2 + 0x68);
        ((GameObject*)obj)->anim.localPosY = *(f32*)(p2 + 0x6c);
        ((GameObject*)obj)->anim.localPosZ = *(f32*)(p2 + 0x70);
        if (ret != 0)
        {
            ((GameObject*)obj)->unkF4 = -1;
        }
        if (hitDetectFn_800658a4(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                 ((GameObject*)obj)->anim.localPosZ, obj, &ground, 0) == 0)
        {
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - ground;
        }
    }
    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)(obj, t, (float*)p4);
    if (moved != 0)
    {
        v = (s16)(getAngle(((GameObject*)obj)->anim.localPosX - ((GameObject*)obj)->anim.previousLocalPosX,
                           ((GameObject*)obj)->anim.localPosZ - ((GameObject*)obj)->anim.previousLocalPosZ) + 0x8000);
        v = v - (u16) * (s16*)obj;
        if (v > 0x8000)
        {
            v -= 0xffff;
        }
        if (v < -0x8000)
        {
            v += 0xffff;
        }
        *(s16*)obj = *(s16*)obj + (v >> 3);
    }
    if (((GameObject*)obj)->anim.currentMove != 0x1a)
    {
        ObjAnim_SetCurrentMove(obj, 0x1a, lbl_803E4110, 0);
    }
    return ret;
}

extern CloudActionInterface** gCloudActionInterface;
extern int* gPlayerShadowInterface;
extern MapEventInterface** gMapEventInterface;
extern void OSReport(const char* fmt, ...);
extern int Obj_GetPlayerObject(void);
extern void fn_80295918(f32 a, int obj, int b);
extern void setDrawCloudsAndLights(int v);
extern void gameFlagFn_8005ce6c(int v);
extern void setDrawLights(int v);
extern void fn_8006FC00(int v);
extern void skyFn_80088c94(int a, int b);
extern void gameFlagFn_8005cd24(int v);
extern void timeOfDayFn_80055000(void);
extern void timeOfDayFn_80055038(void);
extern int getSkyStructField24C(void);
extern void skyFn_80088e54(f32 a, int b);
extern void getEnvfxAct(int obj, int target, int effectId, int flags);
extern int ObjGroup_FindNearestObject(int group, int obj, int p3);
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
    u32 bit;
    u32 v;
    u32 op;
    u32 sel;
    s16 d;
    int ang;
    int first;
    int count;
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
            else if ((b & 2) == 0 || (s8)p3 < 1)
            {
            run:
                switch (p[1])
                {
                case 1:
                    switch (((ObjInterpretSeqPlacement*)p)->unk2)
                    {
                    case 0:
                        break;
                    case 8:
                        t = Obj_GetPlayerObject();
                        if ((void*)t != NULL)
                        {
                            fn_80295918(lbl_803E40D8, t, 1);
                        }
                        break;
                    case 9:
                        t = Obj_GetPlayerObject();
                        if ((void*)t != NULL)
                        {
                            fn_80295918(lbl_803E40D8, t, 10);
                        }
                        break;
                    case 10:
                        t = Obj_GetPlayerObject();
                        if ((void*)t != NULL)
                        {
                            fn_80295918(lbl_803E40D8, t, 0xb);
                        }
                        break;
                    case 0xb:
                        t = Obj_GetPlayerObject();
                        if ((void*)t != NULL)
                        {
                            fn_80295918(lbl_803E40FC, t, 1);
                        }
                        break;
                    }
                    break;
                case 4:
                    if ((s8)p3 < 0)
                    {
                        Sfx_StopFromObject((void*)obj, (u16)((p[2] << 8) | p[3]));
                    }
                    else
                    {
                        Sfx_PlayFromObject(obj, (u16)((p[2] << 8) | p[3]));
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
                        skyFn_80088e54((f32)(u32)p[3], getSkyStructField24C() ^ 1);
                        break;
                    case 10:
                        skyFn_80088e54((f32)(u32)p[3], 0);
                        break;
                    case 0xb:
                        skyFn_80088e54((f32)(u32)p[3], 1);
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
                    getEnvfxAct(obj, p2, (s16)((p[2] << 8) | p[3]), p4);
                    OSReport(desc + 0x68, (int)((GameObject*)obj)->anim.classId, (s16)((p[2] << 8) | p[3]), p4);
                    break;
                case 0xd:
                    getLActions(obj, p2, (s16)((p[2] << 8) | p[3]), p3, p4, 0);
                    break;
                case 0xb:
                    switch (((ObjInterpretSeqPlacement*)p)->unk2)
                    {
                    case 0:
                    case 3:
                        t = ObjGroup_FindNearestObject(0xf, obj, 0);
                        if (t != 0)
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
                        match:
                            if (*(s16*)((char*)tbl + 0x38) == id)
                            {
                                objInterpretSeq(t2, p2, p3, p4);
                            }
                        }
                        else if (d < 0x54)
                        {
                            if (d < 0x51 && d >= 0x4b)
                            {
                                goto match;
                            }
                        }
                        else if (d == 0x230)
                        {
                            goto match;
                        }
                    }
                    break;
                case 0x10:
                    Obj_SetActiveModelIndex(Obj_GetPlayerObject(), p[2]);
                    break;
                case 0x12:
                    op = (p[2] << 8) | p[3];
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
                    bit = ((u32)p[2] << 8 & 0x1f00) | p[3];
                    GameBit_Set(bit, GameBit_Get(bit) ^ (1 << (((u32)p[2] << 8) >> 13)));
                    break;
                case 0x13:
                    (*gMapEventInterface)->setAnimEvent(
                        (int)((GameObject*)obj)->anim.mapEventSlot, (u16)((p[2] << 8) | p[3]), 1);
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
                    if (t != 0)
                    {
                        timer_addDuration(t, (u32)p[3] * 0x3c);
                    }
                    break;
                case 0x14:
                    (*gMapEventInterface)->setAnimEvent(
                        (int)((GameObject*)obj)->anim.mapEventSlot, (u16)((p[2] << 8) | p[3]), 0);
                    break;
                case 0x22:
                    id = (u16)((p[2] << 8) | p[3]);
                    c = (*gMapEventInterface)->getAnimEvent((int)((GameObject*)obj)->anim.mapEventSlot, id);
                    (*gMapEventInterface)->setAnimEvent((int)((GameObject*)obj)->anim.mapEventSlot, id, c ^ 1);
                    break;
                case 0x15:
                    tbl = (int*)getTablesBinEntry((u16)((p[2] << 8) | p[3]) + 2);
                    if (tbl != NULL)
                    {
                        for (; *tbl != -1; tbl++)
                        {
                            if (getLoadedTexture(*tbl) == 0)
                            {
                                crash(0x32, 3, 0, *tbl, 0, 0, 0, 0);
                            }
                        }
                    }
                    break;
                case 0x16:
                    tbl = (int*)getTablesBinEntry((u16)((p[2] << 8) | p[3]) + 2);
                    if (tbl != NULL)
                    {
                        for (; *tbl != -1; tbl++)
                        {
                            if (getLoadedTexture(*tbl) != 0)
                            {
                                textureFree(*tbl);
                            }
                        }
                    }
                    break;
                case 0x18:
                    (*gMapEventInterface)->setMode(
                        (int)((GameObject*)obj)->anim.mapEventSlot, (u16)((p[2] << 8) | p[3]));
                    break;
                case 0x1a:
                    (*gMapEventInterface)->setAnimEvent(p[3], p[2], 1);
                    break;
                case 0x1b:
                    (*gMapEventInterface)->setAnimEvent(p[3], p[2], 0);
                    break;
                case 0x1e:
                    (*gMapEventInterface)->setMode(p[3], p[2]);
                    break;
                case 0x11:
                    GameBit_Set(0x4e3, (p[2] << 8) | p[3]);
                    break;
                case 0x1f:
                    t = Obj_GetPlayerObject();
                    d = *(s16*)obj - (u16) * (s16*)t;
                    if (d > 0x8000)
                    {
                        d -= 0xffff;
                    }
                    if (d < -0x8000)
                    {
                        d += 0xffff;
                    }
                    ang = d;
                    if (ang < 0)
                    {
                        ang = -ang;
                    }
                    if (ang > 0x4000)
                    {
                        (*gMapEventInterface)->triggerEvent(obj + 0xc,
                                                            (int)(s16)(*(s16*)obj + 0x8000),
                                                            p[3], getCurMapLayer());
                    }
                    else
                    {
                        (*gMapEventInterface)->triggerEvent(obj + 0xc, (int)*(s16*)obj,
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
                        (*(code*)((u8*)*gMapEventInterface + 0x24))(obj + 0xc, (int)*(s16*)obj, getCurMapLayer(), 0);
                        break;
                    case 1:
                        (*(code*)((u8*)*gMapEventInterface + 0x2c))();
                        break;
                    case 2:
                        (*gMapEventInterface)->finishCurrentEvent(*gMapEventInterface);
                        break;
                    case 3:
                        (*(code*)((u8*)*gMapEventInterface + 0x24))(obj + 0xc, (int)*(s16*)obj, getCurMapLayer(), 1);
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
                            if (t2 == 0)
                            {
                                t2 = ObjGroup_FindNearestObject(0x31, t, 0);
                            }
                            if (t2 != 0)
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
                    c = p[2];
                    if (c == 2)
                    {
                        GameBit_Set(0x3af, p[3] == 0);
                    }
                    else if (c < 2)
                    {
                        if (c == 0)
                        {
                            GameBit_Set(0x3ab, p[3] == 0);
                        }
                        else
                        {
                            GameBit_Set(0x3ac, p[3] == 0);
                        }
                    }
                    else if (c < 4)
                    {
                        c = p[3];
                        if (c == 1)
                        {
                            GameBit_Set(0x3b0, 0);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x134, 0);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x135, 0);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x142, 0);
                            envFxFn_800887cc();
                        }
                        else if (c == 0)
                        {
                            GameBit_Set(0x3b0, 1);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x134, 0);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x135, 0);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x142, 0);
                        }
                        else if (c < 3)
                        {
                            GameBit_Set(0x3b0, 1);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x136, 0);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x137, 0);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x143, 0);
                        }
                    }
                    break;
                case 0x1d:
                    if (p[2] == 0)
                    {
                        GameBit_Set(0x966, 1);
                        GameBit_Set(0x967, 1);
                        GameBit_Set(0x968, 1);
                    }
                    else
                    {
                        GameBit_Set(0x966, 0);
                        GameBit_Set(0x967, 0);
                        GameBit_Set(0x968, 0);
                    }
                    break;
                case 0x2c:
                    **(f32**)(p2 + 0xb8) = lbl_803E4100 * (f32)(int)(u16)((p[2] << 8) | p[3]);
                    break;
                case 0x2d:
                    t = Obj_GetPlayerObject();
                    if (t == 0)
                    {
                        if (getArwing() != 0)
                        {
                            gameTextFn_80125ba4((u16)((p[2] << 8) | p[3]));
                        }
                    }
                    else
                    {
                        (*gGameUIInterface)->showNpcDialogue((u16)((p[2] << 8) | p[3]), 0x14, 0x8c, 1);
                    }
                    break;
                }
            }
        }
    next:
        i++;
        p += 4;
    }
    if ((s8)p3 < 1)
    {
        if ((s8)p3 < 0)
        {
            *state |= 2;
        }
    }
    else
    {
        *state |= 1;
        GameBit_Set(((TriggerState*)state)->unk80, 1);
    }
}

extern int fn_802972A8(void);
extern int return1_800202BC(void);
extern int fn_80198B68(int obj, int p2);
extern void objSeqFn_801992ec(int obj, int target);
extern void fn_80198DE8(int obj, int target);
extern void fn_80198A00(int obj, int target);
extern void objSeqMoveFn_80199188(int obj, int target);
extern f32 lbl_803E4104;
extern u8 framesThisStep;

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
                    if (((TriggerState*)state)->unk82 != -1 && GameBit_Get(((TriggerState*)state)->unk82) == 0)
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
                    if ((u32)((TriggerPlacement*)def)->unk46 <= ((TriggerState*)state)->unk8)
                    {
                        objInterpretSeq(obj, 0, 1, 0);
                    }
                    break;
                case 0x4d:
                    if (ok)
                    {
                        r1 = fn_80198B68(obj, *(int*)&((GameObject*)obj)->extra + 0x28);
                        r2 = fn_80198B68(obj, *(int*)&((GameObject*)obj)->extra + 0x1c);
                        if (r1 == 0)
                        {
                            if (r2 == 0)
                            {
                                objInterpretSeq(obj, target, -2, 0);
                            }
                            else
                            {
                                objInterpretSeq(obj, target, -1, 0);
                            }
                        }
                        else if (r2 == 0)
                        {
                            objInterpretSeq(obj, target, 1, 0);
                        }
                        else
                        {
                            objInterpretSeq(obj, target, 2, 0);
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
                        if (*(s16*)(p8 + 0x82) != -1 && GameBit_Get(*(s16*)(p8 + 0x82)) == 0)
                        {
                            ok = 0;
                        }
                        p8 += 2;
                        i++;
                    }
                    if (ok && (s8)state[0x8a] >= 0)
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
