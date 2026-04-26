#include "ghidra_import.h"
#include "main/dll/DR/sandwormBoss.h"

extern undefined4 FUN_800066e0();
extern undefined4 FUN_80006728();
extern undefined4 FUN_800067c0();
extern bool FUN_800067f0();
extern undefined8 FUN_8000680c();
extern undefined4 FUN_80006814();
extern undefined8 FUN_80006824();
extern undefined8 FUN_800069bc();
extern int FUN_80006a10();
extern undefined4 FUN_80006ba8();
extern undefined4 FUN_80017520();
extern int FUN_80017524();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175ec();
extern undefined4 FUN_80017688();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017710();
extern undefined4 FUN_8001771c();
extern int FUN_80017730();
extern undefined4 FUN_80017748();
extern uint FUN_80017760();
extern undefined4 FUN_80017a40();
extern undefined4 FUN_80017a78();
extern undefined4 FUN_80017a88();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ad0();
extern int FUN_80017b00();
extern undefined4 ObjAnim_SetPrimaryEventStepFrames();
extern undefined4 FUN_8002f6ac();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 FUN_80035fe8();
extern undefined4 FUN_800360d4();
extern undefined4 FUN_800360f0();
extern int FUN_800368c4();
extern int FUN_800369d0();
extern int FUN_80037008();
extern void* FUN_80037134();
extern undefined4 FUN_80037180();
extern undefined4 FUN_8003735c();
extern int FUN_80037584();
extern undefined8 FUN_80037844();
extern undefined4 FUN_80037bd4();
extern undefined4 FUN_80037ce0();
extern undefined4 FUN_80037d74();
extern undefined4 FUN_8003817c();
extern int FUN_800384ec();
extern undefined4 FUN_800388b4();
extern int FUN_80038a34();
extern undefined4 FUN_80038f38();
extern undefined4 FUN_800392ec();
extern undefined4 FUN_80039468();
extern undefined4 FUN_8003964c();
extern undefined4 FUN_8003add8();
extern undefined4 FUN_8003b1a4();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b818();
extern int FUN_80057690();
extern int FUN_800620e8();
extern int FUN_800632e8();
extern undefined4 FUN_8006f7a0();
extern int FUN_8007f56c();
extern undefined4 FUN_8007f5ec();
extern uint FUN_8007f66c();
extern uint FUN_8007f6c8();
extern undefined4 FUN_8007f6e4();
extern undefined4 FUN_8007f718();
extern int FUN_8007f764();
extern int FUN_8007f924();
extern undefined4 FUN_80080f8c();
extern int FUN_800810ac();
extern undefined4 FUN_800810e8();
extern undefined4 FUN_80081110();
extern undefined4 FUN_8008111c();
extern undefined4 FUN_800e8630();
extern undefined4 FUN_801141e8();
extern undefined4 FUN_80114274();
extern undefined4 FUN_80114340();
extern int FUN_801145b0();
extern int FUN_801149b8();
extern undefined4 FUN_801149bc();
extern undefined4 FUN_80114b10();
extern undefined4 FUN_80115094();
extern undefined4 FUN_801150a4();
extern undefined4 FUN_801150ac();
extern undefined4 FUN_8014ccac();
extern int FUN_8020a468();
extern int FUN_8020a490();
extern undefined4 FUN_8020a494();
extern undefined4 FUN_8020a4a4();
extern undefined4 FUN_8020a4ac();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern double FUN_802480e8();
extern undefined4 FUN_80286830();
extern uint FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern byte FUN_80294c20();
extern double FUN_80294c6c();
extern undefined4 FUN_80294c74();
extern int FUN_80294d38();
extern undefined4 FUN_80294d40();
extern int FUN_80294d6c();
extern uint countLeadingZeros();

extern undefined4 DAT_802c2a40;
extern undefined4 DAT_802c2a44;
extern undefined4 DAT_802c2a48;
extern undefined4 DAT_802c2a4c;
extern undefined4 DAT_802c2a50;
extern undefined4 DAT_802c2a54;
extern undefined4 DAT_802c2a58;
extern undefined4 DAT_802c2a5c;
extern undefined4 DAT_802c2a60;
extern undefined4 DAT_802c2a64;
extern undefined4 DAT_8032349c;
extern undefined4 DAT_803235a4;
extern undefined4 DAT_80323698;
extern undefined4 DAT_803236b8;
extern undefined4 DAT_80323778;
extern undefined4 DAT_80323888;
extern undefined4 DAT_8032388c;
extern undefined4 DAT_80323890;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dca88;
extern undefined4 DAT_803dca90;
extern undefined4 DAT_803dca98;
extern undefined4 DAT_803dcab0;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd740;
extern undefined4 DAT_803de790;
extern f64 DOUBLE_803e4db0;
extern f64 DOUBLE_803e4df8;
extern f64 DOUBLE_803e4e58;
extern f64 DOUBLE_803e4ea0;
extern f64 DOUBLE_803e4eb8;
extern f64 DOUBLE_803e4f08;
extern f64 DOUBLE_803e4f10;
extern f64 DOUBLE_803e4f28;
extern f64 DOUBLE_803e4f40;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc078;
extern f32 FLOAT_803dcaa0;
extern f32 FLOAT_803dcaa4;
extern f32 FLOAT_803dcaac;
extern f32 FLOAT_803dcab4;
extern f32 FLOAT_803dcac0;
extern f32 FLOAT_803dcac4;
extern f32 FLOAT_803e4da8;
extern f32 FLOAT_803e4db8;
extern f32 FLOAT_803e4dbc;
extern f32 FLOAT_803e4dc0;
extern f32 FLOAT_803e4dc4;
extern f32 FLOAT_803e4dc8;
extern f32 FLOAT_803e4dcc;
extern f32 FLOAT_803e4dd0;
extern f32 FLOAT_803e4dd4;
extern f32 FLOAT_803e4dd8;
extern f32 FLOAT_803e4ddc;
extern f32 FLOAT_803e4de0;
extern f32 FLOAT_803e4de4;
extern f32 FLOAT_803e4de8;
extern f32 FLOAT_803e4dec;
extern f32 FLOAT_803e4df0;
extern f32 FLOAT_803e4df4;
extern f32 FLOAT_803e4e00;
extern f32 FLOAT_803e4e04;
extern f32 FLOAT_803e4e08;
extern f32 FLOAT_803e4e0c;
extern f32 FLOAT_803e4e10;
extern f32 FLOAT_803e4e14;
extern f32 FLOAT_803e4e18;
extern f32 FLOAT_803e4e1c;
extern f32 FLOAT_803e4e20;
extern f32 FLOAT_803e4e24;
extern f32 FLOAT_803e4e28;
extern f32 FLOAT_803e4e2c;
extern f32 FLOAT_803e4e30;
extern f32 FLOAT_803e4e34;
extern f32 FLOAT_803e4e38;
extern f32 FLOAT_803e4e3c;
extern f32 FLOAT_803e4e40;
extern f32 FLOAT_803e4e44;
extern f32 FLOAT_803e4e48;
extern f32 FLOAT_803e4e4c;
extern f32 FLOAT_803e4e50;
extern f32 FLOAT_803e4e54;
extern f32 FLOAT_803e4e60;
extern f32 FLOAT_803e4e64;
extern f32 FLOAT_803e4e70;
extern f32 FLOAT_803e4e74;
extern f32 FLOAT_803e4e78;
extern f32 FLOAT_803e4e7c;
extern f32 FLOAT_803e4e80;
extern f32 FLOAT_803e4e84;
extern f32 FLOAT_803e4e88;
extern f32 FLOAT_803e4e8c;
extern f32 FLOAT_803e4e90;
extern f32 FLOAT_803e4e94;
extern f32 FLOAT_803e4e98;
extern f32 FLOAT_803e4e9c;
extern f32 FLOAT_803e4eb0;
extern f32 FLOAT_803e4ec4;
extern f32 FLOAT_803e4ec8;
extern f32 FLOAT_803e4ecc;
extern f32 FLOAT_803e4ed0;
extern f32 FLOAT_803e4ed4;
extern f32 FLOAT_803e4ed8;
extern f32 FLOAT_803e4edc;
extern f32 FLOAT_803e4ee0;
extern f32 FLOAT_803e4ee4;
extern f32 FLOAT_803e4ee8;
extern f32 FLOAT_803e4eec;
extern f32 FLOAT_803e4ef0;
extern f32 FLOAT_803e4ef8;
extern f32 FLOAT_803e4efc;
extern f32 FLOAT_803e4f00;
extern f32 FLOAT_803e4f18;
extern f32 FLOAT_803e4f1c;
extern f32 FLOAT_803e4f24;
extern f32 FLOAT_803e4f30;
extern f32 FLOAT_803e4f38;
extern f32 FLOAT_803e4f3c;
extern f32 FLOAT_803e4f4c;
extern f32 FLOAT_803e4f58;
extern f32 FLOAT_803e4f5c;
extern f32 FLOAT_803e4f60;
extern f32 FLOAT_803e4f64;
extern f32 FLOAT_803e4f68;
extern f32 FLOAT_803e4f6c;
extern f32 FLOAT_803e4f70;
extern f32 FLOAT_803e4f74;

/*
 * --INFO--
 *
 * Function: FUN_8019b1d8
 * EN v1.0 Address: 0x8019B1D8
 * EN v1.0 Size: 260b
 * EN v1.1 Address: 0x8019B3B8
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019b1d8(undefined4 param_1,undefined4 param_2,ushort *param_3)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_80286840();
  uVar1 = (uint)((ulonglong)uVar4 >> 0x20);
  iVar2 = 0;
  for (iVar3 = 0; iVar3 < *(char *)((int)uVar4 + 0x1b); iVar3 = iVar3 + 1) {
    switch(*(undefined *)((int)uVar4 + iVar3 + 0x13)) {
    case 0:
      if (param_3 != (ushort *)0x0) {
        FUN_80006824(uVar1,*param_3);
      }
      break;
    case 1:
      iVar2 = 1;
      break;
    case 2:
      iVar2 = 2;
      break;
    case 3:
      iVar2 = 3;
      break;
    case 4:
      iVar2 = 4;
      break;
    case 7:
      if (param_3 != (ushort *)0x0) {
        FUN_80006824(uVar1,param_3[1]);
      }
      break;
    case 9:
      FUN_80006824(uVar1,0xe1);
    }
  }
  if ((iVar2 != 0) && (param_3 != (ushort *)0x0)) {
    FUN_80006824(uVar1,param_3[2]);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019b2dc
 * EN v1.0 Address: 0x8019B2DC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8019B4E0
 * EN v1.1 Size: 628b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019b2dc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,float *param_12,int param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8019b2e0
 * EN v1.0 Address: 0x8019B2E0
 * EN v1.0 Size: 680b
 * EN v1.1 Address: 0x8019B754
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8019b2e0(double param_1,short *param_2,short *param_3,float *param_4,undefined4 param_5,
            undefined4 param_6,undefined4 param_7,undefined4 param_8,undefined4 param_9)
{
  int iVar1;
  short sVar2;
  undefined4 uVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  float local_58;
  float local_54;
  float local_50 [2];
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  longlong local_38;
  
  if (param_3 == (short *)0x0) {
    uVar3 = 0;
  }
  else {
    local_50[0] = *(float *)(param_3 + 6) - *(float *)(param_2 + 6);
    dVar6 = (double)local_50[0];
    local_54 = *(float *)(param_3 + 8) - *(float *)(param_2 + 8);
    local_58 = *(float *)(param_3 + 10) - *(float *)(param_2 + 10);
    dVar4 = FUN_80293900((double)(local_58 * local_58 + (float)(dVar6 * dVar6) + local_54 * local_54
                                 ));
    if ((double)(float)((double)FLOAT_803e4dbc * param_1) <= dVar4) {
      FUN_8006f7a0(local_50,&local_54,&local_58);
      *(float *)(param_2 + 0x12) = FLOAT_803dc074 * (float)((double)local_50[0] * param_1);
      *(float *)(param_2 + 0x14) = FLOAT_803dc074 * (float)((double)local_54 * param_1);
      *(float *)(param_2 + 0x16) = FLOAT_803dc074 * (float)((double)local_58 * param_1);
      sVar2 = (*param_3 + -0x8000) - *param_2;
      if (0x8000 < sVar2) {
        sVar2 = sVar2 + 1;
      }
      if (sVar2 < -0x8000) {
        sVar2 = sVar2 + -1;
      }
      uStack_44 = (int)*param_2 ^ 0x80000000;
      local_48 = 0x43300000;
      uStack_3c = (int)sVar2 ^ 0x80000000;
      local_40 = 0x43300000;
      iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e4db0) +
                   (float)((double)((FLOAT_803e4dc0 +
                                    (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e4db0
                                           )) * (float)(param_1 * (double)FLOAT_803dc074)) / dVar4))
      ;
      local_38 = (longlong)iVar1;
      *param_2 = (short)iVar1;
      dVar4 = (double)*(float *)(param_2 + 0x14);
      dVar5 = (double)*(float *)(param_2 + 0x16);
      FUN_80017a88((double)*(float *)(param_2 + 0x12),dVar4,dVar5,(int)param_2);
      if (param_2[0x50] != 0x1a) {
        FUN_800305f8((double)FLOAT_803e4da8,dVar4,dVar5,dVar6,in_f5,in_f6,in_f7,in_f8,param_2,0x1a,0
                     ,param_5,param_6,param_7,param_8,param_9);
      }
      FUN_8002f6ac(param_1,(int)param_2,param_4);
      uVar3 = 0;
    }
    else {
      uVar3 = 1;
    }
  }
  return uVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_8019b588
 * EN v1.0 Address: 0x8019B588
 * EN v1.0 Size: 200b
 * EN v1.1 Address: 0x8019B974
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8019b588(int param_1,undefined4 param_2,undefined4 *param_3,int param_4)
{
  int iVar1;
  int iVar2;
  undefined4 local_18;
  undefined4 local_14;
  
  iVar2 = 0;
  if (param_4 == 1) {
    local_18 = 0;
    local_14 = 0;
  }
  else {
    local_18 = 0x19;
    local_14 = 0x15;
  }
  iVar1 = (**(code **)(*DAT_803dd71c + 0x14))
                    ((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                     (double)*(float *)(param_1 + 0x14),&local_18,2,param_2);
  if ((-1 < iVar1) && (iVar2 = (**(code **)(*DAT_803dd71c + 0x1c))(), param_3 != (undefined4 *)0x0))
  {
    *param_3 = *(undefined4 *)(iVar2 + 8);
    param_3[1] = *(undefined4 *)(iVar2 + 0xc);
    param_3[2] = *(undefined4 *)(iVar2 + 0x10);
  }
  return iVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_8019b650
 * EN v1.0 Address: 0x8019B650
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8019BA44
 * EN v1.1 Size: 3800b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8019b650(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,
            undefined4 param_10,undefined4 param_11,float *param_12,int param_13,undefined4 param_14
            ,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8019b658
 * EN v1.0 Address: 0x8019B658
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x8019C91C
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8019b658(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  undefined4 uVar1;
  int iVar2;
  float *pfVar3;
  undefined4 *puVar4;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  
  pfVar3 = *(float **)(param_9 + 0xb8);
  local_28 = DAT_802c2a58;
  local_24 = DAT_802c2a5c;
  local_20 = DAT_802c2a60;
  local_1c = DAT_802c2a64;
  if (*(short *)(param_9 + 0xb4) < 0) {
    FUN_800e8630(param_9);
    uVar1 = 0;
  }
  else {
    if (*(char *)(pfVar3 + 0x2a0) == '\x06') {
      puVar4 = &local_20;
    }
    else {
      puVar4 = &local_28;
    }
    iVar2 = FUN_8007f924(param_11);
    if ((iVar2 == 0x283) ||
       (iVar2 = FUN_801149b8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                             ,param_11,pfVar3,(short)*puVar4,(short)puVar4[1],param_14,param_15,
                             param_16), iVar2 == 0)) {
      if (*(char *)(param_11 + 0x80) == '\x02') {
        iVar2 = FUN_80017a98();
        FUN_80294d40(iVar2,10);
      }
      uVar1 = 0;
    }
    else {
      uVar1 = 1;
    }
  }
  return uVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_8019b7cc
 * EN v1.0 Address: 0x8019B7CC
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x8019CA28
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019b7cc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  int iVar1;
  int iVar2;
  
  iVar1 = *(int *)(param_9 + 0xb8);
  if (param_10 == 0) {
    iVar2 = 0;
    do {
      if (*(int *)(iVar1 + 0x68c) != 0) {
        param_1 = FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                               *(int *)(iVar1 + 0x68c));
      }
      iVar1 = iVar1 + 4;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 6);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019b8ac
 * EN v1.0 Address: 0x8019B8AC
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x8019CA88
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019b8ac(short *param_1)
{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  if (in_r8 != '\0') {
    FUN_8003b818((int)param_1);
    FUN_801149bc(param_1,iVar1,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019b8fc
 * EN v1.0 Address: 0x8019B8FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8019CAFC
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019b8fc(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,
                 undefined4 param_10,undefined4 param_11,float *param_12,int param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  FUN_8019b650(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,
               param_11,param_12,param_13,param_14,param_15,param_16);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019b900
 * EN v1.0 Address: 0x8019B900
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8019CB1C
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019b900(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8019b904
 * EN v1.0 Address: 0x8019B904
 * EN v1.0 Size: 1708b
 * EN v1.1 Address: 0x8019CD00
 * EN v1.1 Size: 1412b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019b904(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,uint param_12,int param_13,
                 uint param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  byte bVar2;
  float fVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  double dVar10;
  double extraout_f1;
  double dVar11;
  double dVar12;
  double dVar13;
  undefined8 uVar14;
  
  uVar14 = FUN_80286838();
  uVar5 = (uint)((ulonglong)uVar14 >> 0x20);
  iVar7 = (int)uVar14;
  iVar8 = param_13;
  uVar9 = param_14;
  dVar10 = param_2;
  dVar12 = extraout_f1;
  iVar6 = FUN_80017a98();
  dVar13 = (double)(*(float *)(iVar7 + 0x10) - *(float *)(uVar5 + 0x10));
  if (((double)FLOAT_803e4e04 <= dVar13) &&
     ((dVar11 = (double)FUN_80017710((float *)(iVar7 + 0x18),(float *)(uVar5 + 0x18)),
      dVar11 <= (double)(float)((double)FLOAT_803e4e08 + dVar10) ||
      ((*(byte *)(param_11 + 0x10) & 0xe0) != 0)))) {
    bVar2 = *(byte *)(param_11 + 0x10);
    if (((bVar2 & 0x80) == 0) || (param_12 == 0)) {
      if (dVar10 <= dVar11) {
        if (param_13 == 0) {
          FUN_80037bd4(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar7,0x10,
                       uVar5,param_12,iVar8,uVar9,param_15,param_16);
          *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0xe;
          *(float *)(param_11 + 0xc) = FLOAT_803e4e04;
          *(undefined *)(param_11 + 0x11) = 0;
        }
        else {
          FUN_80294c74((double)FLOAT_803e4e04,iVar7);
        }
      }
      else {
        if (((bVar2 & 0xe0) == 0) || ((bVar2 & 0x80) != 0)) {
          if ((param_12 != 0) &&
             ((uVar4 = countLeadingZeros((uint)bVar2), (uVar4 >> 5 & 0x80) != 0 &&
              (dVar13 < (double)FLOAT_803e4e0c)))) {
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 0x80;
            goto LAB_8019d244;
          }
          if ((bVar2 & 2) != 0) {
            dVar11 = (double)(float)(dVar13 / dVar12);
            if (dVar11 <= (double)FLOAT_803e4e10) {
              *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 8;
              *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0xfb;
            }
            else {
              *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 4;
              *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0xf7;
            }
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0xfd;
          }
          if (param_12 == 0) {
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 0x40;
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0xdf;
            FUN_80037bd4(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar7,0xf,
                         uVar5,((int)(*(byte *)(param_11 + 0x10) & 0xe0) >> 4) << 8 | param_14,iVar8
                         ,uVar9,param_15,param_16);
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0x7f;
          }
          else {
            if ((double)FLOAT_803e4e14 < dVar13) {
              FUN_80037bd4(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar7,0xf,
                           uVar5,((int)(*(byte *)(param_11 + 0x10) & 0xe0) >> 4) << 8 | param_14,
                           iVar8,uVar9,param_15,param_16);
            }
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 0x20;
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0xbf;
          }
        }
        dVar10 = (double)FLOAT_803e4e18;
        bVar2 = *(byte *)(param_11 + 0x10);
        if ((((bVar2 & 0xe) != 0) && ((bVar2 & 8) != 0)) && (param_12 == 0)) {
          dVar12 = (double)(float)(dVar12 * (double)FLOAT_803e4e1c);
        }
        fVar1 = (float)(dVar12 * (double)FLOAT_803e4e1c);
        if (FLOAT_803e4e08 < fVar1) {
          if (dVar13 < (double)FLOAT_803e4e20) {
            dVar13 = (double)FLOAT_803e4e20;
          }
          if (param_12 == 0) {
            fVar3 = *(float *)(param_11 + 0xc);
            dVar12 = -(double)((fVar1 / FLOAT_803e4e24) * fVar3 * fVar3 * fVar3 - fVar1);
            if (dVar13 <= dVar12) {
              fVar1 = (float)(dVar12 - dVar13);
              if (fVar1 <= FLOAT_803e4e0c) {
                dVar11 = (double)(fVar1 / FLOAT_803e4e0c);
              }
              else {
                dVar11 = (double)FLOAT_803e4e28;
              }
            }
            else {
              dVar11 = (double)FLOAT_803e4e04;
            }
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 1;
            dVar12 = (double)*(float *)(param_11 + 0xc);
            if ((((dVar12 < (double)FLOAT_803e4e2c) && ((*(byte *)(param_11 + 0x11) & 1) != 0)) ||
                (((double)FLOAT_803e4e30 < dVar12 && ((*(byte *)(param_11 + 0x11) & 1) == 0)))) &&
               (((*(byte *)(param_11 + 0x10) & 8) != 0 &&
                (bVar2 = *(byte *)(param_11 + 0x11), *(byte *)(param_11 + 0x11) = bVar2 + 1,
                2 < bVar2)))) {
              *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0xf7;
              *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 4;
            }
          }
          else {
            dVar12 = (double)*(float *)(param_11 + 0xc);
            fVar3 = FLOAT_803e4e34;
            if ((bVar2 & 0xe) != 0) {
              fVar3 = FLOAT_803e4e00;
            }
            if ((double)fVar3 < dVar12) {
              *(undefined *)(param_11 + 0x11) = 1;
            }
            dVar10 = (double)(float)(dVar10 * (double)FLOAT_803e4e38);
            if (*(char *)(param_11 + 0x11) == '\0') {
              fVar3 = FLOAT_803e4e40;
              if ((*(byte *)(param_11 + 0x10) & 0xe) != 0) {
                fVar3 = FLOAT_803e4e3c;
              }
              fVar1 = FLOAT_803e4e28 - (float)(dVar13 / (double)(fVar3 * fVar1));
              dVar12 = (double)FLOAT_803e4e28;
              if (fVar1 < FLOAT_803e4e04) {
                fVar1 = FLOAT_803e4e04;
              }
              dVar11 = (double)(fVar1 * fVar1);
            }
            else {
              dVar11 = (double)FLOAT_803e4e44;
            }
          }
          *(float *)(param_11 + 8) = (float)(dVar10 * dVar11 - (double)FLOAT_803e4e48);
          *(float *)(param_11 + 0xc) = *(float *)(param_11 + 0xc) + *(float *)(param_11 + 8);
          if (FLOAT_803e4e4c < *(float *)(param_11 + 0xc)) {
            *(float *)(param_11 + 0xc) = FLOAT_803e4e4c;
          }
          dVar10 = (double)FLOAT_803e4e04;
          if (dVar10 == (double)*(float *)(param_11 + 0xc)) {
            *(float *)(param_11 + 0xc) = FLOAT_803e4e50;
          }
          if ((dVar13 < (double)FLOAT_803e4e0c) && (param_12 != 0)) {
            *(float *)(param_11 + 0xc) = FLOAT_803e4e04;
            *(undefined *)(param_11 + 0x11) = 0;
            FUN_80037bd4(dVar10,dVar12,dVar11,param_4,param_5,param_6,param_7,param_8,iVar7,0x10,
                         uVar5,param_12,iVar8,uVar9,param_15,param_16);
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 0x80;
            if (param_13 != 0) {
              *(float *)(iVar6 + 0x28) = FLOAT_803e4e04;
            }
          }
          if (param_13 == 0) {
            *(float *)(iVar7 + 0x10) =
                 *(float *)(param_11 + 0xc) * FLOAT_803dc074 + *(float *)(iVar7 + 0x10);
            *(float *)(iVar7 + 0x28) = *(float *)(param_11 + 0xc) * FLOAT_803dc074;
          }
          else {
            FUN_80294c74((double)*(float *)(param_11 + 0xc),iVar7);
          }
        }
      }
    }
  }
LAB_8019d244:
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019bfb0
 * EN v1.0 Address: 0x8019BFB0
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x8019D284
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019bfb0(int param_1)
{
  int iVar1;
  double dVar2;
  
  iVar1 = FUN_80017a98();
  if ((iVar1 == 0) || (dVar2 = FUN_80294c6c(iVar1), (double)FLOAT_803e4e04 == dVar2)) {
    FUN_800067c0((int *)0xbd,0);
  }
  FUN_80037180(param_1,0x49);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019c00c
 * EN v1.0 Address: 0x8019C00C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8019D2E0
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019c00c(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019c034
 * EN v1.0 Address: 0x8019C034
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8019D314
 * EN v1.1 Size: 1300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019c034(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8019c038
 * EN v1.0 Address: 0x8019C038
 * EN v1.0 Size: 736b
 * EN v1.1 Address: 0x8019D828
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019c038(int param_1,int param_2)
{
  float fVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int *piVar5;
  
  piVar5 = *(int **)(param_1 + 0xb8);
  piVar5[1] = (int)*(short *)(param_2 + 0x1e);
  iVar3 = FUN_8007f56c((int *)&DAT_80323698,4,piVar5[1]);
  *piVar5 = iVar3;
  iVar3 = FUN_8007f56c((int *)&DAT_803236b8,3,piVar5[1]);
  piVar5[3] = iVar3;
  if (piVar5[3] == 0) {
    piVar5[3] = -1;
  }
  if (*piVar5 == 0) {
    *piVar5 = 100;
  }
  piVar5[2] = (int)*(short *)(param_2 + 0x1c);
  piVar5[5] = 0;
  if ((int)*(char *)(param_2 + 0x19) == 0) {
    piVar5[0x5c] = (int)FLOAT_803e4e64;
  }
  else {
    piVar5[0x5c] = (int)(FLOAT_803e4e60 *
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)*(char *)(param_2 + 0x19) ^ 0x80000000) -
                               DOUBLE_803e4e58));
  }
  *(float *)(param_1 + 8) =
       (*(float *)(*(int *)(param_1 + 0x50) + 4) * (float)piVar5[0x5c]) / FLOAT_803e4e64;
  uVar4 = FUN_80017690(0x57);
  if ((uVar4 != 0) || (9 < *piVar5)) {
    piVar5[5] = 0x3c;
  }
  *(byte *)(piVar5 + 0x5d) = *(byte *)(piVar5 + 0x5d) & 0xbf | 0x40;
  if (piVar5[3] != 0xffffffff) {
    uVar4 = FUN_80017690(piVar5[3]);
    if (uVar4 == 0) {
      *(byte *)(piVar5 + 0x5d) = *(byte *)(piVar5 + 0x5d) & 0xbf;
      *(undefined *)(param_1 + 0x36) = 0;
    }
    else {
      piVar5[5] = 0x3c;
    }
  }
  fVar2 = FLOAT_803e4e04;
  fVar1 = FLOAT_803e4e00;
  iVar3 = 2;
  do {
    *(undefined *)(piVar5 + 10) = 0;
    *(byte *)(piVar5 + 10) = *(byte *)(piVar5 + 10) & 0xe;
    piVar5[7] = (int)fVar1;
    piVar5[9] = (int)fVar2;
    piVar5[8] = (int)fVar2;
    piVar5[6] = 0;
    *(undefined *)((int)piVar5 + 0x29) = 0;
    *(undefined *)(piVar5 + 0x10) = 0;
    *(byte *)(piVar5 + 0x10) = *(byte *)(piVar5 + 0x10) & 0xe;
    piVar5[0xd] = (int)fVar1;
    piVar5[0xf] = (int)fVar2;
    piVar5[0xe] = (int)fVar2;
    piVar5[0xc] = 0;
    *(undefined *)((int)piVar5 + 0x41) = 0;
    *(undefined *)(piVar5 + 0x16) = 0;
    *(byte *)(piVar5 + 0x16) = *(byte *)(piVar5 + 0x16) & 0xe;
    piVar5[0x13] = (int)fVar1;
    piVar5[0x15] = (int)fVar2;
    piVar5[0x14] = (int)fVar2;
    piVar5[0x12] = 0;
    *(undefined *)((int)piVar5 + 0x59) = 0;
    *(undefined *)(piVar5 + 0x1c) = 0;
    *(byte *)(piVar5 + 0x1c) = *(byte *)(piVar5 + 0x1c) & 0xe;
    piVar5[0x19] = (int)fVar1;
    piVar5[0x1b] = (int)fVar2;
    piVar5[0x1a] = (int)fVar2;
    piVar5[0x18] = 0;
    *(undefined *)((int)piVar5 + 0x71) = 0;
    *(undefined *)(piVar5 + 0x22) = 0;
    *(byte *)(piVar5 + 0x22) = *(byte *)(piVar5 + 0x22) & 0xe;
    piVar5[0x1f] = (int)fVar1;
    piVar5[0x21] = (int)fVar2;
    piVar5[0x20] = (int)fVar2;
    piVar5[0x1e] = 0;
    *(undefined *)((int)piVar5 + 0x89) = 0;
    *(undefined *)(piVar5 + 0x28) = 0;
    *(byte *)(piVar5 + 0x28) = *(byte *)(piVar5 + 0x28) & 0xe;
    piVar5[0x25] = (int)fVar1;
    piVar5[0x27] = (int)fVar2;
    piVar5[0x26] = (int)fVar2;
    piVar5[0x24] = 0;
    *(undefined *)((int)piVar5 + 0xa1) = 0;
    *(undefined *)(piVar5 + 0x2e) = 0;
    *(byte *)(piVar5 + 0x2e) = *(byte *)(piVar5 + 0x2e) & 0xe;
    piVar5[0x2b] = (int)fVar1;
    piVar5[0x2d] = (int)fVar2;
    piVar5[0x2c] = (int)fVar2;
    piVar5[0x2a] = 0;
    *(undefined *)((int)piVar5 + 0xb9) = 0;
    piVar5 = piVar5 + 0x2a;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  FUN_8003735c(param_1,0x49);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019c318
 * EN v1.0 Address: 0x8019C318
 * EN v1.0 Size: 848b
 * EN v1.1 Address: 0x8019DAF4
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8019c318(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,undefined4 param_10,int param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  short *psVar3;
  uint local_28;
  uint local_24;
  uint local_20 [4];
  
  psVar3 = *(short **)(param_9 + 0xb8);
  local_28 = 0;
  while (iVar1 = FUN_80037584(param_9,&local_24,local_20,&local_28), iVar1 != 0) {
    if (local_24 == 0x110001) {
      if ((*psVar3 == 0x54) && (0xaf < *(short *)(param_11 + 0x58))) {
        FUN_80037bd4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_20[0],
                     0x110001,param_9,0,param_13,param_14,param_15,param_16);
      }
    }
    else if ((int)local_24 < 0x110001) {
      if (local_24 == 0xa0005) {
        param_1 = FUN_80017698((int)*psVar3,1);
      }
    }
    else if (local_24 == 0x110003) {
      if ((*psVar3 == 0x56) && (0xaf < *(short *)(param_11 + 0x58))) {
        FUN_80037bd4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_20[0],
                     0x110003,param_9,0,param_13,param_14,param_15,param_16);
      }
    }
    else if ((((int)local_24 < 0x110003) && (*psVar3 == 0x55)) &&
            (0xaf < *(short *)(param_11 + 0x58))) {
      FUN_80037bd4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_20[0],
                   0x110002,param_9,0,param_13,param_14,param_15,param_16);
    }
  }
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar1 = iVar1 + 1) {
    if (((*(char *)(param_11 + iVar1 + 0x81) == '\x01') && (uVar2 = FUN_80017690(0x54), uVar2 != 0))
       && ((uVar2 = FUN_80017690(0x55), uVar2 != 0 && (uVar2 = FUN_80017690(0x56), uVar2 != 0)))) {
      FUN_80017698(0x4e0,1);
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8019c668
 * EN v1.0 Address: 0x8019C668
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8019DCC4
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019c668(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019c690
 * EN v1.0 Address: 0x8019C690
 * EN v1.0 Size: 312b
 * EN v1.1 Address: 0x8019DCF8
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019c690(int param_1)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_80017690((int)*(short *)(iVar3 + 2));
  if (uVar1 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
  }
  if (*(int *)(param_1 + 0xf4) != 0) {
    (**(code **)(*DAT_803dd6d4 + 0x54))(param_1,0xfa);
    (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar3 + 4),param_1,3);
    *(undefined4 *)(param_1 + 0xf4) = 0;
  }
  if (((*(byte *)(param_1 + 0xaf) & 1) != 0) &&
     (iVar2 = (**(code **)(*DAT_803dd6e8 + 0x20))((int)*(short *)(iVar3 + 2)), iVar2 != 0)) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    FUN_80017698((int)*(short *)(iVar3 + 2),0);
    FUN_80017698(0x973,0);
    (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar3 + 4),param_1,0xffffffff);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019c7c8
 * EN v1.0 Address: 0x8019C7C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8019DE30
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019c7c8(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8019c7cc
 * EN v1.0 Address: 0x8019C7CC
 * EN v1.0 Size: 2464b
 * EN v1.1 Address: 0x8019DF6C
 * EN v1.1 Size: 2128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019c7cc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  short *psVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  float *pfVar6;
  bool bVar7;
  undefined4 in_r7;
  float *in_r8;
  int in_r9;
  undefined4 in_r10;
  int iVar8;
  float *pfVar9;
  int iVar10;
  short sVar11;
  float *pfVar12;
  float *pfVar13;
  undefined8 uVar14;
  uint local_58;
  uint local_54;
  uint local_50;
  float local_4c;
  float local_48;
  float local_44;
  undefined auStack_40 [4];
  short local_3c;
  short local_3a;
  float local_34;
  float local_30;
  float local_2c;
  undefined4 local_28;
  uint uStack_24;
  
  psVar2 = (short *)FUN_80286838();
  pfVar9 = *(float **)(psVar2 + 0x5c);
  local_58 = 0;
  FUN_80017a98();
  uVar14 = FUN_800069bc();
  while (iVar3 = FUN_80037584((int)psVar2,&local_54,&local_50,&local_58), iVar3 != 0) {
    if (local_54 == 0x110003) {
      pfVar9[2] = *(float *)(local_50 + 0xc);
      pfVar9[6] = FLOAT_803e4e70;
      pfVar9[10] = *(float *)(local_50 + 0x14);
      *(undefined2 *)(pfVar9 + 0xd) = 1;
    }
    else if ((int)local_54 < 0x110003) {
      if (local_54 == 0x110001) {
        *pfVar9 = *(float *)(local_50 + 0xc);
        pfVar9[4] = FLOAT_803e4e70;
        pfVar9[8] = *(float *)(local_50 + 0x14);
        *(undefined2 *)(pfVar9 + 0xc) = 1;
      }
      else if (0x110000 < (int)local_54) {
        pfVar9[1] = *(float *)(local_50 + 0xc);
        pfVar9[5] = FLOAT_803e4e70;
        pfVar9[9] = *(float *)(local_50 + 0x14);
        *(undefined2 *)((int)pfVar9 + 0x32) = 1;
      }
    }
    else if ((int)local_54 < 0x110005) {
      pfVar9[3] = *(float *)(local_50 + 0xc);
      pfVar9[7] = *(float *)(local_50 + 0x10);
      pfVar9[0xb] = *(float *)(local_50 + 0x14);
      *(undefined2 *)((int)pfVar9 + 0x36) = 1;
    }
  }
  if (*(short *)((int)pfVar9 + 0x36) == 0) {
    in_r7 = 0;
    uVar14 = FUN_80037844(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xdc,5,
                          (uint)psVar2,0x110004,0,in_r8,in_r9,in_r10);
  }
  uVar4 = FUN_80017690(0x54);
  if ((uVar4 != 0) && (*(short *)(pfVar9 + 0xc) == 0)) {
    in_r7 = 0;
    uVar14 = FUN_80037844(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xda,4,
                          (uint)psVar2,0x110001,0,in_r8,in_r9,in_r10);
  }
  uVar4 = FUN_80017690(0x55);
  if ((uVar4 != 0) && (*(short *)((int)pfVar9 + 0x32) == 0)) {
    in_r7 = 0;
    uVar14 = FUN_80037844(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xda,4,
                          (uint)psVar2,0x110002,0,in_r8,in_r9,in_r10);
  }
  uVar4 = FUN_80017690(0x56);
  if ((uVar4 != 0) && (*(short *)(pfVar9 + 0xd) == 0)) {
    in_r7 = 0;
    FUN_80037844(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xda,4,(uint)psVar2,
                 0x110003,0,in_r8,in_r9,in_r10);
  }
  *(undefined *)((int)pfVar9 + 0x53) = 0;
  *(undefined *)((int)pfVar9 + 0x6f) = 0;
  *(undefined *)((int)pfVar9 + 0x8b) = 0;
  *(undefined *)((int)pfVar9 + 0xa7) = 0;
  *(undefined *)((int)pfVar9 + 0xc3) = 0;
  *(undefined *)((int)pfVar9 + 0xdf) = 0;
  *(undefined *)((int)pfVar9 + 0xfb) = 0;
  *(undefined *)((int)pfVar9 + 0x117) = 0;
  *(undefined *)((int)pfVar9 + 0x133) = 0;
  *(undefined *)((int)pfVar9 + 0x14f) = 0;
  uVar4 = 0;
  iVar3 = 0;
  if (*(short *)((int)pfVar9 + 0x36) != 0) {
    uVar5 = FUN_80017690(0x57);
    if (uVar5 != 0) {
      if (*(short *)(pfVar9 + 0xc) != 0) {
        *(undefined2 *)(pfVar9 + 0xc) = 0x78;
      }
      if (*(short *)((int)pfVar9 + 0x32) != 0) {
        *(undefined2 *)((int)pfVar9 + 0x32) = 0x78;
      }
      if (*(short *)(pfVar9 + 0xd) != 0) {
        *(undefined2 *)(pfVar9 + 0xd) = 0x78;
      }
      *(undefined2 *)(pfVar9 + 0x54) = 0x5a;
    }
    iVar10 = 0;
    pfVar12 = pfVar9;
    pfVar13 = pfVar9;
    do {
      if ((iVar10 < 3) && (*(short *)(pfVar13 + 0xc) != 0)) {
        iVar8 = iVar3 + 1;
        pfVar6 = pfVar9 + iVar3 * 7 + 0xe;
        *(undefined *)((int)pfVar6 + 0x1b) = 1;
        *(undefined *)(pfVar6 + 6) = 0x7f;
        *(undefined *)((int)pfVar6 + 0x19) = 0x7f;
        *(undefined *)((int)pfVar6 + 0x1a) = 0xff;
        *pfVar6 = pfVar9[3];
        pfVar6[2] = FLOAT_803e4e74 + pfVar9[7];
        pfVar6[4] = pfVar9[0xb];
        local_4c = *pfVar12 - *pfVar6;
        local_48 = (FLOAT_803e4e78 + pfVar12[4]) - pfVar6[2];
        local_44 = pfVar12[8] - pfVar6[4];
        FUN_80247ef8(&local_4c,&local_4c);
        local_34 = *pfVar12 - pfVar9[3];
        local_30 = (FLOAT_803e4e78 + pfVar12[4]) - pfVar9[7];
        local_2c = pfVar12[8] - pfVar9[0xb];
        local_4c = -local_4c;
        local_48 = -local_48;
        local_44 = -local_44;
        sVar11 = (short)iVar10;
        local_3a = sVar11;
        (**(code **)(*DAT_803dd708 + 8))(psVar2,0x7f4,auStack_40,2,0xffffffff,&local_4c);
        local_4c = *pfVar12 - *(float *)(DAT_803de790 + 0xc);
        local_48 = FLOAT_803e4e7c;
        local_44 = pfVar12[8] - *(float *)(DAT_803de790 + 0x14);
        FUN_80247ef8(&local_4c,&local_4c);
        local_34 = FLOAT_803e4e80;
        local_30 = FLOAT_803e4e74;
        local_2c = FLOAT_803e4e80;
        local_3a = sVar11 + 3;
        in_r7 = 0xffffffff;
        in_r8 = &local_4c;
        in_r9 = *DAT_803dd708;
        (**(code **)(in_r9 + 8))(DAT_803de790,0x7f4,auStack_40,2);
        param_2 = (double)*pfVar12;
        local_34 = *pfVar12;
        local_30 = pfVar12[4];
        local_2c = pfVar12[8];
        iVar3 = iVar3 + 2;
        *(undefined *)((int)pfVar9 + iVar8 * 0x1c + 0x53) = 1;
        uVar4 = uVar4 + 1;
        local_3c = sVar11;
      }
      pfVar13 = (float *)((int)pfVar13 + 2);
      pfVar12 = pfVar12 + 1;
      iVar10 = iVar10 + 1;
    } while (iVar10 < 3);
    if (((int)*(short *)(pfVar9 + 0xc) +
         (int)*(short *)((int)pfVar9 + 0x32) + (int)*(short *)(pfVar9 + 0xd) < 300) &&
       (uVar5 = FUN_80017760(0,3), uVar5 == 0)) {
      in_r7 = 0xffffffff;
      in_r8 = (float *)0x0;
      in_r9 = *DAT_803dd708;
      (**(code **)(in_r9 + 8))(psVar2,0x81,0,0);
    }
    if (((*(short *)(pfVar9 + 0xc) != 0) || (*(short *)((int)pfVar9 + 0x32) != 0)) ||
       (*(short *)(pfVar9 + 0xd) != 0)) {
      if (100 < *(byte *)(pfVar9 + 0x57)) {
        *(undefined *)(pfVar9 + 0x57) = 0;
      }
      if (100 < *(byte *)((int)pfVar9 + 0x15d)) {
        *(undefined *)((int)pfVar9 + 0x15d) = 0;
      }
      if (100 < *(byte *)((int)pfVar9 + 0x15e)) {
        *(undefined *)((int)pfVar9 + 0x15e) = 0;
      }
      if (0x14 < *(byte *)((int)pfVar9 + 0x15f)) {
        *(undefined *)((int)pfVar9 + 0x15f) = 0;
      }
      *(byte *)(pfVar9 + 0x57) = *(char *)(pfVar9 + 0x57) + DAT_803dc070;
      *(byte *)((int)pfVar9 + 0x15d) = *(char *)((int)pfVar9 + 0x15d) + DAT_803dc070;
      *(byte *)((int)pfVar9 + 0x15e) = *(char *)((int)pfVar9 + 0x15e) + DAT_803dc070;
      *(byte *)((int)pfVar9 + 0x15f) = *(char *)((int)pfVar9 + 0x15f) + DAT_803dc070;
    }
    if (uVar4 == 3) {
      if (*(short *)(pfVar9 + 0x54) == 0) {
        uVar14 = FUN_80006824(0,0x7e);
        FUN_80006728(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x7f,0,in_r7
                     ,in_r8,in_r9,in_r10);
      }
      *(ushort *)(pfVar9 + 0x54) = *(short *)(pfVar9 + 0x54) + (ushort)DAT_803dc070;
    }
    if (0x3b < *(short *)(pfVar9 + 0x54)) {
      uStack_24 = (int)*(short *)(pfVar9 + 0x54) - 0x3cU ^ 0x80000000;
      local_28 = 0x43300000;
      fVar1 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e4ea0) / FLOAT_803e4e84;
      pfVar12 = pfVar9 + iVar3 * 7 + 0xe;
      *(undefined *)((int)pfVar12 + 0x1b) = 1;
      *(undefined *)(pfVar12 + 6) = 0;
      *(undefined *)((int)pfVar12 + 0x19) = 0;
      *(undefined *)((int)pfVar12 + 0x1a) = 0;
      *pfVar12 = *(float *)(psVar2 + 6);
      pfVar12[2] = FLOAT_803e4e88 + *(float *)(psVar2 + 8);
      pfVar12[4] = *(float *)(psVar2 + 10);
      pfVar12[1] = *pfVar12;
      pfVar12[3] = -(FLOAT_803e4e8c * fVar1 - pfVar12[2]);
      pfVar12[5] = pfVar12[4];
    }
    *psVar2 = *psVar2 + (ushort)DAT_803dc070 * (short)uVar4 * 0x7e;
  }
  if (uVar4 != 0) {
    bVar7 = FUN_800067f0((int)psVar2,0x40);
    if (bVar7) {
      uStack_24 = uVar4 ^ 0x80000000;
      local_28 = 0x43300000;
      fVar1 = FLOAT_803e4e94 +
              (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e4ea0) / FLOAT_803e4e98;
      pfVar9[0x55] = (fVar1 - pfVar9[0x55]) * FLOAT_803e4e9c + pfVar9[0x55];
      if (0x3b < *(short *)(pfVar9 + 0x54)) {
        pfVar9[0x55] = fVar1;
      }
      FUN_80006814((double)pfVar9[0x55],(int)psVar2,0x40,100);
    }
    else {
      FUN_80006824((uint)psVar2,0xd5);
      pfVar9[0x55] = FLOAT_803e4e90;
    }
  }
  iVar3 = 0;
  do {
    sVar11 = *(short *)(pfVar9 + 0xc);
    if ((sVar11 != 0) && (sVar11 < 0x80)) {
      *(ushort *)(pfVar9 + 0xc) = sVar11 + (ushort)DAT_803dc070;
      if ((sVar11 == 1) && (1 < *(short *)(pfVar9 + 0xc))) {
        FUN_80006824((uint)psVar2,0xd6);
      }
      if ((sVar11 < 0x1e) && (0x1d < *(short *)(pfVar9 + 0xc))) {
        FUN_80006824((uint)psVar2,0xd7);
      }
    }
    pfVar9 = (float *)((int)pfVar9 + 2);
    iVar3 = iVar3 + 1;
  } while (iVar3 < 3);
  *psVar2 = *psVar2 + (ushort)DAT_803dc070 * 0x2a;
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019d16c
 * EN v1.0 Address: 0x8019D16C
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8019E7BC
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019d16c(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x14))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019d1a0
 * EN v1.0 Address: 0x8019D1A0
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8019E7EC
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019d1a0(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019d1c8
 * EN v1.0 Address: 0x8019D1C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8019E820
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019d1c8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8019d1cc
 * EN v1.0 Address: 0x8019D1CC
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x8019E8F4
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019d1cc(undefined2 *param_1,int param_2)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  if (*(char *)(param_2 + 0x19) == '\0') {
    *(undefined *)(iVar1 + 0x15c) = 0x28;
    *(undefined *)(iVar1 + 0x15d) = 0;
    *(undefined *)(iVar1 + 0x15e) = 0;
    *(undefined *)(iVar1 + 0x15f) = 0x46;
    *(undefined *)((int)param_1 + 0xad) = 1;
    *(undefined4 *)(iVar1 + 0x158) = 0;
  }
  FUN_80037ce0((int)param_1,2);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019d238
 * EN v1.0 Address: 0x8019D238
 * EN v1.0 Size: 668b
 * EN v1.1 Address: 0x8019E970
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8019d238(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,
            undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  double dVar2;
  
  iVar1 = *(int *)(param_9 + 0xb8);
  if ((*(short *)(param_9 + 0xa0) != 5) && (*(short *)(param_9 + 0xa0) != 0xd)) {
    FUN_800305f8((double)*(float *)(param_9 + 0x98),param_2,param_3,param_4,param_5,param_6,param_7,
                 param_8,param_9,0xd,0,param_12,param_13,param_14,param_15,param_16);
  }
  if ((*(short *)(param_9 + 0xa0) == 5) && (FLOAT_803e4ec4 < *(float *)(param_9 + 0x28))) {
    FUN_800305f8((double)*(float *)(param_9 + 0x98),param_2,param_3,param_4,param_5,param_6,param_7,
                 param_8,param_9,0xd,0,param_12,param_13,param_14,param_15,param_16);
  }
  if ((*(short *)(param_9 + 0xa0) == 0xd) && (*(float *)(param_9 + 0x28) < FLOAT_803e4eb0)) {
    FUN_800305f8((double)*(float *)(param_9 + 0x98),param_2,param_3,param_4,param_5,param_6,param_7,
                 param_8,param_9,5,0,param_12,param_13,param_14,param_15,param_16);
  }
  dVar2 = (double)((*(float *)(param_9 + 0x28) * FLOAT_803dcab4 + FLOAT_803e4ec8) * FLOAT_803e4ecc);
  if (dVar2 < (double)FLOAT_803e4eb0) {
    dVar2 = (double)FLOAT_803e4eb0;
  }
  if ((double)FLOAT_803e4ecc < dVar2) {
    dVar2 = (double)FLOAT_803e4ecc;
  }
  if (*(short *)(param_9 + 0xa0) == 0xd) {
    if (*(float *)(param_9 + 0x98) <= FLOAT_803e4ecc) {
      *(byte *)(iVar1 + 0x244) = *(byte *)(iVar1 + 0x244) & 0xbf;
    }
    else if ((*(byte *)(iVar1 + 0x244) >> 6 & 1) == 0) {
      FUN_80006824(param_9,0x334);
      *(byte *)(iVar1 + 0x244) = *(byte *)(iVar1 + 0x244) & 0xbf | 0x40;
    }
  }
  FUN_8002fc3c(dVar2,(double)FLOAT_803dc074);
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_8019d4d4
 * EN v1.0 Address: 0x8019D4D4
 * EN v1.0 Size: 572b
 * EN v1.1 Address: 0x8019EAE4
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019d4d4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,int param_10,int param_11,int param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  short sVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  
  uVar3 = 0x28;
  uVar4 = 0;
  uVar5 = 3;
  FUN_8003add8(param_9,param_10,param_11 + 0x3c,0x28,0,3);
  iVar2 = FUN_80038a34(param_9,param_10,(float *)0x0);
  sVar1 = (short)(iVar2 >> 3);
  *param_9 = *param_9 + sVar1;
  if (param_12 != 0) {
    if ((sVar1 < -199) || (199 < sVar1)) {
      if (*(int *)(param_11 + 0xc0) == 0) {
        *(undefined4 *)(param_11 + 0xc0) = 1;
        FUN_800305f8((double)FLOAT_803e4eb0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,9,0,uVar3,uVar4,uVar5,param_15,param_16);
      }
      else {
        iVar2 = (int)sVar1;
        if (iVar2 < 1) {
          sVar1 = (short)(-iVar2 >> 2);
        }
        else {
          sVar1 = (short)(iVar2 >> 2);
        }
        FUN_8002fc3c((double)((float)((double)CONCAT44(0x43300000,(int)sVar1 ^ 0x80000000) -
                                     DOUBLE_803e4eb8) / FLOAT_803e4ed8),(double)FLOAT_803dc074);
      }
    }
    else if (*(int *)(param_11 + 0xc0) == 0) {
      FUN_8002fc3c((double)FLOAT_803e4ed4,(double)FLOAT_803dc074);
    }
    else {
      *(undefined4 *)(param_11 + 0xc0) = 0;
      FUN_800305f8((double)FLOAT_803e4eb0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0,0,uVar3,uVar4,uVar5,param_15,param_16);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019d710
 * EN v1.0 Address: 0x8019D710
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x8019EC44
 * EN v1.1 Size: 340b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019d710(void)
{
  bool bVar1;
  undefined2 *puVar2;
  int iVar3;
  int iVar4;
  float *pfVar5;
  int iVar6;
  double dVar7;
  
  puVar2 = (undefined2 *)FUN_80286840();
  pfVar5 = *(float **)(puVar2 + 0x5c);
  iVar4 = *(int *)(puVar2 + 0x26);
  iVar3 = FUN_80017a98();
  iVar6 = *(int *)(puVar2 + 0x26);
  bVar1 = false;
  dVar7 = (double)FUN_8001771c((float *)(iVar3 + 0x18),(float *)(puVar2 + 0xc));
  if (((dVar7 < (double)(float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(iVar6 + 0x1a) ^ 0x80000000) -
                               DOUBLE_803e4eb8)) && (pfVar5[0x8c] == 4.2039e-45)) &&
     ((puVar2[0x58] & 0x1000) == 0)) {
    bVar1 = true;
  }
  if (bVar1) {
    FUN_8007f718(pfVar5,0x3c);
    *(undefined4 *)(puVar2 + 0x7a) = 1;
    *puVar2 = *(undefined2 *)(pfVar5 + 0x34);
    (**(code **)(*DAT_803dd6d4 + 0x48))(4,puVar2,0xffffffff);
    *pfVar5 = FLOAT_803e4edc;
    FUN_80017688(0x901);
    pfVar5[0x31] = 1.68156e-44;
    FUN_80017698((int)*(short *)(iVar4 + 0x1e),1);
    *(undefined4 *)(puVar2 + 0x7a) = 0;
  }
  else {
    FUN_80039468(puVar2,pfVar5 + 0x1b,0x296,0x1000,0xffffffff,1);
    FUN_80006824((uint)puVar2,0xd4);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019d874
 * EN v1.0 Address: 0x8019D874
 * EN v1.0 Size: 984b
 * EN v1.1 Address: 0x8019ED98
 * EN v1.1 Size: 936b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019d874(undefined4 param_1,undefined4 param_2,int param_3)
{
  float fVar1;
  float fVar2;
  bool bVar3;
  int iVar4;
  ushort *puVar5;
  int iVar6;
  uint uVar7;
  undefined4 uVar8;
  int iVar9;
  char cVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  bool bVar14;
  double dVar15;
  float local_48 [2];
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  
  puVar5 = (ushort *)FUN_80286830();
  iVar13 = *(int *)(puVar5 + 0x26);
  iVar12 = *(int *)(puVar5 + 0x5c);
  if (puVar5[0x5a] != 4) {
    *(undefined *)(param_3 + 0x56) = 0;
    iVar6 = FUN_80017a98();
    fVar1 = *(float *)(iVar6 + 0xc) - *(float *)(iVar13 + 8);
    fVar2 = *(float *)(iVar6 + 0x14) - *(float *)(iVar13 + 0x10);
    iVar4 = (int)*(short *)(iVar13 + 0x1a) / 2;
    uStack_3c = iVar4 * iVar4 ^ 0x80000000;
    local_40 = 0x43300000;
    bVar14 = fVar1 * fVar1 + fVar2 * fVar2 <
             (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e4eb8);
    *(byte *)((int)puVar5 + 0xaf) = *(byte *)((int)puVar5 + 0xaf) & 0xf7;
    iVar9 = *(int *)(puVar5 + 0x5c);
    iVar4 = FUN_80017a98();
    iVar11 = *(int *)(puVar5 + 0x26);
    bVar3 = false;
    dVar15 = (double)FUN_8001771c((float *)(iVar4 + 0x18),(float *)(puVar5 + 0xc));
    uStack_34 = (int)*(short *)(iVar11 + 0x1a) ^ 0x80000000;
    local_38 = 0x43300000;
    if (((dVar15 < (double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4eb8)) &&
        (*(int *)(iVar9 + 0x230) == 3)) && ((puVar5[0x58] & 0x1000) == 0)) {
      bVar3 = true;
    }
    if (bVar3) {
      *(byte *)((int)puVar5 + 0xaf) = *(byte *)((int)puVar5 + 0xaf) & 0xef;
    }
    else {
      *(byte *)((int)puVar5 + 0xaf) = *(byte *)((int)puVar5 + 0xaf) | 0x10;
    }
    if ((!bVar14) && (*(int *)(iVar12 + 0x230) == 2)) {
      uStack_34 = (int)*(short *)(iVar13 + 0x18) ^ 0x80000000;
      local_38 = 0x43300000;
      local_48[0] = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4eb8);
      iVar4 = FUN_80037008(3,puVar5,local_48);
      if (iVar4 != 0) {
        bVar14 = true;
      }
    }
    for (cVar10 = '\0'; (int)cVar10 < (int)(uint)*(byte *)(param_3 + 0x8b); cVar10 = cVar10 + '\x01'
        ) {
      if (*(char *)(param_3 + cVar10 + 0x81) == '\x01') {
        FUN_80006824(0,0x109);
      }
    }
    *(undefined4 *)(iVar12 + 0xc4) = 0;
    switch(*(undefined4 *)(iVar12 + 0xc4)) {
    case 0:
    case 8:
      *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfffd;
      uVar7 = FUN_80038a34(puVar5,iVar6,(float *)0x0);
      FUN_8003add8(puVar5,iVar6,iVar12 + 0x3c,0x28,0,3);
      *puVar5 = *puVar5 + ((short)uVar7 >> 3) + (ushort)((short)uVar7 < 0 && (uVar7 & 7) != 0);
      if (bVar14) {
        *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
      }
      else {
        *(undefined *)(param_3 + 0x90) = 8;
      }
      break;
    case 5:
      *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfffd;
      iVar13 = FUN_80017a90();
      uVar7 = FUN_80038a34(puVar5,iVar13,(float *)0x0);
      uVar8 = FUN_80017a90();
      FUN_8003add8(puVar5,uVar8,iVar12 + 0x3c,0x28,0,3);
      *puVar5 = *puVar5 + ((short)uVar7 >> 3) + (ushort)((short)uVar7 < 0 && (uVar7 & 7) != 0);
      break;
    case 10:
    case 0xb:
      if (*(int *)(iVar12 + 0x114) != 0) {
        *(float *)(iVar12 + 0xac) = *(float *)(iVar12 + 0xac) * FLOAT_803e4ee0;
        *(undefined4 *)(*(int *)(iVar12 + 0x114) + 8) = *(undefined4 *)(iVar12 + 0xac);
      }
      *(undefined4 *)(iVar12 + 0xc4) = 0xb;
      dVar15 = (double)FUN_8001771c((float *)(puVar5 + 0xc),(float *)(iVar6 + 0x18));
      uStack_34 = (int)*(short *)(iVar13 + 0x1a) ^ 0x80000000;
      local_38 = 0x43300000;
      if ((dVar15 < (double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4eb8)) &&
         ((*(byte *)((int)puVar5 + 0xaf) & 1) != 0)) {
        *(undefined4 *)(iVar12 + 0xc4) = 7;
        goto LAB_8019f118;
      }
    }
  }
LAB_8019f118:
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019dc4c
 * EN v1.0 Address: 0x8019DC4C
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x8019F140
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019dc4c(int param_1)
{
  FUN_80037180(param_1,0x20);
  FUN_80037180(param_1,3);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019dc88
 * EN v1.0 Address: 0x8019DC88
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8019F17C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019dc88(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019dcb0
 * EN v1.0 Address: 0x8019DCB0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8019F1B0
 * EN v1.1 Size: 1908b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019dcb0(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8019dcb4
 * EN v1.0 Address: 0x8019DCB4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8019F924
 * EN v1.1 Size: 408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019dcb4(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8019dcb8
 * EN v1.0 Address: 0x8019DCB8
 * EN v1.0 Size: 1136b
 * EN v1.1 Address: 0x8019FABC
 * EN v1.1 Size: 1020b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019dcb8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)
{
  bool bVar1;
  byte bVar2;
  short sVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar9;
  int iVar10;
  double dVar11;
  undefined8 uVar12;
  uint local_38;
  uint uStack_34;
  uint auStack_30 [2];
  undefined4 local_28;
  uint uStack_24;
  
  uVar4 = FUN_80286834();
  iVar10 = *(int *)(uVar4 + 0xb8);
  local_38 = 0;
  iVar9 = *(int *)(uVar4 + 0x4c);
  bVar2 = *(byte *)(param_11 + 0x80);
  if (bVar2 == 5) {
    param_2 = (double)FLOAT_803e4efc;
    uStack_24 = (uint)DAT_803dc070;
    local_28 = 0x43300000;
    *(float *)(iVar10 + 0x30) =
         (float)(param_2 * (double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e4f08)
                + (double)*(float *)(iVar10 + 0x30));
  }
  else if (bVar2 < 5) {
    if (3 < bVar2) {
      *(undefined *)(iVar10 + 0x37) = 6;
      goto LAB_8019fe8c;
    }
  }
  else if (bVar2 == 0x29) {
    *(float *)(iVar10 + 0x30) = FLOAT_803e4ef8;
  }
  if (*(short *)(uVar4 + 0xb4) < 0) goto LAB_8019fe8c;
  FUN_800360f0(uVar4);
  uVar5 = FUN_80017690(0x50);
  uVar6 = FUN_80017690(0x48);
  if (((*(byte *)(iVar10 + 0x38) & 2) != 0) && (uVar7 = FUN_80017690(0x4d), uVar7 != 0)) {
    *(byte *)(iVar10 + 0x38) = *(byte *)(iVar10 + 0x38) & 0xfd;
    goto LAB_8019fe8c;
  }
  bVar1 = (char)uVar5 != '\0';
  if (bVar1) goto LAB_8019fe8c;
  if ((bVar1) || (*(char *)(iVar10 + 0x37) == '\x05')) {
    *(undefined *)(iVar10 + 0x37) = 5;
    goto LAB_8019fe8c;
  }
  bVar1 = false;
  iVar8 = FUN_80017a98();
  switch(*(undefined *)(iVar10 + 0x37)) {
  case 0:
    FUN_8003b1a4(uVar4,iVar10);
    dVar11 = (double)FUN_8001771c((float *)(uVar4 + 0x18),(float *)(iVar8 + 0x18));
    if ((char)uVar6 == '\0') {
      uStack_24 = (int)*(short *)(iVar9 + 0x1a) ^ 0x80000000;
      local_28 = 0x43300000;
      param_2 = DOUBLE_803e4f10;
      if ((dVar11 < (double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e4f10)) ||
         (iVar9 = FUN_800810ac((double)FLOAT_803e4f00,(float *)(uVar4 + 0xc)), iVar9 != 0)) {
        iVar9 = FUN_80294d6c(iVar8);
        if (iVar9 == 0x40) {
          *(byte *)(uVar4 + 0xaf) = *(byte *)(uVar4 + 0xaf) | 8;
          *(undefined *)(iVar10 + 0x37) = 5;
          *(undefined2 *)(iVar10 + 0x34) = 0x14;
          (**(code **)(*DAT_803dd6d4 + 0x48))(2,uVar4,0xffffffff);
          goto LAB_8019fe8c;
        }
        bVar1 = true;
        *(undefined *)(iVar10 + 0x37) = 4;
      }
    }
    break;
  case 1:
    dVar11 = (double)FUN_8001771c((float *)(uVar4 + 0x18),(float *)(iVar8 + 0x18));
    if ((char)uVar6 == '\0') {
      uStack_24 = (int)*(short *)(iVar9 + 0x1a) ^ 0x80000000;
      local_28 = 0x43300000;
      param_2 = DOUBLE_803e4f10;
      if (dVar11 < (double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e4f10)) {
        iVar9 = FUN_80294d6c(iVar8);
        if (iVar9 == 0x40) {
          *(undefined *)(iVar10 + 0x37) = 2;
        }
        else {
          bVar1 = true;
          *(undefined *)(iVar10 + 0x37) = 4;
        }
      }
    }
    break;
  case 2:
    sVar3 = *(short *)(iVar10 + 0x34) - (ushort)DAT_803dc070;
    *(short *)(iVar10 + 0x34) = sVar3;
    if (sVar3 < 1) {
      *(undefined *)(iVar10 + 0x37) = 1;
    }
    FUN_8003b1a4(uVar4,iVar10);
    break;
  case 3:
    sVar3 = *(short *)(iVar10 + 0x34) - (ushort)DAT_803dc070;
    *(short *)(iVar10 + 0x34) = sVar3;
    if (sVar3 < 1) {
      *(undefined *)(iVar10 + 0x37) = 0;
    }
    break;
  case 5:
    goto LAB_8019fe8c;
  case 6:
    goto LAB_8019fe8c;
  case 7:
    bVar1 = true;
    *(undefined *)(iVar10 + 0x37) = 4;
  }
  if ((*(short *)(uVar4 + 0xa0) == 0x103) || (*(short *)(uVar4 + 0xa0) == 0x2e)) {
    uVar12 = FUN_80006824(uVar4,0xe3);
  }
  else {
    uVar12 = FUN_8000680c(uVar4,0x10);
  }
  if (!bVar1) {
    *(undefined *)(iVar10 + 0x36) = 0;
    *(undefined *)(param_11 + 0x56) = 0;
    do {
      iVar9 = FUN_80037584(uVar4,&uStack_34,auStack_30,&local_38);
    } while (iVar9 != 0);
    if (*(char *)(param_11 + 0x80) == '\x01') {
      FUN_800066e0(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar4,uVar4,0x18,0
                   ,0,0,in_r9,in_r10);
      *(undefined *)(param_11 + 0x80) = 0;
    }
  }
LAB_8019fe8c:
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019e128
 * EN v1.0 Address: 0x8019E128
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x8019FEB8
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019e128(int param_1)
{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
    if (FLOAT_803e4ef8 < *(float *)(iVar1 + 0x30)) {
      *(float *)(iVar1 + 0x30) =
           FLOAT_803e4efc *
           (float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) - DOUBLE_803e4f08) +
           *(float *)(iVar1 + 0x30);
      if ((double)*(float *)(iVar1 + 0x30) < (double)FLOAT_803e4f1c) {
        FUN_8008111c((double)FLOAT_803e4f18,(double)*(float *)(iVar1 + 0x30),param_1,3,(int *)0x0);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019e1d0
 * EN v1.0 Address: 0x8019E1D0
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x8019FF74
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019e1d0(int param_1)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_800369d0(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
  if (iVar1 == 0x13) {
    *(undefined *)(iVar2 + 0x37) = 7;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019e218
 * EN v1.0 Address: 0x8019E218
 * EN v1.0 Size: 412b
 * EN v1.1 Address: 0x8019FFBC
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019e218(void)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  
  iVar1 = FUN_80286840();
  iVar5 = *(int *)(iVar1 + 0xb8);
  iVar2 = FUN_80017a98();
  iVar4 = *(int *)(iVar1 + 0x4c);
  if ((char)*(byte *)(iVar5 + 0x39) < '\0') {
    *(byte *)(iVar5 + 0x39) = *(byte *)(iVar5 + 0x39) & 0x7f;
  }
  uVar3 = FUN_80017690((int)*(short *)(iVar4 + 0x1e));
  if (uVar3 == 0) {
    uVar3 = FUN_80017690(0x44);
    dVar6 = (double)FUN_8001771c((float *)(iVar1 + 0x18),(float *)(iVar2 + 0x18));
    if (*(char *)(iVar5 + 0x38) == '\x01') {
      FUN_800810ac((double)FLOAT_803e4f00,(float *)(iVar1 + 0xc));
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,iVar1,0xffffffff);
      *(undefined *)(iVar5 + 0x38) = 2;
    }
    if (((uVar3 == 0) &&
        (((*(char *)(iVar5 + 0x37) == '\x04' ||
          (dVar6 < (double)(float)((double)CONCAT44(0x43300000,
                                                    (int)*(short *)(iVar4 + 0x1a) ^ 0x80000000) -
                                  DOUBLE_803e4f10))) ||
         (iVar4 = FUN_800810ac((double)FLOAT_803e4f00,(float *)(iVar1 + 0xc)), iVar4 != 0)))) &&
       (iVar2 = FUN_80294d6c(iVar2), iVar2 != 0x40)) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,iVar1,0xffffffff);
    }
  }
  else {
    *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) | 8;
    *(ushort *)(iVar1 + 6) = *(ushort *)(iVar1 + 6) | 0x4000;
    FUN_800360d4(iVar1);
    FUN_80017ad0(iVar1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019e3b4
 * EN v1.0 Address: 0x8019E3B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A014C
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019e3b4(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8019e3b8
 * EN v1.0 Address: 0x8019E3B8
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x801A0200
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8019e3b8(int param_1,undefined4 param_2,int param_3)
{
  int iVar1;
  
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 0x74) == '\0') && (*(char *)(param_3 + 0x80) == '\x02'))
  {
    *(undefined *)(*(int *)(param_1 + 0xb8) + 0x74) = 1;
    iVar1 = FUN_80017a98();
    FUN_80294d40(iVar1,2);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8019e408
 * EN v1.0 Address: 0x8019E408
 * EN v1.0 Size: 324b
 * EN v1.1 Address: 0x801A0270
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019e408(void)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  char in_r8;
  int *piVar4;
  
  iVar1 = FUN_80286838();
  piVar4 = *(int **)(iVar1 + 0xb8);
  uVar2 = FUN_80017690(0x50);
  if (uVar2 == 0) {
    uVar2 = FUN_80017690(0x4d);
    if ((uVar2 == 0) || (in_r8 == '\0')) {
      if ((piVar4 != (int *)0x0) && (iVar3 = *piVar4, iVar3 != 0)) {
        if (*(char *)((int)piVar4 + 0x73) == '\0') {
          if (in_r8 != '\0') {
            iVar3 = FUN_80057690(iVar3);
            if (iVar3 != 0) {
              FUN_8003b818(*piVar4);
              FUN_800388b4(*piVar4,0,(float *)(iVar1 + 0xc),(undefined4 *)(iVar1 + 0x10),
                           (float *)(iVar1 + 0x14),0);
            }
            FUN_8003b818(iVar1);
          }
        }
        else {
          iVar3 = FUN_80057690(iVar3);
          if (iVar3 != 0) {
            FUN_8003b818(*piVar4);
          }
          if (in_r8 != '\0') {
            FUN_8003b818(iVar1);
          }
        }
      }
    }
    else {
      FUN_8003b818(iVar1);
      if ((*piVar4 != 0) && (iVar1 = FUN_80057690(*piVar4), iVar1 != 0)) {
        FUN_8003b818(*piVar4);
      }
    }
  }
  else if ((*piVar4 != 0) && (iVar1 = FUN_80057690(*piVar4), iVar1 != 0)) {
    FUN_8003b818(*piVar4);
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019e54c
 * EN v1.0 Address: 0x8019E54C
 * EN v1.0 Size: 536b
 * EN v1.1 Address: 0x801A0458
 * EN v1.1 Size: 536b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019e54c(uint param_1)
{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  undefined2 *puVar4;
  int iVar5;
  int *piVar6;
  uint uStack_38;
  uint uStack_34;
  int local_30;
  int local_2c;
  uint auStack_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  piVar6 = *(int **)(param_1 + 0xb8);
  if ((piVar6 != (int *)0x0) && (uVar1 = FUN_80017690(0x50), uVar1 == 0)) {
    iVar2 = FUN_80037584(param_1,&uStack_34,auStack_28,&uStack_38);
    if (iVar2 != 0) {
      *piVar6 = 0;
    }
    if (*piVar6 == 0) {
      iVar2 = FUN_80017b00(&local_2c,&local_30);
      for (; local_2c < local_30; local_2c = local_2c + 1) {
        iVar5 = *(int *)(iVar2 + local_2c * 4);
        if (*(short *)(iVar5 + 0x44) == 0x3d) {
          *piVar6 = iVar5;
          local_2c = local_30;
        }
      }
    }
    FUN_80037d74(param_1);
    uVar1 = FUN_80017690(0x4d);
    *(char *)((int)piVar6 + 0x73) = (char)uVar1;
    if (*(char *)((int)piVar6 + 0x73) == '\0') {
      uVar3 = FUN_80017a98();
      FUN_8003add8(param_1,uVar3,*(int *)(param_1 + 0xb8) + 4,0x41,0,3);
      uVar1 = FUN_80017760(0,0x1e);
      if (uVar1 == 0) {
        FUN_800392ec(param_1,(undefined *)(piVar6 + 0xd),0x297);
      }
      iVar2 = FUN_800384ec(param_1);
      if (iVar2 == 0) {
        FUN_80038f38(param_1,(char *)(piVar6 + 0xd));
        uStack_1c = (uint)DAT_803dc070;
        local_20 = 0x43300000;
        FUN_8002fc3c((double)FLOAT_803e4f24,
                     (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4f28));
      }
      else {
        FUN_8003add8(param_1,uVar3,*(int *)(param_1 + 0xb8) + 4,0x41,0,3);
        puVar4 = (undefined2 *)FUN_8003964c(param_1,1);
        *puVar4 = 0xf556;
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
      }
    }
    else {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      if (*(short *)(param_1 + 0xb4) == -1) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019e764
 * EN v1.0 Address: 0x8019E764
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A0670
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019e764(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8019e768
 * EN v1.0 Address: 0x8019E768
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x801A06F0
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
byte FUN_8019e768(int param_1)
{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 8) >> 7;
}

/*
 * --INFO--
 *
 * Function: FUN_8019e77c
 * EN v1.0 Address: 0x8019E77C
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x801A0710
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019e77c(int param_1)
{
  if (**(uint **)(param_1 + 0xb8) != 0) {
    FUN_80017520(*(uint **)(param_1 + 0xb8));
  }
  if (*(int *)(param_1 + 0xc4) != 0) {
    FUN_8003817c(*(int *)(param_1 + 0xc4),param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019e7cc
 * EN v1.0 Address: 0x8019E7CC
 * EN v1.0 Size: 408b
 * EN v1.1 Address: 0x801A0764
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019e7cc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int *param_9)
{
  int iVar1;
  byte bVar2;
  int iVar3;
  int local_70;
  float local_6c;
  float local_68;
  undefined4 local_64;
  int aiStack_60 [22];
  
  iVar3 = param_9[0x2e];
  *(byte *)(iVar3 + 8) = *(byte *)(iVar3 + 8) & 0x7f;
  if (((param_9[0x31] != 0) &&
      (((iVar1 = FUN_800369d0((int)param_9,&local_70,(int *)0x0,(uint *)0x0), iVar1 != 0 ||
        (local_70 = *(int *)(param_9[0x15] + 0x50), local_70 != 0)) &&
       (iVar1 = FUN_80017a98(), local_70 == iVar1)))) &&
     (bVar2 = FUN_80294c20(local_70), bVar2 == 0)) {
    local_6c = *(float *)(local_70 + 0xc);
    local_68 = (float)((double)FLOAT_803e4f30 + (double)*(float *)(local_70 + 0x10));
    local_64 = *(undefined4 *)(local_70 + 0x14);
    iVar1 = FUN_8020a490((double)FLOAT_803e4f30,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,(float *)(param_9 + 3),&local_6c);
    if (iVar1 != 0) {
      if ((param_9[0x3d] == 0) &&
         (iVar1 = FUN_800620e8(param_9 + 3,&local_6c,(float *)0x0,aiStack_60,param_9,4,0xffffffff,0,
                               0), iVar1 != 0)) {
        return;
      }
      *(byte *)(iVar3 + 8) = *(byte *)(iVar3 + 8) & 0x7f | 0x80;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019e964
 * EN v1.0 Address: 0x8019E964
 * EN v1.0 Size: 600b
 * EN v1.1 Address: 0x801A088C
 * EN v1.1 Size: 408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019e964(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  double dVar5;
  byte local_58;
  byte local_57;
  byte local_56 [2];
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_38;
  uint uStack_34;
  longlong local_30;
  undefined4 local_28;
  uint uStack_24;
  longlong local_20;
  undefined4 local_18;
  uint uStack_14;
  longlong local_10;
  
  piVar4 = *(int **)(param_9 + 0x5c);
  if (*piVar4 == 0) {
    iVar3 = FUN_80017524(param_9,0xfa,0xfa,0xfa,1);
    *piVar4 = iVar3;
    if (*piVar4 != 0) {
      param_2 = (double)(float)((double)FLOAT_803e4f38 + (double)FLOAT_803dcac0);
      FUN_800175d0((double)FLOAT_803dcac0,param_2,*piVar4);
    }
  }
  FUN_80035fe8((int)param_9,0x17,0,0);
  local_48 = DAT_80323888;
  local_44 = DAT_8032388c;
  local_40 = DAT_80323890;
  FUN_80017a40(param_9,&DAT_80323888,&local_48);
  FUN_8020a494((double)FLOAT_803dcac4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               &local_54,(float *)(param_9 + 6),&local_48);
  dVar5 = FUN_802480e8((float *)(param_9 + 6),&local_54);
  FUN_80247edc(dVar5,&DAT_80323888,&local_54);
  FUN_80080f8c(0,local_56,&local_57,&local_58);
  if (*piVar4 != 0) {
    uStack_34 = (uint)local_56[0];
    local_38 = 0x43300000;
    iVar3 = (int)(FLOAT_803e4f3c * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4f40)
                 );
    local_30 = (longlong)iVar3;
    uStack_24 = (uint)local_57;
    local_28 = 0x43300000;
    iVar1 = (int)(FLOAT_803e4f3c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e4f40)
                 );
    local_20 = (longlong)iVar1;
    uStack_14 = (uint)local_58;
    local_18 = 0x43300000;
    iVar2 = (int)(FLOAT_803e4f3c * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e4f40)
                 );
    local_10 = (longlong)iVar2;
    FUN_8001759c(*piVar4,(char)iVar3,(char)iVar1,(char)iVar2,0xff);
    FUN_800175ec((double)local_54,(double)local_50,(double)local_4c,(int *)*piVar4);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: babycloudrunner_func08
 * EN v1.0 Address: 0x8019EBBC
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x801A0A24
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void babycloudrunner_func08(int param_1)
{
  undefined4 *puVar1;
  
  puVar1 = *(undefined4 **)(param_1 + 0xb8);
  *puVar1 = 0;
  puVar1[1] = 0;
  FUN_800360f0(param_1);
  *(undefined *)(param_1 + 0x36) = 0x80;
  return;
}

/*
 * --INFO--
 *
 * Function: babycloudrunner_render
 * EN v1.0 Address: 0x8019EC00
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x801A0A70
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 babycloudrunner_render(undefined4 param_1,undefined4 param_2,int param_3)
{
  uint uVar1;
  
  uVar1 = FUN_80017690(0x4d);
  if (uVar1 != 0) {
    *(undefined *)(param_3 + 0x90) = 4;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8019ec44
 * EN v1.0 Address: 0x8019EC44
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x801A0AC4
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019ec44(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  FUN_80037844(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3e,0,param_9,
               0x40001,0,in_r8,in_r9,in_r10);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019ecf0
 * EN v1.0 Address: 0x8019ECF0
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x801A0B04
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019ecf0(int param_1)
{
  uint uVar1;
  
  if ((*(int *)(param_1 + 0xf4) != 0) && (uVar1 = FUN_80017690(0x50), uVar1 == 0)) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
  }
  *(undefined4 *)(param_1 + 0xf4) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019ed60
 * EN v1.0 Address: 0x8019ED60
 * EN v1.0 Size: 332b
 * EN v1.1 Address: 0x801A0B90
 * EN v1.1 Size: 408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8019ed60(int param_1,undefined4 param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint local_28;
  uint uStack_24;
  uint local_20 [5];
  
  local_28 = 0;
  iVar3 = *(int *)(param_1 + 0x4c);
  uVar1 = FUN_80017690((int)*(short *)(iVar3 + 0x18));
  if (uVar1 == 0) {
    if (*(short *)(param_1 + 0x46) != 0x127) {
      while (iVar2 = FUN_80037584(param_1,local_20,&uStack_24,&local_28), iVar2 != 0) {
        if (local_20[0] == 0xa0005) {
          FUN_80017698((int)*(short *)(iVar3 + 0x18),1);
        }
      }
      uVar1 = FUN_80017690(0x44);
      if (uVar1 == 0) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
      }
      else {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
      }
      if (((*(byte *)(param_1 + 0xaf) & 1) != 0) &&
         (iVar3 = (**(code **)(*DAT_803dd6e8 + 0x20))(0x44), iVar3 != 0)) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      }
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8019eeac
 * EN v1.0 Address: 0x8019EEAC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801A0D28
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019eeac(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019eed4
 * EN v1.0 Address: 0x8019EED4
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801A0D58
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019eed4(int param_1)
{
  int iVar1;
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined4 auStack_10 [4];
  
  iVar1 = FUN_800368c4(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0,&uStack_18,&uStack_14,
                       auStack_10);
  if (iVar1 != 0) {
    FUN_800810e8(&uStack_18,8,200,0x80,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019ef2c
 * EN v1.0 Address: 0x8019EF2C
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x801A0DB0
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019ef2c(int param_1)
{
  short sVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0xf4) != 0) {
    sVar1 = *(short *)(param_1 + 0x46);
    if (((sVar1 == 0x128) || (0x127 < sVar1)) || (sVar1 < 0x127)) {
      uVar2 = 1;
    }
    else {
      uVar2 = 0;
    }
    (**(code **)(*DAT_803dd6d4 + 0x48))(uVar2,param_1,0xffffffff);
    *(undefined4 *)(param_1 + 0xf4) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019efac
 * EN v1.0 Address: 0x8019EFAC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A0E30
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019efac(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8019efb0
 * EN v1.0 Address: 0x8019EFB0
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801A0F20
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019efb0(int param_1)
{
  FUN_80037180(param_1,0x4e);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019efd4
 * EN v1.0 Address: 0x8019EFD4
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x801A0F44
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019efd4(int param_1)
{
  char in_r8;
  
  if ((in_r8 != '\0') && (**(char **)(param_1 + 0xb8) != '\0')) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019f00c
 * EN v1.0 Address: 0x8019F00C
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x801A0F8C
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019f00c(int param_1)
{
  uint uVar1;
  int iVar2;
  char *pcVar3;
  
  pcVar3 = *(char **)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
  if (*pcVar3 == '\0') {
    uVar1 = FUN_80017690((int)*(short *)(iVar2 + 0x1e));
    uVar1 = countLeadingZeros(uVar1);
    *pcVar3 = (char)(uVar1 >> 5);
    if ((uVar1 >> 5 & 0xff) != 0) {
      FUN_8003735c(param_1,0x4e);
    }
    if (*(char *)(param_1 + 0x36) != '\0') {
      *(char *)(param_1 + 0x36) = *(char *)(param_1 + 0x36) + -1;
    }
  }
  else {
    FUN_80081110(param_1,5,0,0,(undefined4 *)0x0);
    uVar1 = FUN_80017690((int)*(short *)(iVar2 + 0x1e));
    uVar1 = countLeadingZeros(uVar1);
    *pcVar3 = (char)(uVar1 >> 5);
    if ((uVar1 >> 5 & 0xff) == 0) {
      FUN_80037180(param_1,0x4e);
    }
    if (*(char *)(param_1 + 0x36) != -1) {
      *(char *)(param_1 + 0x36) = *(char *)(param_1 + 0x36) + '\x01';
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019f0ec
 * EN v1.0 Address: 0x8019F0EC
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x801A1090
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
byte FUN_8019f0ec(int param_1)
{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 0x4a) >> 5 & 1;
}

/*
 * --INFO--
 *
 * Function: FUN_8019f0fc
 * EN v1.0 Address: 0x8019F0FC
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x801A10A0
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8019f0fc(int param_1)
{
  int iVar1;
  undefined4 uVar2;
  
  uVar2 = 0;
  if (((*(char *)(*(int *)(param_1 + 0xb8) + 0x15) == '\0') &&
      (*(float *)(*(int *)(param_1 + 0xb8) + 0x18) == FLOAT_803e4f58)) &&
     (iVar1 = (**(code **)(*DAT_803dd740 + 0x14))(), iVar1 == 0)) {
    uVar2 = 1;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_8019f16c
 * EN v1.0 Address: 0x8019F16C
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x801A110C
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019f16c(int param_1)
{
  float fVar1;
  int iVar2;
  
  fVar1 = FLOAT_803e4f58;
  iVar2 = *(int *)(param_1 + 0xb8);
  *(float *)(iVar2 + 0x24) = FLOAT_803e4f58;
  *(float *)(iVar2 + 0x20) = fVar1;
  *(float *)(iVar2 + 0x28) = fVar1;
  *(byte *)(iVar2 + 0x49) = *(byte *)(iVar2 + 0x49) | 1;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  *(float *)(iVar2 + 0x38) = fVar1;
  *(byte *)(iVar2 + 0x4a) = *(byte *)(iVar2 + 0x4a) & 0xdf;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019f1ac
 * EN v1.0 Address: 0x8019F1AC
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x801A1158
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019f1ac(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(byte *)(iVar1 + 0x4a) = *(byte *)(iVar1 + 0x4a) & 0xdf | 0x20;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  *(byte *)(iVar1 + 0x49) = *(byte *)(iVar1 + 0x49) & 0xfd;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019f1dc
 * EN v1.0 Address: 0x8019F1DC
 * EN v1.0 Size: 496b
 * EN v1.1 Address: 0x801A1190
 * EN v1.1 Size: 496b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019f1dc(void)
{
  uint uVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  double in_f29;
  double dVar8;
  double in_f30;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  ulonglong uVar11;
  int local_68;
  ushort local_64 [4];
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  uVar11 = FUN_8028683c();
  uVar1 = (uint)(uVar11 >> 0x20);
  iVar5 = *(int *)(uVar1 + 0xb8);
  iVar2 = FUN_80017a98();
  iVar2 = *(int *)(iVar2 + 0xb8);
  *(float *)(iVar5 + 0x20) = FLOAT_803e4f58;
  if ((uVar11 & 0xff) == 0) {
    *(float *)(iVar5 + 0x24) = FLOAT_803e4f6c;
    *(float *)(iVar5 + 0x28) = FLOAT_803e4f70;
  }
  else {
    *(float *)(iVar5 + 0x24) = FLOAT_803e4f60 * *(float *)(iVar2 + 0x298) + FLOAT_803e4f5c;
    *(float *)(iVar5 + 0x28) = FLOAT_803e4f68 * *(float *)(iVar2 + 0x298) + FLOAT_803e4f64;
  }
  local_58 = FLOAT_803e4f58;
  local_54 = FLOAT_803e4f58;
  local_50 = FLOAT_803e4f58;
  local_5c = FLOAT_803e4f74;
  local_64[2] = 0;
  local_64[1] = 0;
  local_64[0] = *(ushort *)(iVar5 + 0x50);
  FUN_80017748(local_64,(float *)(iVar5 + 0x20));
  *(byte *)(iVar5 + 0x49) = *(byte *)(iVar5 + 0x49) | 1;
  FUN_80006824(uVar1,0xd3);
  *(byte *)(iVar5 + 0x49) = *(byte *)(iVar5 + 0x49) | 2;
  if ((*(byte *)(iVar5 + 0x48) >> 6 & 1) != 0) {
    iVar5 = *(int *)(uVar1 + 0x4c);
    iVar2 = 0;
    if (*(short *)(iVar5 + 0x1a) == 0) {
      iVar2 = FUN_80037008(0x3a,uVar1,(float *)0x0);
    }
    else {
      piVar3 = FUN_80037134(0x3a,&local_68);
      piVar6 = piVar3;
      for (iVar7 = 0; iVar7 < local_68; iVar7 = iVar7 + 1) {
        iVar4 = FUN_8020a468(*piVar6);
        if (*(short *)(iVar5 + 0x1a) == iVar4) {
          iVar2 = piVar3[iVar7];
          break;
        }
        piVar6 = piVar6 + 1;
      }
    }
    if (iVar2 != 0) {
      dVar10 = (double)*(float *)(uVar1 + 0xc);
      dVar9 = (double)*(float *)(uVar1 + 0x10);
      dVar8 = (double)*(float *)(uVar1 + 0x14);
      *(undefined4 *)(uVar1 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(uVar1 + 0x10) = *(undefined4 *)(iVar2 + 0x10);
      *(undefined4 *)(uVar1 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
      FUN_800e8630(uVar1);
      *(float *)(uVar1 + 0xc) = (float)dVar10;
      *(float *)(uVar1 + 0x10) = (float)dVar9;
      *(float *)(uVar1 + 0x14) = (float)dVar8;
    }
  }
  FUN_80286888();
  return;
}
