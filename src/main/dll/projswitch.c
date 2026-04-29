#include "ghidra_import.h"
#include "main/dll/projswitch.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_800068c4();
extern int FUN_80006b7c();
extern int FUN_800175c4();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern uint FUN_80017690();
extern double FUN_80017714();
extern uint FUN_80017730();
extern undefined4 FUN_80017814();
extern int FUN_80017830();
extern undefined4 FUN_8001789c();
extern undefined4 FUN_800178ac();
extern undefined4 FUN_800178b0();
extern byte FUN_80017a34();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern uint ObjGroup_ContainsObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjLink_DetachChild();
extern undefined4 FUN_8003b818();
extern int FUN_8005b220();
extern int FUN_8005b398();
extern undefined4 FUN_8008111c();
extern undefined4 FUN_8011e800();
extern undefined8 FUN_8014721c();
extern undefined8 FUN_801476cc();
extern undefined4 FUN_8014ab58();
extern undefined8 FUN_8014c0b4();
extern undefined4 FUN_8014c528();
extern undefined4 FUN_8014c690();
extern undefined4 FUN_8014ff4c();
extern undefined4 FUN_8015209c();
extern undefined4 FUN_801529a4();
extern undefined4 FUN_80152ec0();
extern undefined4 FUN_80153358();
extern undefined4 FUN_80153a80();
extern undefined4 FUN_801540a0();
extern undefined4 FUN_80154a78();
extern undefined4 FUN_80154f8c();
extern undefined4 FUN_8015603c();
extern undefined4 FUN_80156de4();
extern undefined4 FUN_80157724();
extern undefined4 FUN_80157100();
extern undefined4 FUN_8015801c();
extern undefined4 FUN_801599e0();
extern undefined4 FUN_80159bd0();
extern undefined4 FUN_80159c3c();
extern undefined4 FUN_8015a31c();
extern undefined4 FUN_8015b218();
extern undefined4 FUN_8015b3d4();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293900();
extern uint countLeadingZeros();

extern undefined4 DAT_8031e828;
extern undefined4 DAT_8031e834;
extern undefined4 DAT_803dc8c0;
extern undefined4 DAT_803dc8c8;
extern undefined4 DAT_803dc8cc;
extern undefined4 DAT_803dc8d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd728;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e3218;
extern f64 DOUBLE_803e3278;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc078;
extern f32 FLOAT_803e31fc;
extern f32 FLOAT_803e3200;
extern f32 FLOAT_803e3204;
extern f32 FLOAT_803e3208;
extern f32 FLOAT_803e3210;
extern f32 FLOAT_803e3244;
extern f32 FLOAT_803e324c;
extern f32 FLOAT_803e3284;
extern f32 FLOAT_803e3288;
extern f32 FLOAT_803e328c;
extern f32 FLOAT_803e3290;
extern f32 FLOAT_803e3294;
extern f32 FLOAT_803e3298;

/*
 * --INFO--
 *
 * Function: FUN_8014d164
 * EN v1.0 Address: 0x8014D164
 * EN v1.0 Size: 620b
 * EN v1.1 Address: 0x8014D194
 * EN v1.1 Size: 608b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014d164(double param_1,double param_2,ushort *param_3,int param_4,uint param_5,
                 char param_6)
{
  uint uVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  undefined8 local_50;
  undefined8 local_48;
  
  dVar4 = (double)(FLOAT_803dc074 /
                  (float)((double)CONCAT44(0x43300000,param_5 & 0xffff) - DOUBLE_803e3278));
  if ((double)FLOAT_803e3200 < dVar4) {
    dVar4 = (double)FLOAT_803e3200;
  }
  uVar1 = FUN_80017730();
  local_50 = (double)CONCAT44(0x43300000,(uVar1 & 0xffff) - (uint)*param_3 ^ 0x80000000);
  dVar2 = (double)(float)(local_50 - DOUBLE_803e3218);
  if ((double)FLOAT_803e324c < dVar2) {
    dVar2 = (double)(float)((double)FLOAT_803e3284 + dVar2);
  }
  if (dVar2 < (double)FLOAT_803e328c) {
    dVar2 = (double)(float)((double)FLOAT_803e3288 + dVar2);
  }
  dVar3 = (double)(float)(dVar2 * dVar4);
  *param_3 = *param_3 + (short)(int)(dVar2 * dVar4);
  if (param_1 != (double)FLOAT_803e31fc) {
    if (param_6 == '\0') {
      param_3[2] = (ushort)(int)(FLOAT_803dc078 * (float)(dVar3 * param_1));
      if ((short)param_3[2] < 0x2001) {
        if ((short)param_3[2] < -0x2000) {
          param_3[2] = 0xe000;
        }
      }
      else {
        param_3[2] = 0x2000;
      }
    }
    else {
      param_3[2] = param_3[2] + (short)(int)(param_1 * (double)(float)(dVar3 * dVar4));
    }
  }
  if ((double)FLOAT_803e31fc != param_2) {
    FUN_80293900((double)(*(float *)(param_4 + 0x2c0) * *(float *)(param_4 + 0x2c0) +
                         *(float *)(param_4 + 0x2b8) * *(float *)(param_4 + 0x2b8)));
    uVar1 = FUN_80017730();
    local_48 = (double)CONCAT44(0x43300000,(uVar1 & 0xffff) - (uint)param_3[1] ^ 0x80000000);
    dVar2 = (double)(float)(local_48 - DOUBLE_803e3218);
    if ((double)FLOAT_803e324c < dVar2) {
      dVar2 = (double)(float)((double)FLOAT_803e3284 + dVar2);
    }
    if (dVar2 < (double)FLOAT_803e328c) {
      dVar2 = (double)(float)((double)FLOAT_803e3288 + dVar2);
    }
    param_3[1] = param_3[1] + (short)(int)(dVar2 * dVar4);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014d3d0
 * EN v1.0 Address: 0x8014D3D0
 * EN v1.0 Size: 248b
 * EN v1.1 Address: 0x8014D3F4
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014d3d0(short *param_1,undefined4 param_2,uint param_3,short param_4)
{
  float fVar1;
  short sVar2;
  int iVar3;
  
  iVar3 = FUN_80017730();
  sVar2 = (short)iVar3 - *param_1;
  if (0x8000 < sVar2) {
    sVar2 = sVar2 + 1;
  }
  if (sVar2 < -0x8000) {
    sVar2 = sVar2 + -1;
  }
  fVar1 = FLOAT_803dc074 / (float)((double)CONCAT44(0x43300000,param_3 & 0xffff) - DOUBLE_803e3278);
  if (FLOAT_803e3200 < fVar1) {
    fVar1 = FLOAT_803e3200;
  }
  *param_1 = *param_1 +
             (short)(int)((float)((double)CONCAT44(0x43300000,
                                                   (int)(short)(sVar2 + param_4) ^ 0x80000000) -
                                 DOUBLE_803e3218) * fVar1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014d4c8
 * EN v1.0 Address: 0x8014D4C8
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x8014D504
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014d4c8(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
                 uint param_11,uint param_12,undefined4 param_13,undefined4 param_14,
                 undefined4 param_15,undefined4 param_16)
{
  if ((double)FLOAT_803e31fc == param_1) {
    *(float *)(param_10 + 0x308) = FLOAT_803e3208;
  }
  else {
    param_2 = (double)FLOAT_803e3200;
    *(float *)(param_10 + 0x308) =
         (float)(param_2 / (double)(float)((double)FLOAT_803e3204 * param_1));
  }
  *(char *)(param_10 + 0x323) = (char)param_13;
  FUN_800305f8((double)FLOAT_803e31fc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               param_9,param_11 & 0xff,param_12,param_12,param_13,param_14,param_15,param_16);
  if (*(int *)(param_9 + 0x54) != 0) {
    *(undefined *)(*(int *)(param_9 + 0x54) + 0x70) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014d59c
 * EN v1.0 Address: 0x8014D59C
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x8014D584
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014d59c(int param_1,undefined4 *param_2)
{
  if (*(short *)(param_1 + 0x46) == 0x7c8) {
    FUN_8001789c(param_2,*param_2,*(int **)(*(int *)(param_1 + 0xb8) + 0x36c),FUN_80159bd0);
  }
  else {
    FUN_8001789c(param_2,*param_2,*(int **)(*(int *)(param_1 + 0xb8) + 0x36c),(undefined *)0x0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014d600
 * EN v1.0 Address: 0x8014D600
 * EN v1.0 Size: 440b
 * EN v1.1 Address: 0x8014D5F8
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014d600(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  byte bVar1;
  short sVar2;
  int iVar3;
  uint uVar4;
  uint *puVar5;
  int iVar6;
  int iVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_80286840();
  iVar3 = (int)((ulonglong)uVar9 >> 0x20);
  puVar5 = *(uint **)(iVar3 + 0xb8);
  if ((uint *)puVar5[0xdb] != (uint *)0x0) {
    FUN_800178b0((uint *)puVar5[0xdb]);
  }
  if (puVar5[0xda] != 0) {
    FUN_80017620(puVar5[0xda]);
    puVar5[0xda] = 0;
  }
  if (*puVar5 != 0) {
    FUN_80017814(*puVar5);
    *puVar5 = 0;
  }
  sVar2 = *(short *)(iVar3 + 0x46);
  if (sVar2 == 0x851) {
    uVar4 = ObjGroup_ContainsObject(iVar3,0x50);
    if (uVar4 != 0) {
      ObjGroup_RemoveObject(iVar3,0x50);
    }
  }
  else if ((sVar2 < 0x851) && (sVar2 == 0x7c8)) {
    FUN_80159c3c(iVar3);
  }
  bVar1 = *(byte *)(iVar3 + 0xeb);
  for (iVar6 = 0; iVar6 < (int)(uint)bVar1; iVar6 = iVar6 + 1) {
    iVar7 = *(int *)(iVar3 + 200);
    if ((iVar7 != 0) &&
       ((uVar8 = ObjLink_DetachChild(iVar3,iVar7), (int)uVar9 == 0 ||
        ((*(ushort *)(iVar7 + 0xb0) & 0x10) == 0)))) {
      FUN_80017ac8(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar7);
    }
  }
  (**(code **)(*DAT_803dd6f8 + 0x14))(iVar3);
  ObjGroup_RemoveObject(iVar3,3);
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014d7b8
 * EN v1.0 Address: 0x8014D7B8
 * EN v1.0 Size: 364b
 * EN v1.1 Address: 0x8014D730
 * EN v1.1 Size: 404b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014d7b8(uint param_1)
{
  uint uVar1;
  int *piVar2;
  char in_r8;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if ((in_r8 != '\0') && (*(int *)(param_1 + 0xf4) == 0)) {
    FUN_8003b818(param_1);
    uVar1 = *(uint *)(iVar3 + 0x2e8);
    if ((uVar1 & 3) != 0) {
      if ((uVar1 & 1) != 0) {
        *(uint *)(iVar3 + 0x2e8) = uVar1 & 0xfffffffe;
        *(uint *)(iVar3 + 0x2e8) = *(uint *)(iVar3 + 0x2e8) | 2;
      }
      if (*(int *)(iVar3 + 0x368) == 0) {
        piVar2 = FUN_80017624(0,'\x01');
        *(int **)(iVar3 + 0x368) = piVar2;
      }
      FUN_8008111c((double)FLOAT_803e3200,(double)*(float *)(iVar3 + 0x30c),param_1,3,
                   *(int **)(iVar3 + 0x368));
    }
    if ((*(uint *)(iVar3 + 0x2e8) & 4) != 0) {
      if (*(int *)(iVar3 + 0x368) == 0) {
        piVar2 = FUN_80017624(0,'\x01');
        *(int **)(iVar3 + 0x368) = piVar2;
      }
      FUN_8008111c((double)FLOAT_803e3200,(double)*(float *)(iVar3 + 0x30c),param_1,4,
                   *(int **)(iVar3 + 0x368));
    }
    if ((*(uint *)(iVar3 + 0x2e8) & 0x40) != 0) {
      FUN_800068c4(param_1,0x9e);
      FUN_8008111c((double)FLOAT_803e3200,(double)*(float *)(iVar3 + 0x30c),param_1,5,(int *)0x0);
    }
    if ((*(uint *)(iVar3 + 0x2e8) & 0x80) != 0) {
      FUN_800068c4(param_1,0x9e);
      FUN_8008111c((double)FLOAT_803e3290,(double)*(float *)(iVar3 + 0x30c),param_1,6,(int *)0x0);
    }
    if ((*(uint *)(iVar3 + 0x2e8) & 0x100) != 0) {
      FUN_8008111c((double)FLOAT_803e3294,(double)*(float *)(iVar3 + 0x30c),param_1,7,(int *)0x0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014d924
 * EN v1.0 Address: 0x8014D924
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x8014D8C4
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014d924(int param_1)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if ((*(int *)(iVar2 + 0x368) != 0) && (iVar1 = FUN_800175c4(*(int *)(iVar2 + 0x368)), iVar1 == 0))
  {
    FUN_80017620(*(uint *)(iVar2 + 0x368));
    *(undefined4 *)(iVar2 + 0x368) = 0;
  }
  *(undefined4 *)(iVar2 + 0x340) = *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x50);
  if (*(int *)(*(int *)(param_1 + 0x54) + 0x50) != 0) {
    *(undefined *)(*(int *)(param_1 + 0x54) + 0x70) = 1;
  }
  if (((*(int *)(param_1 + 200) != 0) &&
      (iVar1 = *(int *)(*(int *)(param_1 + 200) + 0x54), iVar1 != 0)) &&
     (*(int *)(iVar1 + 0x50) != 0)) {
    *(undefined *)(*(int *)(param_1 + 0x54) + 0x70) = 1;
  }
  if (*(int *)(iVar2 + 0x36c) != 0) {
    FUN_800178ac(*(int *)(iVar2 + 0x36c));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014d9e4
 * EN v1.0 Address: 0x8014D9E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8014D984
 * EN v1.1 Size: 1268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014d9e4(undefined8 param_1,undefined8 param_2,double param_3,double param_4,double param_5
                 ,double param_6,double param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8014d9e8
 * EN v1.0 Address: 0x8014D9E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8014DE78
 * EN v1.1 Size: 1932b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014d9e8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,int param_11)
{
}

/* conditional init/free pair. */
extern u32 lbl_803DDA50;
extern void fn_80013E2C(u32);
#pragma scheduling off
void enemy_release(void) { if (lbl_803DDA50 != 0) { fn_80013E2C(lbl_803DDA50); lbl_803DDA50 = 0; } }
#pragma scheduling reset
