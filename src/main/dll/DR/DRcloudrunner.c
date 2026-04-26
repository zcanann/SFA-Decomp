#include "ghidra_import.h"
#include "main/dll/DR/DRcloudrunner.h"

extern undefined4 FUN_80006824();
extern double FUN_80006b34();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017748();
extern uint FUN_80017760();
extern undefined4 FUN_80017a28();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017b00();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 FUN_80035d58();
extern undefined4 ObjHits_RecordObjectHit();
extern int ObjHits_GetPriorityHitWithPosition();
extern int ObjHits_PollPriorityHitEffectWithCooldown();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8003b56c();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80042b9c();
extern int FUN_80044404();
extern undefined4 FUN_8004800c();
extern undefined4 FUN_800810e4();
extern undefined4 FUN_80081120();
extern int FUN_800e8b98();
extern undefined4 FUN_801db670();
extern int FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();

extern undefined4 DAT_803de888;
extern f64 DOUBLE_803e6260;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803e61fc;
extern f32 FLOAT_803e6200;
extern f32 FLOAT_803e6208;
extern f32 FLOAT_803e620c;
extern f32 FLOAT_803e6210;
extern f32 FLOAT_803e6214;
extern f32 FLOAT_803e6218;
extern f32 FLOAT_803e6220;
extern f32 FLOAT_803e6224;
extern f32 FLOAT_803e6228;
extern f32 FLOAT_803e622c;
extern f32 FLOAT_803e6230;
extern f32 FLOAT_803e6238;
extern f32 FLOAT_803e6240;
extern f32 FLOAT_803e6244;
extern f32 FLOAT_803e6248;
extern f32 FLOAT_803e624c;
extern f32 FLOAT_803e6250;
extern f32 FLOAT_803e6254;
extern f32 FLOAT_803e6258;
extern f32 FLOAT_803e626c;
extern f32 FLOAT_803e6270;
extern f32 FLOAT_803e6274;

/*
 * --INFO--
 *
 * Function: FUN_801dc310
 * EN v1.0 Address: 0x801DC310
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801DC444
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dc310(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801dc314
 * EN v1.0 Address: 0x801DC314
 * EN v1.0 Size: 428b
 * EN v1.1 Address: 0x801DC590
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dc314(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  uint uVar2;
  undefined2 *puVar3;
  undefined4 uVar4;
  char in_r6;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  undefined8 extraout_f1;
  undefined8 uVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar7 >> 0x20);
  iVar5 = *(int *)(iVar1 + 0x4c);
  uVar6 = extraout_f1;
  uVar2 = FUN_80017ae8();
  if ((uVar2 & 0xff) != 0) {
    puVar3 = FUN_80017aa4(0x28,0x210);
    *(undefined *)(puVar3 + 2) = *(undefined *)(iVar5 + 4);
    *(undefined *)(puVar3 + 3) = *(undefined *)(iVar5 + 6);
    *(undefined *)((int)puVar3 + 5) = *(undefined *)(iVar5 + 5);
    *(char *)((int)puVar3 + 7) = *(char *)(iVar5 + 7) + -10;
    iVar5 = (int)uVar7 + in_r6 * 0xc;
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(iVar5 + 0xc);
    *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(iVar5 + 0x10);
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(iVar5 + 0x14);
    uVar2 = FUN_80017760(0x708,6000);
    puVar3[0xe] = (short)uVar2;
    puVar3[0xf] = 1;
    *(undefined *)(puVar3 + 0x10) = 10;
    *(undefined *)((int)puVar3 + 0x21) = 0x28;
    *(undefined *)(puVar3 + 0x11) = 0x32;
    *(undefined *)((int)puVar3 + 0x23) = 10;
    *(undefined *)(puVar3 + 0x12) = 0x32;
    *(undefined *)((int)puVar3 + 0x25) = 0xce;
    puVar3[0x13] = 0xffff;
    *(undefined4 *)(puVar3 + 0xc) = 0;
    uVar4 = FUN_80017ae4(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,0xff
                         ,0xffffffff,*(uint **)(iVar1 + 0x30),in_r8,in_r9,in_r10);
    *(undefined4 *)((int)uVar7 + in_r6 * 4) = uVar4;
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801dc4c0
 * EN v1.0 Address: 0x801DC4C0
 * EN v1.0 Size: 376b
 * EN v1.1 Address: 0x801DC6AC
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dc4c0(uint param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
  if (iVar2 == 0x448c2) {
    uVar1 = FUN_80017690(0xc44);
    if (uVar1 != 0) {
      FUN_80017698(0xc41,1);
    }
  }
  else if (iVar2 < 0x448c2) {
    if (iVar2 == 0x30d9c) {
      FUN_80006824(param_1,299);
      FUN_80006824(param_1,0x12a);
      FUN_80017698(0x7d,1);
    }
    else if (iVar2 < 0x30d9c) {
      if (0x30d9a < iVar2) {
        FUN_80006824(param_1,0x12d);
        FUN_80006824(param_1,0x12a);
        FUN_80017698(0x7f,1);
      }
    }
    else if (iVar2 < 0x30d9e) {
      FUN_80006824(param_1,300);
      FUN_80006824(param_1,0x12a);
      FUN_80017698(0x7e,1);
    }
  }
  else if (iVar2 == 0x4517c) {
    uVar1 = FUN_80017690(0xc44);
    if (uVar1 != 0) {
      FUN_80017698(0xc45,1);
    }
  }
  else if (((iVar2 < 0x4517c) && (iVar2 == 0x45178)) && (uVar1 = FUN_80017690(0xc44), uVar1 != 0)) {
    FUN_80017698(0xc43,1);
  }
  *(float *)(param_2 + 0x34) = FLOAT_803e6220;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801dc638
 * EN v1.0 Address: 0x801DC638
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x801DC834
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dc638(void)
{
  int iVar1;
  int iVar2;
  char in_r8;
  int iVar3;
  
  iVar1 = FUN_8028683c();
  iVar2 = *(int *)(iVar1 + 0x4c);
  iVar3 = *(int *)(iVar1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b56c((ushort)*(byte *)(iVar2 + 0x20),(ushort)*(byte *)(iVar2 + 0x21),
                 (ushort)*(byte *)(iVar2 + 0x22));
    FUN_8003b818(iVar1);
    if ((*(byte *)(iVar3 + 0x4c) & 0x80) != 0) {
      iVar2 = 0;
      do {
        ObjPath_GetPointWorldPosition(iVar1,iVar2,(float *)(iVar3 + 0xc),(undefined4 *)(iVar3 + 0x10),
                     (float *)(iVar3 + 0x14),0);
        iVar3 = iVar3 + 0xc;
        iVar2 = iVar2 + 1;
      } while (iVar2 < 3);
    }
    *(undefined4 *)(iVar1 + 0xf8) = 1;
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801dc6e4
 * EN v1.0 Address: 0x801DC6E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801DC900
 * EN v1.1 Size: 1116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dc6e4(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801dc6e8
 * EN v1.0 Address: 0x801DC6E8
 * EN v1.0 Size: 496b
 * EN v1.1 Address: 0x801DCD5C
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dc6e8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_9 + 0x5c);
  *(float *)(iVar3 + 0x34) = FLOAT_803e622c;
  fVar1 = FLOAT_803e6228;
  *(float *)(iVar3 + 0x30) = FLOAT_803e6228;
  *(ushort *)(iVar3 + 0x48) = (ushort)*(byte *)(param_10 + 0x1b) << 1;
  *(undefined *)(iVar3 + 0x4c) = *(undefined *)(param_10 + 0x23);
  *(float *)(iVar3 + 0x3c) = fVar1;
  *(undefined4 *)(iVar3 + 0x38) = *(undefined4 *)(param_10 + 0x1c);
  param_9[2] = (*(byte *)(param_10 + 0x18) - 0x7f) * 0x80;
  param_9[1] = (*(byte *)(param_10 + 0x19) - 0x7f) * 0x80;
  *param_9 = (ushort)*(byte *)(param_10 + 0x1a) << 8;
  *(float *)(param_9 + 4) = FLOAT_803e6250 * *(float *)(param_10 + 0x1c);
  param_9[0x7c] = 0;
  param_9[0x7d] = 0;
  param_9[0x58] = param_9[0x58] | 0x2000;
  uVar2 = FUN_80017760(1,99);
  FUN_800305f8((double)((float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e6260) /
                       FLOAT_803e6254),param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               param_9,0,0,param_12,param_13,param_14,param_15,param_16);
  FUN_8002fc3c((double)FLOAT_803e6224,(double)FLOAT_803e6224);
  FUN_80035d58((int)param_9,(short)(int)(FLOAT_803e6258 * *(float *)(iVar3 + 0x38)),-5,0xff);
  if ((*(byte *)(iVar3 + 0x4c) & 0x80) != 0) {
    *(byte *)(iVar3 + 0x4c) = *(byte *)(iVar3 + 0x4c) | 0x20;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801dc8d8
 * EN v1.0 Address: 0x801DC8D8
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x801DCEC4
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dc8d8(void)
{
  ushort uVar1;
  ushort uVar2;
  int iVar3;
  uint uVar4;
  undefined2 extraout_r4;
  byte bVar5;
  byte bVar6;
  ushort local_28 [20];
  
  iVar3 = FUN_8028683c();
  for (bVar6 = 0; bVar6 < 3; bVar6 = bVar6 + 1) {
    uVar4 = FUN_80017690((uint)*(ushort *)(iVar3 + (uint)bVar6 * 2));
    local_28[bVar6] = (ushort)uVar4;
  }
  local_28[3] = extraout_r4;
  for (bVar6 = 0; bVar6 < 3; bVar6 = bVar6 + 1) {
    for (bVar5 = 0; bVar5 < 3; bVar5 = bVar5 + 1) {
      uVar1 = local_28[bVar5 + 1];
      if (uVar1 != 0) {
        uVar2 = local_28[bVar5];
        if ((uVar1 < uVar2) || (uVar2 == 0)) {
          local_28[bVar5] = uVar1;
          local_28[bVar5 + 1] = uVar2;
        }
      }
    }
  }
  for (bVar6 = 0; bVar6 < 3; bVar6 = bVar6 + 1) {
    FUN_80017698((uint)*(ushort *)(iVar3 + (uint)bVar6 * 2),(uint)local_28[bVar6]);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801dc9e4
 * EN v1.0 Address: 0x801DC9E4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801DCFE8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dc9e4(int param_1)
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
 * Function: FUN_801dca0c
 * EN v1.0 Address: 0x801DCA0C
 * EN v1.0 Size: 648b
 * EN v1.1 Address: 0x801DD01C
 * EN v1.1 Size: 460b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dca0c(uint param_1)
{
  bool bVar1;
  uint uVar2;
  int iVar3;
  uint *puVar4;
  ushort *puVar5;
  double dVar6;
  int local_48;
  int local_44 [9];
  longlong local_20;
  
  puVar5 = *(ushort **)(param_1 + 0xb8);
  *(undefined *)((int)puVar5 + 3) = *(undefined *)(puVar5 + 1);
  uVar2 = FUN_80017690((uint)*puVar5);
  *(char *)(puVar5 + 1) = (char)uVar2;
  if (*(char *)((int)puVar5 + 3) != *(char *)(puVar5 + 1)) {
    if (*(char *)(puVar5 + 1) == '\0') {
      FUN_80006824(param_1,0x3ad);
      *(float *)(puVar5 + 2) = FLOAT_803e6274;
    }
    else {
      FUN_80006824(param_1,0x3ad);
      *(float *)(puVar5 + 2) = FLOAT_803e626c;
      bVar1 = false;
      uVar2 = FUN_80017690(0x81);
      if ((((uVar2 != 0) && (uVar2 = FUN_80017690(0x82), uVar2 != 0)) &&
          (uVar2 = FUN_80017690(0x83), uVar2 != 0)) && (uVar2 = FUN_80017690(0x84), uVar2 != 0)) {
        FUN_80006824(0,0x7e);
        bVar1 = true;
        iVar3 = FUN_80017b00(&local_48,local_44);
        puVar4 = (uint *)(iVar3 + local_48 * 4);
        for (; local_48 < local_44[0]; local_48 = local_48 + 1) {
          if ((*puVar4 != param_1) && (*(short *)(*puVar4 + 0x46) == 0x282)) {
            iVar3 = *(int *)(iVar3 + local_48 * 4);
            (**(code **)(**(int **)(iVar3 + 0x68) + 0x20))(iVar3,6);
            break;
          }
          puVar4 = puVar4 + 1;
        }
        dVar6 = FUN_80006b34();
        local_20 = (longlong)(int)(dVar6 / (double)FLOAT_803e6270);
        FUN_801dc8d8();
      }
      if (!bVar1) {
        FUN_80006824(0,0x109);
      }
    }
  }
  FUN_8002fc3c((double)*(float *)(puVar5 + 2),(double)FLOAT_803dc074);
  ObjHits_PollPriorityHitEffectWithCooldown(param_1,8,0xff,0xff,0x78,0x129,(float *)&DAT_803de888);
  return;
}
