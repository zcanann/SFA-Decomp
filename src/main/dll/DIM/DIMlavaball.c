#include "ghidra_import.h"
#include "main/dll/DIM/DIMlavaball.h"

extern undefined8 FUN_80008b74();
extern undefined8 FUN_80008cbc();
extern undefined4 FUN_8000a538();
extern undefined4 FUN_8000b8a8();
extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000da78();
extern undefined4 FUN_8000e670();
extern undefined4 FUN_80014acc();
extern undefined4 FUN_800168a8();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern undefined4 FUN_80021754();
extern undefined4 FUN_800217c8();
extern undefined4 FUN_80021b8c();
extern uint FUN_80022264();
extern undefined4 FUN_8002ba34();
extern int FUN_8002bac4();
extern int FUN_8002e1f4();
extern undefined4 FUN_80035eec();
extern undefined4 FUN_80035ff8();
extern undefined4 FUN_80036018();
extern int FUN_80036974();
extern void* FUN_80037048();
extern undefined4 FUN_8003709c();
extern undefined4 FUN_800372f8();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80043604();
extern int FUN_8004832c();
extern int FUN_8005b128();
extern int FUN_8005b478();
extern undefined4 FUN_8005cf74();
extern int FUN_80064248();
extern int FUN_80065fcc();
extern undefined4 FUN_80088a84();
extern undefined8 FUN_80088f20();
extern undefined4 FUN_80097568();
extern undefined4 FUN_8009a010();
extern undefined4 FUN_8009adfc();
extern undefined4 FUN_800e85f4();
extern int FUN_800e8a48();
extern undefined4 FUN_8011f6d0();
extern undefined4 FUN_801d84c4();
extern ulonglong FUN_80286830();
extern int FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_802945e0();
extern uint FUN_802979fc();

extern undefined4 DAT_803ad560;
extern undefined4 DAT_803ad568;
extern undefined4 DAT_803ad56c;
extern undefined4 DAT_803ad570;
extern undefined4 DAT_803ad574;
extern undefined4 DAT_803ad578;
extern undefined4 DAT_803ad580;
extern undefined4 DAT_803ad584;
extern undefined4 DAT_803ad588;
extern undefined4 DAT_803ad58c;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd740;
extern undefined4 DAT_803de7ac;
extern undefined4 DAT_803de7b0;
extern undefined4 DAT_803e50f8;
extern undefined4 DAT_803e50fc;
extern f64 DOUBLE_803e5120;
extern f64 DOUBLE_803e5178;
extern f64 DOUBLE_803e5188;
extern f64 DOUBLE_803e51d8;
extern f64 DOUBLE_803e5240;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803de7a8;
extern f32 FLOAT_803e5100;
extern f32 FLOAT_803e5114;
extern f32 FLOAT_803e5150;
extern f32 FLOAT_803e5158;
extern f32 FLOAT_803e5160;
extern f32 FLOAT_803e5168;
extern f32 FLOAT_803e516c;
extern f32 FLOAT_803e5170;
extern f32 FLOAT_803e5180;
extern f32 FLOAT_803e5190;
extern f32 FLOAT_803e5194;
extern f32 FLOAT_803e5198;
extern f32 FLOAT_803e519c;
extern f32 FLOAT_803e51a0;
extern f32 FLOAT_803e51a4;
extern f32 FLOAT_803e51a8;
extern f32 FLOAT_803e51ac;
extern f32 FLOAT_803e51b0;
extern f32 FLOAT_803e51b4;
extern f32 FLOAT_803e51bc;
extern f32 FLOAT_803e51c0;
extern f32 FLOAT_803e51c4;
extern f32 FLOAT_803e51c8;
extern f32 FLOAT_803e51cc;
extern f32 FLOAT_803e51d0;
extern f32 FLOAT_803e51d4;
extern f32 FLOAT_803e51e0;
extern f32 FLOAT_803e51e4;
extern f32 FLOAT_803e51e8;
extern f32 FLOAT_803e51ec;
extern f32 FLOAT_803e51f0;
extern f32 FLOAT_803e51f4;
extern f32 FLOAT_803e51f8;
extern f32 FLOAT_803e51fc;
extern f32 FLOAT_803e5200;
extern f32 FLOAT_803e5204;
extern f32 FLOAT_803e5208;
extern f32 FLOAT_803e520c;
extern f32 FLOAT_803e5210;
extern f32 FLOAT_803e5214;
extern f32 FLOAT_803e5218;
extern f32 FLOAT_803e521c;
extern f32 FLOAT_803e5220;
extern f32 FLOAT_803e5224;
extern f32 FLOAT_803e5228;
extern f32 FLOAT_803e522c;
extern f32 FLOAT_803e5238;

/*
 * --INFO--
 *
 * Function: FUN_801a6ad0
 * EN v1.0 Address: 0x801A6AD0
 * EN v1.0 Size: 284b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a6ad0(int param_1,int param_2)
{
  float fVar1;
  double dVar2;
  int iVar3;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  uint uStack_c;
  undefined4 local_8;
  uint uStack_4;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  local_18 = DAT_803e50f8;
  local_14 = DAT_803e50fc;
  *(undefined4 *)(param_2 + 0x14) = 0xffffffff;
  *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
  *(undefined2 *)(param_1 + 4) = 0x4000;
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(param_1 + 0x18) = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(param_1 + 0x1c) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_2 + 0x10);
  *(undefined4 *)(param_1 + 0x20) = *(undefined4 *)(param_2 + 0x10);
  dVar2 = DOUBLE_803e5120;
  fVar1 = FLOAT_803e5114;
  uStack_c = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
  local_10 = 0x43300000;
  *(float *)(iVar3 + 0x10c) =
       (float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e5120) / FLOAT_803e5114;
  uStack_4 = (int)*(short *)(param_2 + 0x1c) ^ 0x80000000;
  local_8 = 0x43300000;
  *(float *)(iVar3 + 0x108) = (float)((double)CONCAT44(0x43300000,uStack_4) - dVar2) / fVar1;
  *(undefined *)(iVar3 + 0x114) = 0;
  *(undefined *)(iVar3 + 0x115) = 1;
  *(float *)(iVar3 + 0x110) = FLOAT_803e5100;
  (**(code **)(*DAT_803dd71c + 0x8c))((double)FLOAT_803e5150,iVar3,param_1,&local_18,0xffffffff);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a6bec
 * EN v1.0 Address: 0x801A6BEC
 * EN v1.0 Size: 212b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801a6bec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  byte bVar1;
  undefined4 uVar2;
  int iVar3;
  
  uVar2 = FUN_8002bac4();
  *(undefined *)(param_11 + 0x56) = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar3 = iVar3 + 1) {
    bVar1 = *(byte *)(param_11 + iVar3 + 0x81);
    if (bVar1 == 2) {
      param_1 = FUN_80008cbc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                             ,uVar2,0x138,0,param_13,param_14,param_15,param_16);
    }
    else if ((bVar1 < 2) && (bVar1 != 0)) {
      param_1 = FUN_80008cbc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                             ,uVar2,0x13b,0,param_13,param_14,param_15,param_16);
    }
  }
  FUN_801a6d2c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801a6cc0
 * EN v1.0 Address: 0x801A6CC0
 * EN v1.0 Size: 56b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a6cc0(void)
{
  FLOAT_803de7a8 = FLOAT_803e5158;
  DAT_803de7ac = 0;
  FUN_8000a538((int *)0xd5,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a6cf8
 * EN v1.0 Address: 0x801A6CF8
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a6cf8(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a6d2c
 * EN v1.0 Address: 0x801A6D2C
 * EN v1.0 Size: 972b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a6d2c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar4;
  undefined8 uVar5;
  
  iVar1 = FUN_8002bac4();
  uVar2 = FUN_8002bac4();
  dVar4 = (double)FLOAT_803de7a8;
  if ((double)FLOAT_803e5158 < dVar4) {
    FUN_800168a8(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x34f);
    FLOAT_803de7a8 = FLOAT_803de7a8 - FLOAT_803dc074;
    dVar4 = (double)FLOAT_803de7a8;
    if (dVar4 < (double)FLOAT_803e5158) {
      FLOAT_803de7a8 = FLOAT_803e5158;
    }
  }
  if (*(int *)(param_9 + 0xf4) != 0) {
    FUN_80088a84(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
    uVar3 = FUN_80020078(0xd47);
    if (uVar3 == 0) {
      uVar3 = FUN_80020078(0xf33);
      if (uVar3 == 0) {
        param_2 = (double)*(float *)(iVar1 + 0x14);
        iVar1 = FUN_8005b128();
        if (iVar1 == 0x12) {
          uVar5 = FUN_80088f20(7,'\0');
          if (*(int *)(param_9 + 0xf4) == 2) {
            uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 param_9,uVar2,0x13a,0,in_r7,in_r8,in_r9,in_r10);
            uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 param_9,uVar2,0x138,0,in_r7,in_r8,in_r9,in_r10);
            FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2
                         ,0x139,0,in_r7,in_r8,in_r9,in_r10);
          }
          else {
            uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 param_9,uVar2,0x13a,0,in_r7,in_r8,in_r9,in_r10);
            uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 param_9,uVar2,0x138,0,in_r7,in_r8,in_r9,in_r10);
            FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2
                         ,0x139,0,in_r7,in_r8,in_r9,in_r10);
          }
          *(undefined4 *)(param_9 + 0xf8) = 0;
        }
      }
      else {
        uVar5 = FUN_80088f20(7,'\x01');
        if (*(int *)(param_9 + 0xf4) == 2) {
          uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                               ,uVar2,0x13a,0,in_r7,in_r8,in_r9,in_r10);
          uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                               ,uVar2,0x10c,0,in_r7,in_r8,in_r9,in_r10);
          FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2,
                       0x10d,0,in_r7,in_r8,in_r9,in_r10);
        }
        else {
          uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                               ,uVar2,0x13a,0,in_r7,in_r8,in_r9,in_r10);
          uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                               ,uVar2,0x10c,0,in_r7,in_r8,in_r9,in_r10);
          FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2,
                       0x10d,0,in_r7,in_r8,in_r9,in_r10);
        }
        *(undefined4 *)(param_9 + 0xf8) = 1;
      }
    }
    else {
      uVar5 = FUN_80088f20(7,'\x01');
      if (*(int *)(param_9 + 0xf4) == 2) {
        uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             uVar2,0x13a,0,in_r7,in_r8,in_r9,in_r10);
        uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             uVar2,0x234,0,in_r7,in_r8,in_r9,in_r10);
        FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2,
                     0x235,0,in_r7,in_r8,in_r9,in_r10);
      }
      else {
        uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             uVar2,0x13a,0,in_r7,in_r8,in_r9,in_r10);
        uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             uVar2,0x234,0,in_r7,in_r8,in_r9,in_r10);
        FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2,
                     0x235,0,in_r7,in_r8,in_r9,in_r10);
      }
      *(undefined4 *)(param_9 + 0xf8) = 0;
    }
    FUN_8000a538((int *)0x31,1);
    *(undefined4 *)(param_9 + 0xf4) = 0;
  }
  if ((*(int *)(param_9 + 0xf8) == 0) || (uVar3 = FUN_80020078(0xf33), uVar3 != 0)) {
    if ((*(int *)(param_9 + 0xf8) == 0) && (uVar3 = FUN_80020078(0xf33), uVar3 != 0)) {
      uVar5 = FUN_80088f20(7,'\x01');
      uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           uVar2,0x13a,0,in_r7,in_r8,in_r9,in_r10);
      uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           uVar2,0x10c,0,in_r7,in_r8,in_r9,in_r10);
      FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2,0x10d
                   ,0,in_r7,in_r8,in_r9,in_r10);
      *(undefined4 *)(param_9 + 0xf8) = 1;
    }
  }
  else {
    uVar5 = FUN_80088f20(7,'\0');
    uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2
                         ,0x13a,0,in_r7,in_r8,in_r9,in_r10);
    uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2
                         ,0x138,0,in_r7,in_r8,in_r9,in_r10);
    FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2,0x139,0
                 ,in_r7,in_r8,in_r9,in_r10);
    *(undefined4 *)(param_9 + 0xf8) = 0;
  }
  FUN_801d84c4(&DAT_803de7ac,1,-1,-1,0x389,(int *)0xd5);
  FUN_801d84c4(&DAT_803de7ac,2,-1,-1,0xcbb,(int *)0xc4);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a70f8
 * EN v1.0 Address: 0x801A70F8
 * EN v1.0 Size: 228b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a70f8(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801a71dc
 * EN v1.0 Address: 0x801A71DC
 * EN v1.0 Size: 328b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a71dc(undefined4 param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  char *pcVar7;
  
  iVar2 = FUN_8028683c();
  pcVar7 = *(char **)(iVar2 + 0xb8);
  iVar6 = *(int *)(iVar2 + 0x4c);
  if ((*pcVar7 == '\0') && (uVar3 = FUN_80020078((int)*(short *)(iVar6 + 0x18)), uVar3 != 0)) {
    *pcVar7 = '\x02';
  }
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar5 = iVar5 + 1) {
    bVar1 = *(byte *)(param_3 + iVar5 + 0x81);
    if (bVar1 == 2) {
      (**(code **)(*DAT_803dd708 + 8))(iVar2,0x70b,0,2,0xffffffff,0);
      iVar4 = 0;
      do {
        (**(code **)(*DAT_803dd708 + 8))(iVar2,0x70c,0,2,0xffffffff,0);
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0x28);
    }
    else if ((bVar1 < 2) && (bVar1 != 0)) {
      *pcVar7 = '\x01';
      uVar3 = (uint)*(short *)(iVar6 + 0x1a);
      if (uVar3 != 0xffffffff) {
        FUN_800201ac(uVar3,1);
      }
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a7324
 * EN v1.0 Address: 0x801A7324
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a7324(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a7358
 * EN v1.0 Address: 0x801A7358
 * EN v1.0 Size: 204b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a7358(int param_1)
{
  uint uVar1;
  int iVar2;
  char *pcVar3;
  
  pcVar3 = *(char **)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
  if ((pcVar3[1] & 1U) != 0) {
    if ((*(short *)(iVar2 + 0x1c) == 0) || (*pcVar3 == '\0')) {
      uVar1 = 0xffffffff;
    }
    else {
      uVar1 = (uint)*(byte *)(iVar2 + 0x20);
      (**(code **)(*DAT_803dd6d4 + 0x54))();
    }
    if (*(char *)(iVar2 + 0x1e) != -1) {
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar2 + 0x1e),param_1,uVar1);
    }
    pcVar3[1] = pcVar3[1] & 0xfe;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a7424
 * EN v1.0 Address: 0x801A7424
 * EN v1.0 Size: 220b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a7424(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801a7500
 * EN v1.0 Address: 0x801A7500
 * EN v1.0 Size: 420b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801a7500(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,
            undefined4 param_10,int param_11)
{
  byte bVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  
  pbVar4 = *(byte **)(param_9 + 0xb8);
  *(undefined *)(param_11 + 0x56) = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar3 = iVar3 + 1) {
    bVar1 = *(byte *)(param_11 + iVar3 + 0x81);
    if (bVar1 == 2) {
      *pbVar4 = *pbVar4 & 0xf6;
      *pbVar4 = *pbVar4 | 0x30;
      *(undefined *)(param_9 + 0xad) = 1;
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        param_1 = FUN_8005cf74(0);
      }
      else {
        *pbVar4 = 0xd;
        pbVar4[1] = 1;
        param_1 = FUN_800201ac(0x87b,(uint)pbVar4[1]);
        *(undefined *)(param_9 + 0x36) = 0xff;
      }
    }
    else if (bVar1 == 4) {
      *(float *)(pbVar4 + 4) = FLOAT_803e5180;
      param_1 = FUN_8005cf74(1);
    }
    else if (bVar1 < 4) {
      *pbVar4 = *pbVar4 & 0xdf;
      *pbVar4 = *pbVar4 | 0x50;
      uVar2 = FUN_80022264(10,0x3c);
      *(float *)(pbVar4 + 8) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5188);
      pbVar4[1] = 1;
      param_1 = FUN_800201ac(0x87b,(uint)pbVar4[1]);
    }
  }
  *pbVar4 = *pbVar4 | 0x80;
  FUN_801a76d8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801a76a4
 * EN v1.0 Address: 0x801A76A4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a76a4(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a76d8
 * EN v1.0 Address: 0x801A76D8
 * EN v1.0 Size: 1660b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a76d8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  double dVar5;
  undefined8 local_38;
  
  pbVar4 = *(byte **)(param_9 + 0xb8);
  if ((*pbVar4 & 0x80) == 0) {
    uVar2 = FUN_80020078(0xd52);
    if (uVar2 == 0) {
      uVar2 = FUN_80020078(0x88c);
      pbVar4[2] = (byte)uVar2;
    }
    else {
      pbVar4[2] = 1;
    }
    pbVar4[1] = 2;
    FUN_8000da78(param_9,0x107);
    uVar2 = (uint)pbVar4[2] * 0x20 + 0x20;
    if (0x7f < uVar2) {
      uVar2 = 0x7f;
    }
    FUN_8000b8a8((double)FLOAT_803e5194,param_9,0x40,(byte)uVar2);
    if (pbVar4[2] != 0) {
      fVar1 = *(float *)(param_9 + 0x28);
      if (FLOAT_803e5198 *
          ((*(float *)(pbVar4 + 0xc) + *(float *)((uint)pbVar4[2] * 4 + -0x7fcdc1f0)) -
          *(float *)(param_9 + 0x10)) <= fVar1) {
        *(float *)(param_9 + 0x28) = -(FLOAT_803e51a0 * FLOAT_803dc074 - fVar1);
      }
      else {
        *(float *)(param_9 + 0x28) = FLOAT_803e519c * FLOAT_803dc074 + fVar1;
      }
      dVar5 = DOUBLE_803e51d8;
      *(short *)(pbVar4 + 0x14) =
           (short)(int)(FLOAT_803e51a4 * FLOAT_803dc074 +
                       (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(pbVar4 + 0x14)) -
                              DOUBLE_803e51d8));
      local_38 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(pbVar4 + 0x16));
      *(short *)(pbVar4 + 0x16) =
           (short)(int)(FLOAT_803e51a8 * FLOAT_803dc074 + (float)(local_38 - dVar5));
      *(short *)(pbVar4 + 0x18) =
           (short)(int)(FLOAT_803e51ac * FLOAT_803dc074 +
                       (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(pbVar4 + 0x18)) - dVar5
                              ));
      param_3 = (double)FLOAT_803e51b0;
      FUN_8002ba34(param_3,(double)(*(float *)(param_9 + 0x28) * FLOAT_803dc074),param_3,param_9);
      dVar5 = (double)FUN_802945e0();
      *(float *)(param_9 + 0x10) = (float)((double)*(float *)(param_9 + 0x10) + dVar5);
      if (*(float *)(param_9 + 0x10) < *(float *)(pbVar4 + 0xc)) {
        *(float *)(param_9 + 0x10) = *(float *)(pbVar4 + 0xc);
      }
      dVar5 = (double)FUN_802945e0();
      *(short *)(param_9 + 4) =
           *(short *)(param_9 + 4) + (short)(int)((double)FLOAT_803e51bc * dVar5);
      param_2 = (double)FLOAT_803e51b4;
      dVar5 = (double)FUN_802945e0();
      *(short *)(param_9 + 2) =
           *(short *)(param_9 + 2) + (short)(int)((double)FLOAT_803e51bc * dVar5);
      DAT_803ad568 = FLOAT_803e5190;
      DAT_803ad56c = *(undefined4 *)(param_9 + 0xc);
      DAT_803ad570 = *(float *)(pbVar4 + 0xc) - FLOAT_803e51c0;
      DAT_803ad574 = *(undefined4 *)(param_9 + 0x14);
      DAT_803de7b0 = (int)(*(float *)(param_9 + 0x10) - *(float *)(pbVar4 + 0xc));
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x722,0,2,0xffffffff,&DAT_803de7b0);
      (**(code **)(*DAT_803dd708 + 8))
                (param_9,0x723,&DAT_803ad560,0x200001,0xffffffff,&DAT_803de7b0);
      (**(code **)(*DAT_803dd708 + 8))
                (param_9,0x723,&DAT_803ad560,0x200001,0xffffffff,&DAT_803de7b0);
    }
  }
  if (*pbVar4 != 0) {
    if ((*pbVar4 & 1) != 0) {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x716,0,1,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x716,0,1,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x716,0,1,0xffffffff,0);
    }
    if ((*pbVar4 & 8) != 0) {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x71a,0,2,0xffffffff,0);
    }
    if ((*pbVar4 & 0x10) != 0) {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x71b,0,1,0xffffffff,0);
      iVar3 = 0x28;
      do {
        (**(code **)(*DAT_803dd708 + 8))(param_9,0x71c,0,1,0xffffffff,0);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
      FUN_8009adfc((double)FLOAT_803e51c4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,1,1,0,1,0,1,0);
      FUN_8000e670((double)FLOAT_803e51c8,(double)FLOAT_803e51cc,(double)FLOAT_803e51d0);
      FUN_80014acc((double)FLOAT_803e51d4);
      *pbVar4 = *pbVar4 & 0xef;
    }
    if ((*pbVar4 & 0x20) != 0) {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x71d,0,1,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x71d,0,1,0xffffffff,0);
    }
    if (((*pbVar4 & 0x40) != 0) &&
       (*(float *)(pbVar4 + 8) = *(float *)(pbVar4 + 8) - FLOAT_803dc074,
       *(float *)(pbVar4 + 8) < FLOAT_803e51b0)) {
      uVar2 = FUN_80022264(10,0x3c);
      *(float *)(pbVar4 + 8) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5188);
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x71e,0,1,0xffffffff,0);
    }
  }
  fVar1 = FLOAT_803e51b0;
  if (FLOAT_803e51b0 < *(float *)(pbVar4 + 4)) {
    *(float *)(pbVar4 + 4) = *(float *)(pbVar4 + 4) - FLOAT_803dc074;
    if (*(float *)(pbVar4 + 4) <= fVar1) {
      FUN_800201ac(0x88b,0);
    }
  }
  *pbVar4 = *pbVar4 & 0x7f;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a7d54
 * EN v1.0 Address: 0x801A7D54
 * EN v1.0 Size: 296b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a7d54(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801a7e7c
 * EN v1.0 Address: 0x801A7E7C
 * EN v1.0 Size: 280b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_801a7e7c(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5,
                float *param_6,undefined4 *param_7)
{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  double dVar5;
  undefined4 *local_38 [4];
  
  iVar2 = FUN_80065fcc(param_1,param_2,param_3,param_5,local_38,0,1);
  *param_6 = (float)param_2;
  *param_7 = 0;
  iVar4 = 0;
  iVar1 = iVar2 + -1;
  puVar3 = local_38[0];
  if (0 < iVar2) {
    do {
      if (((*(char *)((float *)*puVar3 + 5) != '\x0e') &&
          (dVar5 = (double)*(float *)*puVar3, param_2 < dVar5)) &&
         ((dVar5 < param_4 || (iVar4 == iVar1)))) {
        *param_7 = *(undefined4 *)(local_38[0][iVar4] + 0x10);
        *param_6 = *(float *)local_38[0][iVar4];
        return 1 - ((int)((uint)(byte)((*(float *)(local_38[0][iVar4] + 8) < FLOAT_803e51e0) << 3)
                         << 0x1c) >> 0x1f);
      }
      puVar3 = puVar3 + 1;
      iVar4 = iVar4 + 1;
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801a7f94
 * EN v1.0 Address: 0x801A7F94
 * EN v1.0 Size: 304b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a7f94(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int *param_9)
{
  int iVar1;
  int iVar2;
  undefined4 uStack_60;
  int aiStack_5c [21];
  
  iVar2 = param_9[0x2e];
  iVar1 = FUN_80036974((int)param_9,&uStack_60,(int *)0x0,(uint *)0x0);
  if (iVar1 == 0) {
    iVar1 = FUN_80064248(param_9 + 0x20,param_9 + 3,(float *)0x1,aiStack_5c,param_9,1,0xffffffff,
                         0xff,0);
  }
  if ((iVar1 != 0) ||
     (((*(char *)(param_9[0x15] + 0xad) != '\0' && ((*(ushort *)(iVar2 + 0x24) & 0x40) != 0)) ||
      ((*(ushort *)(iVar2 + 0x24) & 0x100) != 0)))) {
    param_9[4] = (int)((float)param_9[4] + FLOAT_803e51e8);
    FUN_8009adfc((double)FLOAT_803e51ec,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,1,1,0,0,0,1,0);
    *(ushort *)(iVar2 + 0x24) = *(ushort *)(iVar2 + 0x24) | 0x200;
    *(float *)(iVar2 + 0x14) = FLOAT_803e51f0;
    *(undefined *)((int)param_9 + 0x36) = 0;
    param_9[3] = *(int *)(iVar2 + 0x18);
    param_9[4] = *(int *)(iVar2 + 0x1c);
    param_9[5] = *(int *)(iVar2 + 0x20);
    FUN_800e85f4((int)param_9);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a80c4
 * EN v1.0 Address: 0x801A80C4
 * EN v1.0 Size: 436b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a80c4(int param_1)
{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  float local_18;
  undefined4 auStack_14 [3];
  
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar3 = FUN_8005b478((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
  if (iVar3 != -1) {
    FUN_80035eec(param_1,0xe,1,0);
    FUN_80036018(param_1);
    *(float *)(param_1 + 0x28) = -(FLOAT_803e51f4 * FLOAT_803dc074 - *(float *)(param_1 + 0x28));
    fVar1 = *(float *)(param_1 + 0x24);
    fVar2 = FLOAT_803e51f8;
    if ((FLOAT_803e51f8 <= fVar1) && (fVar2 = fVar1, FLOAT_803e51fc < fVar1)) {
      fVar2 = FLOAT_803e51fc;
    }
    *(float *)(param_1 + 0x24) = fVar2;
    fVar1 = *(float *)(param_1 + 0x28);
    fVar2 = FLOAT_803e51f8;
    if ((FLOAT_803e51f8 <= fVar1) && (fVar2 = fVar1, FLOAT_803e51fc < fVar1)) {
      fVar2 = FLOAT_803e51fc;
    }
    *(float *)(param_1 + 0x28) = fVar2;
    fVar1 = *(float *)(param_1 + 0x24);
    fVar2 = FLOAT_803e51f8;
    if ((FLOAT_803e51f8 <= fVar1) && (fVar2 = fVar1, FLOAT_803e51fc < fVar1)) {
      fVar2 = FLOAT_803e51fc;
    }
    *(float *)(param_1 + 0x24) = fVar2;
    FUN_8002ba34((double)(*(float *)(param_1 + 0x24) * FLOAT_803dc074),
                 (double)(*(float *)(param_1 + 0x28) * FLOAT_803dc074),
                 (double)(*(float *)(param_1 + 0x2c) * FLOAT_803dc074),param_1);
    *(ushort *)(iVar4 + 0x24) = *(ushort *)(iVar4 + 0x24) & 0xff7f;
    iVar3 = FUN_801a7e7c((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                         (double)*(float *)(param_1 + 0x14),
                         (double)(float)((double)FLOAT_803e5200 + (double)*(float *)(param_1 + 0x10)
                                        ),param_1,&local_18,auStack_14);
    if (iVar3 != 0) {
      if (iVar3 == 2) {
        *(ushort *)(iVar4 + 0x24) = *(ushort *)(iVar4 + 0x24) | 0x100;
        fVar1 = FLOAT_803e51ec;
        *(float *)(param_1 + 0x24) = FLOAT_803e51ec;
        *(float *)(param_1 + 0x28) = fVar1;
        *(float *)(param_1 + 0x2c) = fVar1;
      }
      else {
        *(ushort *)(iVar4 + 0x24) = *(ushort *)(iVar4 + 0x24) | 0x180;
        *(float *)(param_1 + 0x10) = local_18;
        fVar1 = FLOAT_803e51ec;
        *(float *)(param_1 + 0x24) = FLOAT_803e51ec;
        *(float *)(param_1 + 0x28) = fVar1;
        *(float *)(param_1 + 0x2c) = fVar1;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a8278
 * EN v1.0 Address: 0x801A8278
 * EN v1.0 Size: 176b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a8278(int param_1)
{
  ushort *puVar1;
  int iVar2;
  int iVar3;
  ushort local_28 [4];
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  puVar1 = (ushort *)FUN_8002bac4();
  local_1c = FLOAT_803e51ec;
  iVar2 = *(int *)(puVar1 + 0x5c);
  *(float *)(param_1 + 0x24) = FLOAT_803e51ec;
  *(float *)(param_1 + 0x28) = FLOAT_803e5208 * *(float *)(iVar2 + 0x298) + FLOAT_803e5204;
  *(float *)(param_1 + 0x2c) = FLOAT_803e5210 * *(float *)(iVar2 + 0x298) + FLOAT_803e520c;
  local_18 = local_1c;
  local_14 = local_1c;
  local_20 = FLOAT_803e5214;
  local_28[2] = 0;
  local_28[1] = 0;
  local_28[0] = *puVar1;
  FUN_80021b8c(local_28,(float *)(param_1 + 0x24));
  *(ushort *)(iVar3 + 0x24) = *(ushort *)(iVar3 + 0x24) | 0x40;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a8328
 * EN v1.0 Address: 0x801A8328
 * EN v1.0 Size: 848b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a8328(undefined4 param_1,undefined4 param_2,uint param_3)
{
  char cVar1;
  undefined4 uVar2;
  char cVar4;
  ushort uVar3;
  int iVar5;
  int iVar6;
  uint uVar7;
  char cVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  double dVar12;
  ulonglong uVar13;
  int local_38;
  int local_34 [13];
  
  uVar13 = FUN_80286830();
  iVar5 = (int)(uVar13 >> 0x20);
  iVar11 = *(int *)(iVar5 + 0xb8);
  iVar6 = FUN_8002e1f4(local_34,&local_38);
  for (; local_34[0] < local_38; local_34[0] = local_34[0] + 1) {
    iVar9 = *(int *)(iVar6 + local_34[0] * 4);
    if (((iVar9 != iVar5) && (*(short *)(iVar9 + 0x46) == 0x518)) &&
       (dVar12 = (double)FUN_800217c8((float *)(iVar5 + 0x18),(float *)(iVar9 + 0x18)),
       dVar12 < (double)FLOAT_803e5218)) {
      iVar10 = *(int *)(*(int *)(iVar6 + local_34[0] * 4) + 0x4c);
      iVar9 = *(int *)(iVar5 + 0x4c);
      uVar7 = FUN_80020078(0x88c);
      cVar4 = (char)uVar7;
      uVar7 = FUN_80020078(0x894);
      cVar8 = (char)uVar7;
      if ((uVar13 & 0xff) == 0) {
        (**(code **)(*DAT_803dd740 + 0x20))(iVar11,1);
        if ((int)*(short *)(iVar10 + 0x1e) != 0xffffffff) {
          FUN_800201ac((int)*(short *)(iVar10 + 0x1e),0);
        }
        cVar1 = *(char *)(iVar11 + 0x2e);
        if (((cVar1 == '\x03') || (cVar1 == '\x04')) || (cVar1 == '\x06')) {
          cVar4 = cVar4 + -1;
        }
        else {
          cVar8 = cVar8 + -1;
        }
        uVar7 = (uint)*(short *)(iVar9 + 0x1a);
        if (uVar7 != 0xffffffff) {
          FUN_800201ac(uVar7,0);
          *(undefined *)(iVar11 + 0x2e) = 0;
        }
        uVar2 = *(undefined4 *)(iVar5 + 0x10);
        *(undefined4 *)(iVar11 + 0xc) = uVar2;
        *(undefined4 *)(iVar11 + 0x10) = uVar2;
        *(ushort *)(iVar11 + 0x24) = *(ushort *)(iVar11 + 0x24) & 0xfbff;
        *(undefined4 *)(iVar5 + 0xc) = *(undefined4 *)(iVar11 + 0x18);
        *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(iVar11 + 0x1c);
        *(undefined4 *)(iVar5 + 0x14) = *(undefined4 *)(iVar11 + 0x20);
        FUN_800e85f4(iVar5);
      }
      else {
        (**(code **)(*DAT_803dd740 + 0x20))(iVar11,0);
        if ((int)*(short *)(iVar10 + 0x1e) != 0xffffffff) {
          FUN_800201ac((int)*(short *)(iVar10 + 0x1e),1);
        }
        if ((param_3 & 0xff) == 0) {
          *(undefined4 *)(iVar5 + 0xc) = *(undefined4 *)(*(int *)(iVar6 + local_34[0] * 4) + 0xc);
          *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(*(int *)(iVar6 + local_34[0] * 4) + 0x10);
          *(undefined4 *)(iVar5 + 0x14) = *(undefined4 *)(*(int *)(iVar6 + local_34[0] * 4) + 0x14);
          FUN_800e85f4(iVar5);
        }
        uVar2 = *(undefined4 *)(iVar5 + 0x10);
        *(undefined4 *)(iVar11 + 0xc) = uVar2;
        *(undefined4 *)(iVar11 + 0x10) = uVar2;
        uVar7 = (uint)*(short *)(iVar9 + 0x1a);
        if (uVar7 != 0xffffffff) {
          FUN_800201ac(uVar7,(int)*(short *)(iVar10 + 0x1a));
          *(char *)(iVar11 + 0x2e) = (char)*(undefined2 *)(iVar10 + 0x1a);
        }
        cVar1 = *(char *)(iVar11 + 0x2e);
        if (((cVar1 == '\x03') || (cVar1 == '\x04')) || (cVar1 == '\x06')) {
          if ((param_3 & 0xff) != 2) {
            cVar4 = cVar4 + '\x01';
          }
          if ((param_3 & 0xff) == 0) {
            if (cVar4 < '\x03') {
              uVar3 = 0x109;
            }
            else {
              uVar3 = 0x7e;
            }
            FUN_8000bb38(0,uVar3);
            FUN_800201ac(0x9ae,1);
          }
          *(ushort *)(iVar11 + 0x24) = *(ushort *)(iVar11 + 0x24) | 0x400;
          FUN_8011f6d0(0);
        }
        else if ((param_3 & 0xff) != 2) {
          cVar8 = cVar8 + '\x01';
        }
      }
      if (cVar4 < '\x03') {
        FUN_800201ac(0x89b,0);
      }
      else {
        FUN_800201ac(0x89b,1);
      }
      if (cVar4 < '\x04') {
        if (cVar4 < '\0') {
          cVar4 = '\0';
        }
      }
      else {
        cVar4 = '\x03';
      }
      if (cVar8 < '\x04') {
        if (cVar8 < '\0') {
          cVar8 = '\0';
        }
      }
      else {
        cVar8 = '\x03';
      }
      FUN_800201ac(0x88c,(int)cVar4);
      FUN_800201ac(0x894,(int)cVar8);
    }
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a8678
 * EN v1.0 Address: 0x801A8678
 * EN v1.0 Size: 44b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a8678(double param_1,double param_2,double param_3,int param_4)
{
  *(float *)(param_4 + 0xc) = (float)param_1;
  *(float *)(param_4 + 0x10) = (float)param_2;
  *(float *)(param_4 + 0x14) = (float)param_3;
  FUN_800e85f4(param_4);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a86a4
 * EN v1.0 Address: 0x801A86A4
 * EN v1.0 Size: 104b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a86a4(int param_1,char param_2)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (param_2 != '\0') {
    *(ushort *)(iVar1 + 0x24) = *(ushort *)(iVar1 + 0x24) | 4;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    return;
  }
  *(ushort *)(iVar1 + 0x24) = *(ushort *)(iVar1 + 0x24) & 0xfffb;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a870c
 * EN v1.0 Address: 0x801A870C
 * EN v1.0 Size: 72b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a870c(int param_1)
{
  FUN_8003709c(param_1,4);
  (**(code **)(*DAT_803dd740 + 0x10))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a8754
 * EN v1.0 Address: 0x801A8754
 * EN v1.0 Size: 128b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a8754(void)
{
  int iVar1;
  int iVar2;
  char in_r8;
  
  iVar1 = FUN_80286840();
  iVar2 = (**(code **)(*DAT_803dd740 + 0xc))(iVar1,(int)in_r8);
  if (iVar2 != 0) {
    FUN_8003b9ec(iVar1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a87d4
 * EN v1.0 Address: 0x801A87D4
 * EN v1.0 Size: 1736b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a87d4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801a8e9c
 * EN v1.0 Address: 0x801A8E9C
 * EN v1.0 Size: 360b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a8e9c(int param_1,int param_2)
{
  char cVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  *(undefined2 *)(iVar4 + 0x24) = 0;
  uVar3 = FUN_80020078((int)*(short *)(param_2 + 0x1a));
  *(char *)(iVar4 + 0x2e) = (char)uVar3;
  cVar1 = *(char *)(iVar4 + 0x2e);
  if (cVar1 == '\0') {
    (**(code **)(*DAT_803dd740 + 0x20))(iVar4,1);
  }
  else {
    if (((byte)(cVar1 - 3U) < 2) || (cVar1 == '\x06')) {
      *(ushort *)(iVar4 + 0x24) = *(ushort *)(iVar4 + 0x24) | 0x400;
    }
    (**(code **)(*DAT_803dd740 + 0x20))(iVar4,0);
  }
  uVar2 = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(iVar4 + 0xc) = uVar2;
  *(undefined4 *)(iVar4 + 0x10) = uVar2;
  (**(code **)(*DAT_803dd740 + 4))(param_1,*(undefined4 *)(param_1 + 0xb8),0x32);
  (**(code **)(*DAT_803dd740 + 0x2c))(iVar4,1);
  FUN_800372f8(param_1,4);
  *(undefined4 *)(iVar4 + 0x18) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(iVar4 + 0x1c) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(iVar4 + 0x20) = *(undefined4 *)(param_1 + 0x14);
  FUN_80035ff8(param_1);
  FUN_801a8328(param_1,1,2);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a9004
 * EN v1.0 Address: 0x801A9004
 * EN v1.0 Size: 64b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a9004(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}
