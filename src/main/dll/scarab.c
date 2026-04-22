#include "ghidra_import.h"
#include "main/dll/scarab.h"

extern undefined8 FUN_80003494();
extern undefined8 FUN_8000bb38();
extern undefined4 FUN_8000e69c();
extern undefined4 FUN_8000faec();
extern undefined4 FUN_8000faf8();
extern int FUN_80010340();
extern undefined4 FUN_800122b4();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern uint FUN_80021884();
extern uint FUN_80022264();
extern undefined4 FUN_8002ba34();
extern int FUN_8002ba84();
extern int FUN_8002bac4();
extern void* FUN_8002becc();
extern undefined4 FUN_8002cc9c();
extern int FUN_8002e088();
extern uint FUN_8002e144();
extern int FUN_8002e1f4();
extern undefined4 FUN_8003042c();
extern undefined4 FUN_80033a34();
extern undefined4 FUN_80035a6c();
extern undefined4 FUN_80035eec();
extern undefined4 FUN_80035ff8();
extern undefined4 FUN_80036018();
extern int FUN_80036974();
extern undefined8 FUN_8003709c();
extern undefined8 FUN_800377d0();
extern undefined4 FUN_800379bc();
extern undefined4 FUN_800395a4();
extern undefined4 FUN_8003b408();
extern undefined4 FUN_8003b6d8();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_8009a010();
extern undefined4 FUN_8015b3bc();
extern undefined4 FUN_8015b74c();
extern undefined4 FUN_8015b9d0();
extern undefined4 FUN_8015ba78();
extern undefined4 FUN_8015bac0();
extern undefined4 FUN_8015bb1c();
extern undefined4 FUN_8015bbf4();
extern undefined4 FUN_8015bc98();
extern undefined4 FUN_8015be64();
extern undefined4 FUN_8015bfac();
extern undefined4 FUN_8015c0c4();
extern undefined4 FUN_8015c1d8();
extern undefined4 FUN_8015c2b4();
extern undefined4 FUN_8015c3a0();
extern undefined4 FUN_8015c44c();
extern undefined4 FUN_8015c560();
extern undefined4 FUN_8015c758();
extern undefined4 FUN_8015c958();
extern undefined4 FUN_8015ca70();
extern undefined4 FUN_8015cb60();
extern undefined4 FUN_8015cc74();
extern undefined4 FUN_8015ce08();
extern undefined4 FUN_8015d07c();
extern undefined4 FUN_8015d314();
extern undefined4 FUN_8015d544();
extern undefined4 FUN_8015d728();
extern undefined8 FUN_80286838();
extern undefined4 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();

extern undefined4 DAT_803209f0;
extern undefined4 DAT_80320a68;
extern undefined4 DAT_80320af8;
extern undefined4 DAT_80320b70;
extern undefined4 DAT_80320bd0;
extern undefined4 DAT_80320c58;
extern undefined4 DAT_80320cd0;
extern undefined4 DAT_803ad188;
extern undefined4 DAT_803ad18c;
extern undefined4 DAT_803ad190;
extern undefined4 DAT_803ad194;
extern undefined4 DAT_803ad198;
extern undefined4 DAT_803ad19c;
extern undefined4 DAT_803ad1a0;
extern undefined4 DAT_803ad1a4;
extern undefined4 DAT_803ad1a8;
extern undefined4 DAT_803ad1ac;
extern undefined4 DAT_803ad1b0;
extern undefined4 DAT_803ad1b4;
extern undefined4 DAT_803ad1b8;
extern undefined4 DAT_803ad1bc;
extern undefined4 DAT_803ad1c0;
extern undefined4 DAT_803ad1c4;
extern undefined4 DAT_803ad1c8;
extern undefined4 DAT_803ad1cc;
extern undefined4 DAT_803ad1d0;
extern undefined4 DAT_803ad1d4;
extern undefined4 DAT_803ad1d8;
extern undefined4 DAT_803ad1dc;
extern undefined4 DAT_803ad1e0;
extern undefined4 DAT_803ad1f8;
extern undefined4 DAT_803ad210;
extern undefined4 DAT_803ad230;
extern undefined4 DAT_803ad248;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd738;
extern f64 DOUBLE_803e39a0;
extern f64 DOUBLE_803e3a58;
extern f64 DOUBLE_803e3aa0;
extern f64 DOUBLE_803e3ac0;
extern f64 DOUBLE_803e3ae0;
extern f64 DOUBLE_803e3af8;
extern f64 DOUBLE_803e3b18;
extern f64 DOUBLE_803e3b38;
extern f64 DOUBLE_803e3b70;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e39ac;
extern f32 FLOAT_803e39bc;
extern f32 FLOAT_803e39ec;
extern f32 FLOAT_803e3a28;
extern f32 FLOAT_803e3a4c;
extern f32 FLOAT_803e3a50;
extern f32 FLOAT_803e3a60;
extern f32 FLOAT_803e3a64;
extern f32 FLOAT_803e3a68;
extern f32 FLOAT_803e3a6c;
extern f32 FLOAT_803e3a70;
extern f32 FLOAT_803e3a74;
extern f32 FLOAT_803e3a78;
extern f32 FLOAT_803e3a7c;
extern f32 FLOAT_803e3a80;
extern f32 FLOAT_803e3a84;
extern f32 FLOAT_803e3a88;
extern f32 FLOAT_803e3a8c;
extern f32 FLOAT_803e3a90;
extern f32 FLOAT_803e3a94;
extern f32 FLOAT_803e3a98;
extern f32 FLOAT_803e3aac;
extern f32 FLOAT_803e3ab0;
extern f32 FLOAT_803e3ab8;
extern f32 FLOAT_803e3abc;
extern f32 FLOAT_803e3ac8;
extern f32 FLOAT_803e3acc;
extern f32 FLOAT_803e3ad0;
extern f32 FLOAT_803e3ad4;
extern f32 FLOAT_803e3ad8;
extern f32 FLOAT_803e3ae8;
extern f32 FLOAT_803e3aec;
extern f32 FLOAT_803e3af0;
extern f32 FLOAT_803e3b00;
extern f32 FLOAT_803e3b04;
extern f32 FLOAT_803e3b08;
extern f32 FLOAT_803e3b0c;
extern f32 FLOAT_803e3b10;
extern f32 FLOAT_803e3b14;
extern f32 FLOAT_803e3b20;
extern f32 FLOAT_803e3b24;
extern f32 FLOAT_803e3b28;
extern f32 FLOAT_803e3b2c;
extern f32 FLOAT_803e3b30;
extern f32 FLOAT_803e3b34;
extern f32 FLOAT_803e3b40;
extern f32 FLOAT_803e3b48;
extern f32 FLOAT_803e3b4c;
extern f32 FLOAT_803e3b50;
extern f32 FLOAT_803e3b54;
extern f32 FLOAT_803e3b58;
extern f32 FLOAT_803e3b5c;
extern f32 FLOAT_803e3b60;
extern f32 FLOAT_803e3b64;
extern f32 FLOAT_803e3b68;
extern f32 FLOAT_803e3b6c;
extern f32 FLOAT_803e3b78;
extern f32 FLOAT_803e3b7c;
extern f32 FLOAT_803e3b80;
extern f32 FLOAT_803e3b84;
extern f32 FLOAT_803e3b88;
extern f32 FLOAT_803e3b8c;
extern f32 FLOAT_803e3b90;
extern f32 FLOAT_803e3b94;

/*
 * --INFO--
 *
 * Function: FUN_8015d86c
 * EN v1.0 Address: 0x8015D86C
 * EN v1.0 Size: 504b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015d86c(int param_1,int param_2,int param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  float *pfVar5;
  double dVar6;
  undefined auStack_2c [28];
  
  pfVar5 = *(float **)(param_2 + 0x40c);
  FUN_8002bac4();
  iVar4 = *(int *)(param_3 + 0x2d0);
  if (iVar4 != 0) {
    fVar1 = *(float *)(iVar4 + 0x18) - *(float *)(param_1 + 0x18);
    fVar2 = *(float *)(iVar4 + 0x1c) - *(float *)(param_1 + 0x1c);
    fVar3 = *(float *)(iVar4 + 0x20) - *(float *)(param_1 + 0x20);
    dVar6 = FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
    *(float *)(param_3 + 0x2c0) = (float)dVar6;
  }
  if ((*(byte *)(param_2 + 0x404) & 0x20) == 0) {
    (**(code **)(*DAT_803dd738 + 0x3c))
              (param_1,param_3,param_2 + 0x400,2,3,(int)*(short *)(param_2 + 0x3fc),
               (int)*(short *)(param_2 + 0x3fa));
  }
  (**(code **)(*DAT_803dd738 + 0x54))
            (param_1,param_3,param_2 + 0x35c,(int)*(short *)(param_2 + 0x3f4),0,0,0,8);
  *pfVar5 = *pfVar5 + FLOAT_803dc074;
  if ((*(short *)(param_3 + 0x274) != 3) &&
     (iVar4 = (**(code **)(*DAT_803dd738 + 0x50))
                        (param_1,param_3,param_2 + 0x35c,(int)*(short *)(param_2 + 0x3f4),
                         &DAT_803209f0,&DAT_80320a68,1,auStack_2c), iVar4 != 0)) {
    if (FLOAT_803e3a4c <= *pfVar5) {
      *(undefined2 *)((int)pfVar5 + 6) = 0;
    }
    else {
      *(short *)((int)pfVar5 + 6) = *(short *)((int)pfVar5 + 6) + 1;
    }
    *pfVar5 = FLOAT_803e39ac;
    if (('\0' < *(char *)(param_3 + 0x354)) && (1 < *(short *)((int)pfVar5 + 6))) {
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_3,3);
      *(undefined2 *)((int)pfVar5 + 6) = 0;
      *(undefined2 *)(param_3 + 0x270) = 5;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015da64
 * EN v1.0 Address: 0x8015DA64
 * EN v1.0 Size: 128b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015da64(int param_1,char param_2)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (param_2 == -0x80) {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,iVar1,2);
    *(undefined2 *)(iVar1 + 0x270) = 4;
    *(undefined *)(iVar1 + 0x27b) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015dae4
 * EN v1.0 Address: 0x8015DAE4
 * EN v1.0 Size: 124b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015dae4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  undefined4 uVar1;
  undefined8 uVar2;
  
  uVar1 = *(undefined4 *)(param_9 + 0xb8);
  FUN_8000faec();
  uVar2 = FUN_8003709c(param_9,3);
  if (*(int *)(param_9 + 200) != 0) {
    FUN_8002cc9c(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(param_9 + 200));
    *(undefined4 *)(param_9 + 200) = 0;
  }
  (**(code **)(*DAT_803dd738 + 0x40))(param_9,uVar1,0x20);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015db60
 * EN v1.0 Address: 0x8015DB60
 * EN v1.0 Size: 192b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015db60(void)
{
  short *psVar1;
  char in_r8;
  int iVar2;
  
  psVar1 = (short *)FUN_8028683c();
  iVar2 = *(int *)(psVar1 + 0x5c);
  if (((in_r8 != '\0') && (*(int *)(psVar1 + 0x7a) == 0)) && (*(short *)(iVar2 + 0x402) != 0)) {
    if (*(float *)(iVar2 + 1000) != FLOAT_803e39ac) {
      FUN_8003b6d8(200,0,0,(char)(int)*(float *)(iVar2 + 1000));
    }
    FUN_8003b9ec((int)psVar1);
    FUN_8015d314(psVar1,iVar2);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015dc20
 * EN v1.0 Address: 0x8015DC20
 * EN v1.0 Size: 60b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015dc20(int param_1)
{
  (**(code **)(*DAT_803dd70c + 0xc))(param_1,*(undefined4 *)(param_1 + 0xb8),&DAT_803ad1a8);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015dc5c
 * EN v1.0 Address: 0x8015DC5C
 * EN v1.0 Size: 504b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015dc5c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8015de54
 * EN v1.0 Address: 0x8015DE54
 * EN v1.0 Size: 288b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015de54(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,int param_11)
{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  
  iVar6 = *(int *)(param_9 + 0xb8);
  uVar4 = 6;
  if (param_11 != 0) {
    uVar4 = 7;
  }
  if ((*(byte *)(param_10 + 0x2b) & 0x20) == 0) {
    uVar4 = uVar4 | 8;
  }
  uVar1 = 0xe;
  uVar2 = 8;
  uVar3 = 0x102;
  iVar5 = *DAT_803dd738;
  (**(code **)(iVar5 + 0x58))((double)FLOAT_803e3a50,param_9,param_10,iVar6);
  *(undefined4 *)(param_9 + 0xbc) = 0;
  dVar7 = (double)FLOAT_803e39bc;
  if ((float)(dVar7 * (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar6 + 0x3fe))
                                     - DOUBLE_803e39a0)) < FLOAT_803e39ec) {
    *(undefined2 *)(iVar6 + 0x3fe) = 0x6e;
  }
  FUN_8003042c((double)FLOAT_803e39ac,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
               8,0,uVar1,uVar2,uVar3,uVar4,iVar5);
  *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  (**(code **)(*DAT_803dd70c + 0x14))(param_9,iVar6,0);
  *(undefined2 *)(iVar6 + 0x270) = 0;
  *(undefined *)(iVar6 + 0x25f) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015df74
 * EN v1.0 Address: 0x8015DF74
 * EN v1.0 Size: 32b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015df74(void)
{
  FUN_8015df94();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015df94
 * EN v1.0 Address: 0x8015DF94
 * EN v1.0 Size: 284b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015df94(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8015e0b0
 * EN v1.0 Address: 0x8015E0B0
 * EN v1.0 Size: 588b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015e0b0(void)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined8 uVar10;
  int local_38;
  int local_34 [13];
  
  uVar10 = FUN_80286838();
  iVar1 = (int)((ulonglong)uVar10 >> 0x20);
  iVar6 = (int)uVar10;
  iVar9 = *(int *)(iVar1 + 0xb8);
  if ((*(char *)(iVar6 + 0x346) != '\0') || (*(char *)(iVar6 + 0x27b) != '\0')) {
    iVar8 = *(int *)(iVar9 + 0x40c);
    local_34[2] = (int)*(ushort *)(iVar9 + 0x3fe);
    local_34[1] = 0x43300000;
    iVar2 = (**(code **)(*DAT_803dd738 + 0x44))
                      ((double)(float)((double)CONCAT44(0x43300000,local_34[2]) - DOUBLE_803e3a58),
                       iVar1,iVar6,1);
    if (iVar2 == 0) {
      iVar7 = 0;
      iVar2 = 0;
      iVar3 = FUN_8002e1f4(&local_38,local_34);
      for (; local_38 < local_34[0]; local_38 = local_38 + 1) {
        iVar4 = *(int *)(iVar3 + local_38 * 4);
        if ((iVar4 != iVar1) && (*(short *)(iVar4 + 0x46) == 0x306)) {
          iVar4 = (**(code **)(**(int **)(iVar4 + 0x68) + 0x20))(iVar4,0);
          if (iVar2 < iVar4) {
            iVar2 = iVar4;
          }
          if (iVar4 == 4) {
            iVar7 = iVar7 + 1;
          }
        }
      }
      uVar5 = FUN_80022264(0,(uint)*(byte *)(iVar9 + 0x406));
      if ((iVar2 < 5) && ((*(byte *)(iVar8 + 9) & 1) == 0)) {
        if ((int)uVar5 < 0x21) {
          if ((int)uVar5 < 0x11) {
            (**(code **)(*DAT_803dd70c + 0x14))(iVar1,iVar6,3);
          }
          else {
            (**(code **)(*DAT_803dd70c + 0x14))(iVar1,iVar6,2);
          }
        }
        else if (iVar7 < 2) {
          (**(code **)(*DAT_803dd70c + 0x14))(iVar1,iVar6,4);
        }
        else {
          (**(code **)(*DAT_803dd70c + 0x14))(iVar1,iVar6,2);
        }
      }
      else {
        if ((*(byte *)(iVar9 + 0x404) & 2) != 0) {
          *(byte *)(iVar8 + 9) = *(byte *)(iVar8 + 9) | 1;
        }
        (**(code **)(*DAT_803dd70c + 0x14))(iVar1,iVar6,4);
      }
    }
    else {
      *(byte *)(iVar8 + 9) = *(byte *)(iVar8 + 9) & 0xfd;
    }
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015e2fc
 * EN v1.0 Address: 0x8015E2FC
 * EN v1.0 Size: 100b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8015e2fc(int param_1,int param_2)
{
  float fVar1;
  float *pfVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
    fVar1 = FLOAT_803e3a60;
    pfVar2 = *(float **)(iVar3 + 0x40c);
    *pfVar2 = FLOAT_803e3a60;
    pfVar2[1] = fVar1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015e360
 * EN v1.0 Address: 0x8015E360
 * EN v1.0 Size: 108b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8015e360(int param_1,int param_2)
{
  int iVar1;
  
  if (*(char *)(param_2 + 0x27b) != '\0') {
    iVar1 = *(int *)(param_1 + 0xb8);
    *(undefined *)(iVar1 + 0x405) = 0;
    if ((int)*(short *)(iVar1 + 0x3f4) != 0xffffffff) {
      FUN_800201ac((int)*(short *)(iVar1 + 0x3f4),0);
    }
    if ((int)*(short *)(iVar1 + 0x3f2) != 0xffffffff) {
      FUN_800201ac((int)*(short *)(iVar1 + 0x3f2),1);
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015e3cc
 * EN v1.0 Address: 0x8015E3CC
 * EN v1.0 Size: 292b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015e3cc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,int param_10)
{
  float fVar1;
  float *pfVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar3;
  
  fVar1 = FLOAT_803e3a60;
  if (*(char *)(param_10 + 0x27b) == '\0') {
    if (*(char *)(param_10 + 0x346) != '\0') {
      uVar3 = FUN_800377d0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,3,
                           param_9,0xe0000,param_9,in_r8,in_r9,in_r10);
      if (*(int *)(param_9 + 0x4c) == 0) {
        FUN_8002cc9c(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
        return 0;
      }
      return 4;
    }
  }
  else {
    pfVar2 = *(float **)(*(int *)(param_9 + 0xb8) + 0x40c);
    *pfVar2 = FLOAT_803e3a60;
    pfVar2[1] = fVar1;
    (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,6);
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    *(undefined *)(param_10 + 0x25f) = 0;
    *(undefined *)(param_10 + 0x349) = 0;
    FUN_80035ff8(param_9);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015e4f0
 * EN v1.0 Address: 0x8015E4F0
 * EN v1.0 Size: 132b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8015e4f0(undefined4 param_1,int param_2)
{
  float fVar1;
  
  fVar1 = FLOAT_803e3a60;
  if (*(int *)(param_2 + 0x2d0) != 0) {
    if (*(char *)(param_2 + 0x27b) != '\0') {
      *(float *)(param_2 + 0x284) = FLOAT_803e3a60;
      *(float *)(param_2 + 0x280) = fVar1;
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,0);
    }
    if (*(char *)(param_2 + 0x346) != '\0') {
      return 6;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015e574
 * EN v1.0 Address: 0x8015E574
 * EN v1.0 Size: 328b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015e574(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  *(undefined *)(param_10 + 0x34d) = 3;
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3a64;
  fVar1 = FLOAT_803e3a60;
  dVar4 = (double)FLOAT_803e3a60;
  *(float *)(param_10 + 0x280) = FLOAT_803e3a60;
  *(float *)(param_10 + 0x284) = fVar1;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,0,param_12,
                 param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if ((*(byte *)(param_10 + 0x356) & 1) == 0) {
    iVar2 = FUN_8002bac4();
    if (*(short *)(iVar2 + 0x46) == 0) {
      FUN_8000bb38(param_9,0x239);
    }
    else {
      FUN_8000bb38(param_9,0x1f2);
    }
    FUN_8000bb38(param_9,0x232);
    FUN_8000bb38(param_9,0x263);
    *(byte *)(param_10 + 0x356) = *(byte *)(param_10 + 0x356) | 1;
  }
  if (((*(byte *)(param_10 + 0x356) & 2) == 0) && (FLOAT_803e3a68 < *(float *)(param_9 + 0x98))) {
    FUN_8000bb38(param_9,0x233);
    *(byte *)(param_10 + 0x356) = *(byte *)(param_10 + 0x356) | 2;
    (**(code **)(*DAT_803dd738 + 0x4c))(param_9,(int)*(short *)(iVar3 + 0x3f0),0xffffffff,0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015e6bc
 * EN v1.0 Address: 0x8015E6BC
 * EN v1.0 Size: 400b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015e6bc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int local_18;
  int local_14;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3a60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (*(char *)(param_10 + 0x27a) != '\0') {
    iVar1 = FUN_8002e1f4(&local_18,&local_14);
    for (; local_18 < local_14; local_18 = local_18 + 1) {
      uVar2 = *(uint *)(iVar1 + local_18 * 4);
      if ((uVar2 != param_9) && (*(short *)(uVar2 + 0x46) == 0x306)) {
        (**(code **)(**(int **)(uVar2 + 0x68) + 0x24))(uVar2,0x81,0);
      }
    }
    iVar1 = FUN_8002bac4();
    iVar3 = *(int *)(iVar1 + 200);
    iVar1 = FUN_8002bac4();
    iVar3 = (**(code **)(**(int **)(iVar3 + 0x68) + 0x44))(iVar3);
    if (iVar3 == 0) {
      if (*(short *)(iVar1 + 0x46) == 0) {
        FUN_8000bb38(param_9,0x239);
      }
      else {
        FUN_8000bb38(param_9,0x1f2);
      }
    }
    else if (*(short *)(iVar1 + 0x46) == 0) {
      FUN_8000bb38(param_9,0x95);
    }
    else {
      FUN_8000bb38(param_9,0x1f2);
    }
    FUN_8000bb38(param_9,0x267);
  }
  *(undefined *)(param_10 + 0x34d) = 3;
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3a6c;
  *(float *)(param_10 + 0x280) = FLOAT_803e3a60;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015e84c
 * EN v1.0 Address: 0x8015E84C
 * EN v1.0 Size: 384b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015e84c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int local_18;
  int local_14;
  
  iVar4 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_80036018(param_9);
  }
  iVar3 = -1;
  FUN_80035eec(param_9,10,1,-1);
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6c) = 10;
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6d) = 1;
  FUN_80033a34(param_9);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    iVar1 = FUN_8002e1f4(&local_18,&local_14);
    for (; local_18 < local_14; local_18 = local_18 + 1) {
      uVar2 = *(uint *)(iVar1 + local_18 * 4);
      if ((uVar2 != param_9) && (*(short *)(uVar2 + 0x46) == 0x306)) {
        iVar3 = **(int **)(uVar2 + 0x68);
        (**(code **)(iVar3 + 0x24))(uVar2,0x81,0);
      }
    }
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3a70;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3a60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,10,0,iVar3,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 1;
  if ((*(uint *)(param_10 + 0x314) & 1) != 0) {
    iVar4 = *(int *)(iVar4 + 0x40c);
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffffe;
    *(byte *)(iVar4 + 8) = *(byte *)(iVar4 + 8) | 1;
    FUN_8000bb38(param_9,0x266);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015e9cc
 * EN v1.0 Address: 0x8015E9CC
 * EN v1.0 Size: 188b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015e9cc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  undefined4 uVar1;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_80036018(param_9);
  }
  uVar1 = 0xffffffff;
  FUN_80035eec(param_9,10,1,-1);
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6c) = 10;
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6d) = 1;
  FUN_80033a34(param_9);
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3a70;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3a60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,5,0,uVar1,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 1;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015ea88
 * EN v1.0 Address: 0x8015EA88
 * EN v1.0 Size: 444b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015ea88(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int local_28;
  int local_24 [5];
  
  iVar5 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_80036018(param_9);
  }
  iVar4 = -1;
  FUN_80035eec(param_9,10,1,-1);
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6c) = 10;
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6d) = 1;
  FUN_80033a34(param_9);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    iVar1 = FUN_8002e1f4(&local_28,local_24);
    for (; local_28 < local_24[0]; local_28 = local_28 + 1) {
      iVar2 = *(int *)(iVar1 + local_28 * 4);
      if ((iVar2 != param_9) && (*(short *)(iVar2 + 0x46) == 0x306)) {
        iVar4 = **(int **)(iVar2 + 0x68);
        (**(code **)(iVar4 + 0x24))(iVar2,0x81,0);
      }
    }
    uVar3 = FUN_80022264(0,1);
    if (uVar3 == 0) {
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_8003042c((double)FLOAT_803e3a60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,7,0,iVar4,param_13,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    else if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e3a60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,6,0,iVar4,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) =
         FLOAT_803e3a74 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x406)) - DOUBLE_803e3a58) /
         FLOAT_803e3a78;
  }
  *(float *)(param_10 + 0x280) = FLOAT_803e3a60;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015ec44
 * EN v1.0 Address: 0x8015EC44
 * EN v1.0 Size: 292b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015ec44(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int unaff_r29;
  int iVar1;
  
  iVar1 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3a60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xe,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (FLOAT_803e3a7c < *(float *)(param_9 + 0x98)) {
    unaff_r29 = *(int *)(iVar1 + 0x40c);
    *(byte *)(unaff_r29 + 8) = *(byte *)(unaff_r29 + 8) | 2;
  }
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_80035ff8(param_9);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e3a70;
    *(float *)(param_10 + 0x280) = FLOAT_803e3a60;
  }
  if (*(char *)(param_10 + 0x346) != '\0') {
    FUN_800201ac((int)*(short *)(iVar1 + 0x3f4),0);
    FUN_8003042c((double)FLOAT_803e3a60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,8,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    *(undefined *)(param_10 + 0x25f) = 0;
    *(undefined *)(param_10 + 0x349) = 0;
    *(undefined2 *)(iVar1 + 0x402) = 0;
    if ((*(byte *)(unaff_r29 + 9) & 2) == 0) {
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015ed68
 * EN v1.0 Address: 0x8015ED68
 * EN v1.0 Size: 396b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015ed68(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  iVar1 = *(int *)(iVar2 + 0x40c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3a60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xb,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (*(char *)(param_10 + 0x27a) == '\0') {
    FUN_80035eec(param_9,10,1,-1);
    *(undefined *)(*(int *)(param_9 + 0x54) + 0x6c) = 10;
    *(undefined *)(*(int *)(param_9 + 0x54) + 0x6d) = 1;
    FUN_80033a34(param_9);
  }
  else {
    *(undefined *)(param_10 + 0x25f) = 1;
    FUN_800201ac((int)*(short *)(iVar2 + 0x3f4),1);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
    *(undefined *)(param_9 + 0x36) = 0xff;
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) =
         FLOAT_803e3a80 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e3a58) /
         FLOAT_803e3a84;
    FUN_80036018(param_9);
  }
  if (*(char *)(param_10 + 0x346) != '\0') {
    *(undefined2 *)(iVar2 + 0x402) = 1;
  }
  if ((*(uint *)(param_10 + 0x314) & 0x200) != 0) {
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffdff;
    *(byte *)(iVar1 + 8) = *(byte *)(iVar1 + 8) | 4;
  }
  if (*(float *)(param_9 + 0x98) < FLOAT_803e3a88) {
    *(byte *)(iVar1 + 8) = *(byte *)(iVar1 + 8) | 2;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015eef4
 * EN v1.0 Address: 0x8015EEF4
 * EN v1.0 Size: 292b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015eef4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  float fVar1;
  float fVar2;
  uint uVar3;
  undefined2 *puVar4;
  int iVar5;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar6;
  
  uVar3 = FUN_8002e144();
  if ((uVar3 & 0xff) == 0) {
    puVar4 = FUN_8002becc(0x24,0x30a);
    *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(param_9 + 0xc);
    dVar6 = (double)FLOAT_803e3a8c;
    *(float *)(puVar4 + 6) = (float)(dVar6 + (double)*(float *)(param_9 + 0x10));
    *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)(puVar4 + 2) = 1;
    *(undefined *)((int)puVar4 + 5) = 1;
    *(undefined *)(puVar4 + 3) = 0xff;
    *(undefined *)((int)puVar4 + 7) = 0xff;
    iVar5 = FUN_8002e088(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4,5,0xff
                         ,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    if (iVar5 != 0) {
      fVar1 = *(float *)(param_10 + 0x2c0) /
              (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_10 + 0x3fe)) -
                     DOUBLE_803e3a58);
      fVar2 = FLOAT_803e3a90 * fVar1;
      *(float *)(iVar5 + 0x24) =
           (*(float *)(*(int *)(param_10 + 0x2d0) + 0xc) - *(float *)(param_9 + 0xc)) / fVar2;
      *(float *)(iVar5 + 0x28) =
           ((FLOAT_803e3a94 * fVar1 + *(float *)(*(int *)(param_10 + 0x2d0) + 0x10)) -
           *(float *)(param_9 + 0x10)) / fVar2;
      *(float *)(iVar5 + 0x2c) =
           (*(float *)(*(int *)(param_10 + 0x2d0) + 0x14) - *(float *)(param_9 + 0x14)) / fVar2;
      *(int *)(iVar5 + 0xc4) = param_9;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015f018
 * EN v1.0 Address: 0x8015F018
 * EN v1.0 Size: 432b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015f018(undefined4 param_1,undefined4 param_2,int param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  float *pfVar7;
  double dVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_80286840();
  uVar5 = (uint)((ulonglong)uVar9 >> 0x20);
  iVar6 = (int)uVar9;
  pfVar7 = *(float **)(iVar6 + 0x40c);
  iVar4 = (**(code **)(*DAT_803dd738 + 0x48))
                    ((double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar6 + 0x3fe)) -
                                    DOUBLE_803e3a58),uVar5,param_3,0x8000);
  if ((iVar4 == 0) || ((*(byte *)(iVar6 + 0x404) & 4) != 0)) {
    iVar4 = FUN_8002bac4();
    if (iVar4 == 0) {
      dVar8 = (double)FLOAT_803e3a84;
    }
    else {
      fVar1 = *(float *)(iVar4 + 0x18) - *(float *)(uVar5 + 0x18);
      fVar2 = *(float *)(iVar4 + 0x1c) - *(float *)(uVar5 + 0x1c);
      fVar3 = *(float *)(iVar4 + 0x20) - *(float *)(uVar5 + 0x20);
      dVar8 = FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
    }
    if ((pfVar7[1] < *pfVar7) && (dVar8 < (double)FLOAT_803e3a98)) {
      FUN_8000bb38(uVar5,0x265);
      uVar5 = FUN_80022264(0x32,0xfa);
      pfVar7[1] = pfVar7[1] +
                  (float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) - DOUBLE_803e3aa0);
    }
    *pfVar7 = *pfVar7 + FLOAT_803dc074;
  }
  else {
    (**(code **)(*DAT_803dd738 + 0x28))
              (uVar5,param_3,iVar6 + 0x35c,(int)*(short *)(iVar6 + 0x3f4),0,0,0,8,0xffffffff);
    *(int *)(param_3 + 0x2d0) = iVar4;
    *(undefined *)(param_3 + 0x349) = 0;
    *(undefined2 *)(iVar6 + 0x402) = 1;
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015f1c8
 * EN v1.0 Address: 0x8015F1C8
 * EN v1.0 Size: 380b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015f1c8(int param_1,int param_2,int param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  
  iVar4 = FUN_8002bac4();
  iVar5 = *(int *)(param_3 + 0x2d0);
  if (iVar5 != 0) {
    fVar1 = *(float *)(iVar5 + 0x18) - *(float *)(param_1 + 0x18);
    fVar2 = *(float *)(iVar5 + 0x1c) - *(float *)(param_1 + 0x1c);
    fVar3 = *(float *)(iVar5 + 0x20) - *(float *)(param_1 + 0x20);
    dVar6 = FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
    *(float *)(param_3 + 0x2c0) = (float)dVar6;
  }
  if ((*(byte *)(param_2 + 0x404) & 0x20) == 0) {
    (**(code **)(*DAT_803dd738 + 0x3c))
              (param_1,param_3,param_2 + 0x400,2,3,(int)*(short *)(param_2 + 0x3fa),
               (int)*(short *)(param_2 + 0x3fc));
  }
  (**(code **)(*DAT_803dd738 + 0x54))
            (param_1,param_3,param_2 + 0x35c,(int)*(short *)(param_2 + 0x3f4),0,0,0,8);
  iVar5 = (**(code **)(*DAT_803dd738 + 0x50))
                    (param_1,param_3,param_2 + 0x35c,(int)*(short *)(param_2 + 0x3f4),&DAT_80320af8,
                     &DAT_80320b70,1,&DAT_803ad1e0);
  if (iVar5 != 0) {
    (**(code **)(**(int **)(*(int *)(iVar4 + 200) + 0x68) + 0x50))();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015f344
 * EN v1.0 Address: 0x8015F344
 * EN v1.0 Size: 208b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015f344(uint param_1,byte param_2)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (param_2 == 0x81) {
    *(byte *)(iVar1 + 0x404) = *(byte *)(iVar1 + 0x404) & 0xfb;
  }
  else if ((param_2 < 0x81) && (0x7f < param_2)) {
    *(byte *)(*(int *)(iVar1 + 0x40c) + 9) = *(byte *)(*(int *)(iVar1 + 0x40c) + 9) | 2;
    FUN_8000bb38(param_1,0x264);
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,iVar1,1);
    *(undefined2 *)(iVar1 + 0x270) = 4;
    *(undefined *)(iVar1 + 0x27b) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015f414
 * EN v1.0 Address: 0x8015F414
 * EN v1.0 Size: 116b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015f414(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  undefined4 uVar1;
  undefined8 uVar2;
  
  uVar1 = *(undefined4 *)(param_9 + 0xb8);
  uVar2 = FUN_8003709c(param_9,3);
  if (*(int *)(param_9 + 200) != 0) {
    FUN_8002cc9c(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(param_9 + 200));
    *(undefined4 *)(param_9 + 200) = 0;
  }
  (**(code **)(*DAT_803dd738 + 0x40))(param_9,uVar1,0x20);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015f488
 * EN v1.0 Address: 0x8015F488
 * EN v1.0 Size: 184b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015f488(void)
{
  float fVar1;
  int iVar2;
  char in_r8;
  
  iVar2 = FUN_80286840();
  if (((in_r8 != '\0') && (*(int *)(iVar2 + 0xf4) == 0)) &&
     (*(short *)(*(int *)(iVar2 + 0xb8) + 0x402) != 0)) {
    fVar1 = *(float *)(*(int *)(iVar2 + 0xb8) + 1000);
    if (fVar1 != FLOAT_803e3a60) {
      FUN_8003b6d8(200,0,0,(char)(int)fVar1);
    }
    FUN_8003b9ec(iVar2);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015f540
 * EN v1.0 Address: 0x8015F540
 * EN v1.0 Size: 836b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015f540(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8015f884
 * EN v1.0 Address: 0x8015F884
 * EN v1.0 Size: 472b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015f884(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,int param_11)
{
  uint uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  uint uVar5;
  int iVar6;
  float *pfVar7;
  int iVar8;
  
  iVar8 = *(int *)(param_9 + 0xb8);
  uVar5 = 6;
  if (param_11 != 0) {
    uVar5 = 7;
  }
  if ((*(byte *)(param_10 + 0x2b) & 0x20) == 0) {
    uVar5 = uVar5 | 8;
  }
  uVar2 = 7;
  uVar3 = 6;
  uVar4 = 0x102;
  iVar6 = *DAT_803dd738;
  (**(code **)(iVar6 + 0x58))((double)FLOAT_803e3aac,param_9,param_10,iVar8);
  *(undefined4 *)(param_9 + 0xbc) = 0;
  pfVar7 = *(float **)(iVar8 + 0x40c);
  uVar1 = FUN_80022264(10,300);
  *pfVar7 = (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e3aa0);
  FUN_8003042c((double)FLOAT_803e3a60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               param_9,8,0,uVar2,uVar3,uVar4,uVar5,iVar6);
  *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  (**(code **)(*DAT_803dd70c + 0x14))(param_9,iVar8,0);
  *(undefined2 *)(iVar8 + 0x270) = 0;
  *(undefined *)(iVar8 + 0x25f) = 0;
  FUN_80035ff8(param_9);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015fa5c
 * EN v1.0 Address: 0x8015FA5C
 * EN v1.0 Size: 276b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015fa5c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  float fVar1;
  uint uVar2;
  undefined2 *puVar3;
  int iVar4;
  int iVar5;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar6;
  double dVar7;
  
  iVar6 = *(int *)(param_9 + 0xb8);
  uVar2 = FUN_8002e144();
  if ((uVar2 & 0xff) != 0) {
    puVar3 = FUN_8002becc(0x24,0x51b);
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_9 + 0xc);
    dVar7 = (double)FLOAT_803e3ab8;
    *(float *)(puVar3 + 6) = (float)(dVar7 + (double)*(float *)(param_9 + 0x10));
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)(puVar3 + 2) = 1;
    *(undefined *)((int)puVar3 + 5) = 4;
    *(undefined *)((int)puVar3 + 7) = 0xff;
    iVar4 = FUN_8002e088(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,0xff
                         ,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    if (iVar4 != 0) {
      iVar5 = FUN_8002bac4();
      fVar1 = FLOAT_803e3abc;
      *(float *)(iVar4 + 0x24) =
           (*(float *)(iVar5 + 0xc) - *(float *)(param_9 + 0xc)) / FLOAT_803e3abc;
      *(float *)(iVar4 + 0x28) =
           ((*(float *)(iVar5 + 0x10) +
            (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar6 + 0x15)) - DOUBLE_803e3ac0)) -
           *(float *)(param_9 + 0x10)) / fVar1;
      *(float *)(iVar4 + 0x2c) = (*(float *)(iVar5 + 0x14) - *(float *)(param_9 + 0x14)) / fVar1;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015fb70
 * EN v1.0 Address: 0x8015FB70
 * EN v1.0 Size: 72b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015fb70(uint param_1,char param_2)
{
  if (param_2 == -0x80) {
    FUN_8000bb38(param_1,0x26b);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015fbb8
 * EN v1.0 Address: 0x8015FBB8
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015fbb8(int param_1)
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
 * Function: FUN_8015fbec
 * EN v1.0 Address: 0x8015FBEC
 * EN v1.0 Size: 944b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015fbec(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)
{
  float fVar1;
  float fVar2;
  int *piVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  float *pfVar7;
  double dVar8;
  undefined8 uVar9;
  uint uStack_38;
  int iStack_34;
  undefined4 uStack_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined8 local_20;
  
  pfVar7 = *(float **)(param_9 + 0x5c);
  if (pfVar7[1] != FLOAT_803e3acc) {
    pfVar7[1] = pfVar7[1] - FLOAT_803dc074;
    FUN_8009a010((double)FLOAT_803e3ac8,(double)(pfVar7[1] / FLOAT_803e3ad0),param_9,1,(int *)0x0);
    if (pfVar7[1] <= FLOAT_803e3acc) {
      pfVar7[1] = FLOAT_803e3acc;
    }
  }
  if ((*(byte *)((int)pfVar7 + 0x12) & 2) == 0) {
    piVar3 = (int *)FUN_800395a4((int)param_9,0);
    fVar1 = *pfVar7;
    if (FLOAT_803e3ad4 <= fVar1) {
      if (FLOAT_803e3ad8 - fVar1 < FLOAT_803dc074) {
        *pfVar7 = FLOAT_803e3acc;
      }
      else {
        *pfVar7 = fVar1 + FLOAT_803dc074;
      }
      *piVar3 = 0;
    }
    else {
      if ((int)fVar1 == 10) {
        *(byte *)((int)pfVar7 + 0x12) = *(byte *)((int)pfVar7 + 0x12) | 1;
      }
      local_20 = (double)(longlong)(int)*pfVar7;
      *piVar3 = (uint)(byte)(&DAT_80320bd0)[(int)*pfVar7] << 8;
      fVar2 = FLOAT_803e3ad4;
      fVar1 = *pfVar7 + FLOAT_803e3ac8;
      *pfVar7 = fVar1;
      if (fVar2 == fVar1) {
        uVar4 = FUN_80022264(0x10,0xf5);
        local_20 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
        *pfVar7 = (float)(local_20 - DOUBLE_803e3ae0);
      }
    }
    iVar5 = FUN_8002bac4();
    fVar1 = *(float *)(iVar5 + 0xc) - *(float *)(param_9 + 6);
    fVar2 = *(float *)(iVar5 + 0x14) - *(float *)(param_9 + 10);
    dVar8 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
    uVar4 = (uint)dVar8;
    local_20 = (double)(longlong)(int)uVar4;
    if ((uVar4 & 0xffff) < (uint)*(ushort *)(pfVar7 + 3)) {
      if ((uint)*(ushort *)(pfVar7 + 3) <= (uint)*(ushort *)(pfVar7 + 4)) {
        *(undefined *)((int)pfVar7 + 0x12) = 5;
        *pfVar7 = FLOAT_803e3acc;
      }
      if ((*(byte *)((int)pfVar7 + 0x12) & 5) != 0) {
        local_2c = *(float *)(iVar5 + 0x18) - *(float *)(param_9 + 0xc);
        local_28 = *(float *)(iVar5 + 0x1c) - *(float *)(param_9 + 0xe);
        local_24 = *(float *)(iVar5 + 0x20) - *(float *)(param_9 + 0x10);
        dVar8 = (double)local_24;
        uVar6 = FUN_80021884();
        uVar6 = (uVar6 & 0xffff) - (uint)*param_9;
        if (0x8000 < (int)uVar6) {
          uVar6 = uVar6 - 0xffff;
        }
        if ((int)uVar6 < -0x8000) {
          uVar6 = uVar6 + 0xffff;
        }
        if (((uVar6 & 0xffff) < (uint)*(ushort *)((int)pfVar7 + 0xe)) ||
           ((0xffff - *(ushort *)((int)pfVar7 + 0xe) & 0xffff) < (uVar6 & 0xffff))) {
          uVar6 = FUN_80022264(0,99);
          if (((int)uVar6 < (int)(uint)*(byte *)(pfVar7 + 5)) ||
             ((*(byte *)((int)pfVar7 + 0x12) & 4) != 0)) {
            uVar9 = FUN_8000bb38((uint)param_9,0x268);
            FUN_8015fa5c(uVar9,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
          }
          else {
            FUN_8000bb38((uint)param_9,0x269);
          }
        }
        else {
          FUN_8000bb38((uint)param_9,0x269);
        }
      }
    }
    else if ((*(byte *)((int)pfVar7 + 0x12) & 1) != 0) {
      FUN_8000bb38((uint)param_9,0x269);
    }
    *(short *)(pfVar7 + 4) = (short)uVar4;
    iVar5 = FUN_80036974((int)param_9,&uStack_30,&iStack_34,&uStack_38);
    if ((iVar5 == 0xe) &&
       (*(char *)((int)pfVar7 + 0x13) = *(char *)((int)pfVar7 + 0x13) + -1,
       *(char *)((int)pfVar7 + 0x13) == '\0')) {
      FUN_80035ff8((int)param_9);
      param_9[3] = param_9[3] | 0x4000;
      *(byte *)((int)pfVar7 + 0x12) = *(byte *)((int)pfVar7 + 0x12) | 2;
      FUN_8000bb38((uint)param_9,0x26a);
      FUN_800201ac((int)*(short *)((int)pfVar7 + 10),1);
      pfVar7[1] = FLOAT_803e3ad0;
      FUN_8000bb38((uint)param_9,0x1ec);
    }
    *(byte *)((int)pfVar7 + 0x12) = *(byte *)((int)pfVar7 + 0x12) & 0xfa;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015ff9c
 * EN v1.0 Address: 0x8015FF9C
 * EN v1.0 Size: 252b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015ff9c(undefined2 *param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
  *(undefined2 *)(iVar2 + 10) = *(undefined2 *)(param_2 + 0x18);
  if (((int)*(short *)(iVar2 + 10) == 0xffffffff) ||
     (uVar1 = FUN_80020078((int)*(short *)(iVar2 + 10)), uVar1 == 0)) {
    *(ushort *)(iVar2 + 0xc) = (ushort)*(byte *)(param_2 + 0x29) << 3;
    *(undefined2 *)(iVar2 + 8) = *(undefined2 *)(param_2 + 0x22);
    *(undefined *)(iVar2 + 0x13) = *(undefined *)(param_2 + 0x32);
    *(short *)(iVar2 + 0xe) = *(char *)(param_2 + 0x28) * 0xb6;
    *(undefined *)(iVar2 + 0x14) = *(undefined *)(param_2 + 0x2f);
    *(undefined *)(iVar2 + 0x15) = *(undefined *)(param_2 + 0x27);
    *param_1 = (short)((int)*(char *)(param_2 + 0x2a) << 8);
  }
  else {
    FUN_80035ff8((int)param_1);
    param_1[3] = param_1[3] | 0x4000;
    *(byte *)(iVar2 + 0x12) = *(byte *)(iVar2 + 0x12) | 2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80160098
 * EN v1.0 Address: 0x80160098
 * EN v1.0 Size: 224b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80160098(uint param_1)
{
  short sVar1;
  int iVar2;
  
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x2cb) {
    iVar2 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x342,0,1,0xffffffff,0);
      iVar2 = iVar2 + 1;
    } while (iVar2 < 0x19);
  }
  else if ((sVar1 == 100) || (sVar1 == 0x30a)) {
    iVar2 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x344,0,1,0xffffffff,0);
      iVar2 = iVar2 + 1;
    } while (iVar2 < 0x19);
  }
  FUN_8000bb38(param_1,0x26a);
  FUN_8000faf8();
  FUN_8000e69c((double)FLOAT_803e3ae8);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80160178
 * EN v1.0 Address: 0x80160178
 * EN v1.0 Size: 680b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80160178(uint param_1)
{
  short sVar1;
  int iVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int local_28;
  int local_24;
  int local_20;
  int local_1c;
  int local_18;
  int local_14 [3];
  
  FUN_8000faf8();
  FUN_8000e69c((double)FLOAT_803e3ae8);
  FUN_8000bb38(param_1,0x26a);
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x2cb) {
    iVar6 = *(int *)(param_1 + 0xc4);
    if (iVar6 != 0) {
      iVar5 = FUN_8002e1f4(&local_18,local_14);
      do {
        if (local_14[0] <= local_18) {
          bVar3 = false;
          goto LAB_80160208;
        }
        iVar4 = local_18 + 1;
        iVar2 = local_18 * 4;
        local_18 = iVar4;
      } while (iVar6 != *(int *)(iVar5 + iVar2));
      bVar3 = true;
LAB_80160208:
      if (bVar3) {
        (**(code **)(**(int **)(*(int *)(param_1 + 0xc4) + 0x68) + 0x20))
                  (*(int *)(param_1 + 0xc4),0x80);
      }
    }
    iVar6 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x340,0,1,0xffffffff,0);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0x19);
  }
  else if (sVar1 == 100) {
    iVar6 = *(int *)(param_1 + 0xc4);
    if (iVar6 != 0) {
      iVar5 = FUN_8002e1f4(&local_20,&local_1c);
      do {
        if (local_1c <= local_20) {
          bVar3 = false;
          goto LAB_801602cc;
        }
        iVar4 = local_20 + 1;
        iVar2 = local_20 * 4;
        local_20 = iVar4;
      } while (iVar6 != *(int *)(iVar5 + iVar2));
      bVar3 = true;
LAB_801602cc:
      if (bVar3) {
        (**(code **)(**(int **)(*(int *)(param_1 + 0xc4) + 0x68) + 0x24))
                  (*(int *)(param_1 + 0xc4),0x80);
      }
    }
    iVar6 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x343,0,1,0xffffffff,0);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0x19);
  }
  else if (sVar1 == 0x30a) {
    iVar6 = *(int *)(param_1 + 0xc4);
    if (iVar6 != 0) {
      iVar5 = FUN_8002e1f4(&local_28,&local_24);
      do {
        if (local_24 <= local_28) {
          bVar3 = false;
          goto LAB_80160390;
        }
        iVar4 = local_28 + 1;
        iVar2 = local_28 * 4;
        local_28 = iVar4;
      } while (iVar6 != *(int *)(iVar5 + iVar2));
      bVar3 = true;
LAB_80160390:
      if (bVar3) {
        (**(code **)(**(int **)(*(int *)(param_1 + 0xc4) + 0x68) + 0x24))
                  (*(int *)(param_1 + 0xc4),0x80,0);
      }
    }
    iVar6 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x343,0,1,0xffffffff,0);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0x19);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80160420
 * EN v1.0 Address: 0x80160420
 * EN v1.0 Size: 32b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80160420(void)
{
  FUN_8000faec();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80160440
 * EN v1.0 Address: 0x80160440
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80160440(int param_1)
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
 * Function: FUN_80160474
 * EN v1.0 Address: 0x80160474
 * EN v1.0 Size: 440b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80160474(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
  int iVar1;
  double dVar2;
  
  dVar2 = (double)(float)((double)CONCAT44(0x43300000,*(uint *)(param_9 + 0x7a) ^ 0x80000000) -
                         DOUBLE_803e3af8);
  *(int *)(param_9 + 0x7a) = (int)(dVar2 - (double)FLOAT_803dc074);
  if (*(int *)(param_9 + 0x7a) < 0) {
    FUN_8002cc9c(dVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
  }
  else if (*(char *)(param_9 + 0x1b) != '\0') {
    *(float *)(param_9 + 0x14) = -(FLOAT_803e3aec * FLOAT_803dc074 - *(float *)(param_9 + 0x14));
    *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) * FLOAT_803e3af0;
    *param_9 = *param_9 + 0x38e;
    param_9[2] = param_9[2] + 0x38e;
    param_9[1] = param_9[1] + 0x38e;
    FUN_8002ba34((double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074),
                 (double)(*(float *)(param_9 + 0x14) * FLOAT_803dc074),
                 (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074),(int)param_9);
    FUN_80035eec((int)param_9,10,1,0);
    FUN_80035a6c((int)param_9,5);
    FUN_80036018((int)param_9);
    if ((*(int *)(*(int *)(param_9 + 0x2a) + 0x50) == 0) ||
       ((iVar1 = FUN_8002bac4(), *(int *)(*(int *)(param_9 + 0x2a) + 0x50) != iVar1 &&
        (iVar1 = FUN_8002ba84(), *(int *)(*(int *)(param_9 + 0x2a) + 0x50) != iVar1)))) {
      if (*(char *)(*(int *)(param_9 + 0x2a) + 0xad) != '\0') {
        FUN_80160098((uint)param_9);
        *(undefined *)(param_9 + 0x1b) = 0;
        param_9[0x7a] = 0;
        param_9[0x7b] = 0x78;
        *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & 0xfffe;
      }
    }
    else {
      FUN_80160178((uint)param_9);
      *(undefined *)(param_9 + 0x1b) = 0;
      param_9[0x7a] = 0;
      param_9[0x7b] = 0x78;
      *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
           *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & 0xfffe;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016062c
 * EN v1.0 Address: 0x8016062C
 * EN v1.0 Size: 68b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016062c(int param_1)
{
  *(undefined4 *)(param_1 + 0xf4) = 0xb4;
  FUN_80035ff8(param_1);
  *(undefined *)(param_1 + 0x36) = 0xff;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80160670
 * EN v1.0 Address: 0x80160670
 * EN v1.0 Size: 360b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80160670(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10)
{
  float fVar1;
  int iVar2;
  undefined8 uVar3;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  if (*(int *)(param_10 + 0x2d0) == 0) {
    (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,0);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  else {
    (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,1);
    fVar1 = FLOAT_803e3b00;
    *(float *)(param_10 + 0x290) = FLOAT_803e3b00;
    *(float *)(param_10 + 0x28c) = fVar1;
    FUN_80003494(iVar2 + 0x35c,param_9 + 0xc,0xc);
    uVar3 = FUN_80003494(iVar2 + 0x368,*(int *)(param_10 + 0x2d0) + 0xc,0xc);
    FUN_800122b4(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if ((*(float *)(param_10 + 0x2c0) < FLOAT_803e3b04) && (*(char *)(iVar2 + 0x405) == '\x02')) {
      return 5;
    }
    if (*(char *)(iVar2 + 0x381) == '\0') {
      (**(code **)(*DAT_803dd70c + 0x1c))
                ((double)*(float *)(iVar2 + 0x374),(double)*(float *)(iVar2 + 0x37c),
                 (double)FLOAT_803e3b00,(double)FLOAT_803e3b00,(double)FLOAT_803e3b08,param_9,
                 param_10);
    }
    else {
      (**(code **)(*DAT_803dd70c + 0x1c))
                ((double)*(float *)(iVar2 + 0x374),(double)*(float *)(iVar2 + 0x37c),
                 (double)FLOAT_803e3b0c,(double)FLOAT_803e3b10,(double)FLOAT_803e3b08,param_9,
                 param_10);
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801607d8
 * EN v1.0 Address: 0x801607D8
 * EN v1.0 Size: 188b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801607d8(int param_1,int param_2)
{
  float fVar1;
  undefined4 uVar2;
  double dVar3;
  
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,0);
    fVar1 = FLOAT_803e3b14;
    *(float *)(param_1 + 0x28) = FLOAT_803e3b14;
    *(float *)(param_2 + 0x280) = fVar1;
    *(float *)(param_2 + 0x294) = fVar1;
  }
  fVar1 = FLOAT_803e3b00;
  if (DOUBLE_803e3b18 <= (double)*(float *)(param_1 + 0x28)) {
    dVar3 = (double)FLOAT_803e3b20;
    *(float *)(param_1 + 0x28) = (float)((double)*(float *)(param_1 + 0x28) / dVar3);
    *(float *)(param_2 + 0x280) = (float)((double)*(float *)(param_2 + 0x280) / dVar3);
    *(float *)(param_2 + 0x294) = (float)((double)*(float *)(param_2 + 0x294) / dVar3);
    uVar2 = 0;
  }
  else {
    *(float *)(param_1 + 0x28) = FLOAT_803e3b00;
    *(float *)(param_2 + 0x280) = fVar1;
    *(float *)(param_2 + 0x294) = fVar1;
    uVar2 = 6;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_80160894
 * EN v1.0 Address: 0x80160894
 * EN v1.0 Size: 84b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80160894(int param_1,int param_2)
{
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd738 + 0x4c))
              (param_1,(int)*(short *)(*(int *)(param_1 + 0xb8) + 0x3f0),0xffffffff,0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801608e8
 * EN v1.0 Address: 0x801608E8
 * EN v1.0 Size: 248b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801608e8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,int param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  undefined4 uVar2;
  
  if (*(char *)(param_10 + 0x27b) == '\0') {
    iVar1 = FUN_8002bac4();
    FUN_800379bc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,0xe0000,
                 param_9,0,param_13,param_14,param_15,param_16);
    if (*(int *)(param_9 + 0x4c) == 0) {
      FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
      uVar2 = 0;
    }
    else {
      uVar2 = 4;
    }
  }
  else {
    (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,3);
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    *(undefined *)(param_10 + 0x25f) = 0;
    *(undefined *)(param_10 + 0x349) = 0;
    *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) & 0xfffe;
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    uVar2 = 0;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_801609e0
 * EN v1.0 Address: 0x801609E0
 * EN v1.0 Size: 160b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801609e0(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(byte *)(param_1 + 0x36) < DAT_803dc070) {
    *(undefined *)(param_1 + 0x36) = 0;
  }
  else {
    *(byte *)(param_1 + 0x36) = *(byte *)(param_1 + 0x36) - DAT_803dc070;
  }
  if (*(char *)(param_1 + 0x36) == '\0') {
    FUN_800201ac((int)*(short *)(iVar1 + 0x3f4),0);
    FUN_800201ac((int)*(short *)(iVar1 + 0x3f2),1);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80160a80
 * EN v1.0 Address: 0x80160A80
 * EN v1.0 Size: 188b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80160a80(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3b00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x25f) = 1;
  *(undefined2 *)(param_9 + 4) = *(undefined2 *)(param_10 + 0x19e);
  *(undefined2 *)(param_9 + 2) = *(undefined2 *)(param_10 + 0x19c);
  (**(code **)(*DAT_803dd738 + 0x10))
            ((double)FLOAT_803e3b24,(double)FLOAT_803e3b28,param_9,param_10,uVar1);
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3b2c * *(float *)(param_10 + 0x280);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80160b3c
 * EN v1.0 Address: 0x80160B3C
 * EN v1.0 Size: 96b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80160b3c(int param_1,int param_2)
{
  float fVar1;
  
  fVar1 = FLOAT_803e3b00;
  *(float *)(param_2 + 0x280) = FLOAT_803e3b00;
  *(float *)(param_2 + 0x284) = fVar1;
  *(float *)(param_2 + 0x2a0) = fVar1;
  *(undefined *)(param_2 + 0x25f) = 1;
  *(undefined2 *)(param_1 + 4) = *(undefined2 *)(param_2 + 0x19e);
  *(undefined2 *)(param_1 + 2) = *(undefined2 *)(param_2 + 0x19c);
  (**(code **)(*DAT_803dd70c + 0x30))(param_1,param_2,5);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80160b9c
 * EN v1.0 Address: 0x80160B9C
 * EN v1.0 Size: 332b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80160b9c(undefined4 param_1,undefined4 param_2,int param_3,int param_4)
{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  iVar3 = *(int *)(iVar1 + 0x4c);
  *(undefined *)(param_4 + 0x346) = 1;
  iVar2 = (**(code **)(*DAT_803dd738 + 0x44))
                    ((double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_3 + 0x3fe))
                                    - DOUBLE_803e3b38),iVar1,param_4,1);
  if (iVar2 != 0) {
    *(undefined4 *)(param_4 + 0x2d0) = *(undefined4 *)(param_3 + 0x3e0);
    *(undefined *)(param_4 + 0x349) = 0;
    if (*(char *)(iVar3 + 0x2e) == -1) {
      *(undefined4 *)(param_4 + 0x2d0) = 0;
    }
    else {
      if ((int)uVar4 != 0) {
        (**(code **)(*DAT_803dd6d4 + 0x58))((int)uVar4,(int)*(short *)(iVar3 + 0x24));
      }
      *(undefined *)(param_3 + 0x405) = 1;
    }
  }
  (**(code **)(*DAT_803dd738 + 0x2c))((double)FLOAT_803e3b34,iVar1,param_4,1);
  *(undefined4 *)(param_3 + 0x3e0) = *(undefined4 *)(iVar1 + 0xc0);
  *(undefined4 *)(iVar1 + 0xc0) = 0;
  (**(code **)(*DAT_803dd70c + 8))
            ((double)FLOAT_803dc074,(double)FLOAT_803dc074,iVar1,param_4,&DAT_803ad248,&DAT_803ad230
            );
  *(undefined4 *)(iVar1 + 0xc0) = *(undefined4 *)(param_3 + 0x3e0);
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80160ce8
 * EN v1.0 Address: 0x80160CE8
 * EN v1.0 Size: 384b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80160ce8(int param_1,int param_2,int param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  
  if (*(int *)(param_1 + 200) != 0) {
    *(undefined4 *)(*(int *)(param_1 + 200) + 0x30) = *(undefined4 *)(param_1 + 0x30);
  }
  iVar4 = *(int *)(param_3 + 0x2d0);
  if (iVar4 != 0) {
    fVar1 = *(float *)(iVar4 + 0x18) - *(float *)(param_1 + 0x18);
    fVar2 = *(float *)(iVar4 + 0x1c) - *(float *)(param_1 + 0x1c);
    fVar3 = *(float *)(iVar4 + 0x20) - *(float *)(param_1 + 0x20);
    dVar6 = FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
    *(float *)(param_3 + 0x2c0) = (float)dVar6;
  }
  FUN_8003b408(param_1,param_2 + 0x3ac);
  if ((*(byte *)(param_2 + 0x404) & 1) == 0) {
    (**(code **)(*DAT_803dd738 + 0x3c))
              (param_1,param_3,param_2 + 0x400,2,3,(int)*(short *)(param_2 + 0x3fc),
               (int)*(short *)(param_2 + 0x3fa));
  }
  (**(code **)(*DAT_803dd738 + 0x54))
            (param_1,param_3,param_2 + 0x35c,(int)*(short *)(param_2 + 0x3f4),param_2 + 0x405,0,0,0)
  ;
  iVar4 = (**(code **)(*DAT_803dd738 + 0x50))
                    (param_1,param_3,param_2 + 0x35c,(int)*(short *)(param_2 + 0x3f4),&DAT_80320c58,
                     &DAT_80320cd0,1,0);
  if (3 < iVar4) {
    *(undefined *)(param_2 + 0x405) = 2;
    uVar5 = FUN_8002bac4();
    *(undefined4 *)(param_3 + 0x2d0) = uVar5;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80160e68
 * EN v1.0 Address: 0x80160E68
 * EN v1.0 Size: 792b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80160e68(short *param_1,undefined4 param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80161180
 * EN v1.0 Address: 0x80161180
 * EN v1.0 Size: 116b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80161180(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  undefined4 uVar1;
  undefined8 uVar2;
  
  uVar1 = *(undefined4 *)(param_9 + 0xb8);
  uVar2 = FUN_8003709c(param_9,3);
  if (*(int *)(param_9 + 200) != 0) {
    FUN_8002cc9c(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(param_9 + 200));
    *(undefined4 *)(param_9 + 200) = 0;
  }
  (**(code **)(*DAT_803dd738 + 0x40))(param_9,uVar1,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801611f4
 * EN v1.0 Address: 0x801611F4
 * EN v1.0 Size: 64b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801611f4(int param_1)
{
  char in_r8;
  
  if ((in_r8 != '\0') && (*(int *)(param_1 + 0xf4) == 0)) {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80161234
 * EN v1.0 Address: 0x80161234
 * EN v1.0 Size: 60b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80161234(int param_1)
{
  (**(code **)(*DAT_803dd70c + 0xc))(param_1,*(undefined4 *)(param_1 + 0xb8),&DAT_803ad248);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80161270
 * EN v1.0 Address: 0x80161270
 * EN v1.0 Size: 480b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80161270(short *param_1)
{
  char cVar1;
  int iVar2;
  int iVar3;
  float *pfVar4;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  iVar2 = *(int *)(param_1 + 0x26);
  if (*(int *)(param_1 + 0x7a) == 0) {
    if (*(int *)(param_1 + 0x7c) == 0) {
      *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar2 + 8);
      *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar2 + 0x10);
      param_1[0x7c] = 0;
      param_1[0x7d] = 1;
    }
    else {
      if ((*(ushort *)(iVar3 + 0x400) & 2) != 0) {
        (**(code **)(*DAT_803dd738 + 0x28))
                  (param_1,iVar3,iVar3 + 0x35c,(int)*(short *)(iVar3 + 0x3f4),iVar3 + 0x405,0,0,0,1)
        ;
        *(ushort *)(iVar3 + 0x400) = *(ushort *)(iVar3 + 0x400) & 0xfffd;
      }
      iVar2 = (**(code **)(*DAT_803dd738 + 0x30))(param_1,iVar3,1);
      if (iVar2 != 0) {
        FUN_80160ce8((int)param_1,iVar3,iVar3);
        pfVar4 = *(float **)(iVar3 + 0x3dc);
        if ((*(ushort *)(iVar3 + 0x400) & 8) != 0) {
          iVar2 = FUN_80010340((double)*(float *)(iVar3 + 0x280),pfVar4);
          if (((iVar2 != 0) || (pfVar4[4] != 0.0)) &&
             (cVar1 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar4), cVar1 != '\0')) {
            *(ushort *)(iVar3 + 0x400) = *(ushort *)(iVar3 + 0x400) & 0xfff7;
          }
          *(float *)(iVar3 + 0x280) = FLOAT_803e3b30;
          iVar2 = FUN_80021884();
          *param_1 = (short)iVar2 + -0x8000;
          iVar2 = FUN_80021884();
          param_1[1] = (short)iVar2 + 0x4000;
          iVar2 = FUN_80021884();
          param_1[2] = (short)iVar2 + 0x4000;
          *(float *)(param_1 + 6) = pfVar4[0x1a];
          *(float *)(param_1 + 8) = pfVar4[0x1b];
          *(float *)(param_1 + 10) = pfVar4[0x1c];
        }
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80161450
 * EN v1.0 Address: 0x80161450
 * EN v1.0 Size: 396b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80161450(int param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801615dc
 * EN v1.0 Address: 0x801615DC
 * EN v1.0 Size: 92b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801615dc(int param_1,int param_2)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27b) != '\0') {
    *(undefined *)(iVar1 + 0x405) = 0;
    FUN_800201ac((int)*(short *)(iVar1 + 0x3f4),0);
    FUN_800201ac((int)*(short *)(iVar1 + 0x3f2),1);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80161638
 * EN v1.0 Address: 0x80161638
 * EN v1.0 Size: 216b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80161638(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int param_10)
{
  undefined4 uVar1;
  
  if (*(char *)(param_10 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,8);
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    *(undefined *)(param_10 + 0x25f) = 0;
    *(undefined *)(param_10 + 0x349) = 0;
    param_1 = FUN_80035ff8(param_9);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  }
  if (*(char *)(param_9 + 0x36) == '\0') {
    if (*(int *)(param_9 + 0x4c) == 0) {
      FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
      uVar1 = 0;
    }
    else {
      uVar1 = 6;
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_80161710
 * EN v1.0 Address: 0x80161710
 * EN v1.0 Size: 516b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80161710(short *param_1,int param_2)
{
  short sVar1;
  float fVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  
  iVar5 = *(int *)(param_2 + 0x2d0);
  if (iVar5 == 0) {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,0);
    uVar4 = 1;
  }
  else {
    if (*(short *)(param_2 + 0x274) != 6) {
      dVar7 = (double)(*(float *)(param_1 + 6) - *(float *)(iVar5 + 0xc));
      dVar6 = (double)(*(float *)(param_1 + 10) - *(float *)(iVar5 + 0x14));
      iVar5 = FUN_80021884();
      uVar3 = iVar5 - *param_1 & 0xffff;
      if ((uVar3 < 0x4001) || (fVar2 = FLOAT_803e3b48, 0xbfff < uVar3)) {
        dVar6 = FUN_80293900((double)(float)(dVar7 * dVar7 + (double)(float)(dVar6 * dVar6)));
        fVar2 = (float)(dVar6 - (double)FLOAT_803e3b4c);
      }
      dVar7 = (double)fVar2;
      dVar6 = dVar7;
      if (dVar7 < (double)FLOAT_803e3b50) {
        dVar6 = -dVar7;
      }
      if (((double)FLOAT_803e3b54 <= dVar6) ||
         ((*(short *)(param_2 + 0x274) != 1 &&
          ((*(short *)(param_2 + 0x274) != 5 || (*(char *)(param_2 + 0x346) == '\0')))))) {
        sVar1 = *(short *)(param_2 + 0x274);
        if (sVar1 != 1) {
          if ((((double)FLOAT_803e3b58 < dVar7) && (sVar1 != 4)) &&
             ((sVar1 != 5 || (*(char *)(param_2 + 0x346) != '\0')))) {
            (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
          }
          if (dVar7 < (double)FLOAT_803e3b5c) {
            (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
          }
        }
      }
      else {
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,6);
      }
      if (*(short *)(param_2 + 0x274) == 1) {
        fVar2 = FLOAT_803e3b64;
        if ((double)FLOAT_803e3b50 < dVar7) {
          fVar2 = FLOAT_803e3b60;
        }
        *(float *)(param_2 + 0x2a0) = fVar2;
      }
    }
    uVar4 = 0;
  }
  return uVar4;
}

/*
 * --INFO--
 *
 * Function: FUN_80161914
 * EN v1.0 Address: 0x80161914
 * EN v1.0 Size: 108b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool FUN_80161914(undefined4 param_1,int param_2)
{
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,9);
  }
  return *(char *)(param_2 + 0x346) != '\0';
}

/*
 * --INFO--
 *
 * Function: FUN_80161980
 * EN v1.0 Address: 0x80161980
 * EN v1.0 Size: 244b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80161980(undefined4 param_1,int param_2)
{
  undefined auStack_18 [2];
  undefined auStack_16 [2];
  ushort local_14 [2];
  undefined4 local_10;
  uint uStack_c;
  
  if ((*(int *)(param_2 + 0x2d0) != 0) && (*(short *)(param_2 + 0x274) != 2)) {
    uStack_c = (int)*(short *)(param_2 + 0x32e) ^ 0x80000000;
    local_10 = 0x43300000;
    if (FLOAT_803e3b68 * FLOAT_803dc074 <
        (float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e3b70)) {
      (**(code **)(*DAT_803dd738 + 0x14))
                (param_1,*(int *)(param_2 + 0x2d0),0x10,local_14,auStack_16,auStack_18);
      if ((local_14[0] < 4) || (0xb < local_14[0])) {
        return 3;
      }
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,2);
      *(float *)(param_2 + 0x2a0) = FLOAT_803e3b6c;
      *(undefined *)(param_2 + 0x346) = 0;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80161a74
 * EN v1.0 Address: 0x80161A74
 * EN v1.0 Size: 228b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool FUN_80161a74(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  *(undefined *)(param_10 + 0x34d) = 0;
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3b78;
  fVar1 = FLOAT_803e3b50;
  *(float *)(param_10 + 0x280) = FLOAT_803e3b50;
  *(float *)(param_10 + 0x284) = fVar1;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8000bb38(param_9,0x27c);
    if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e3b50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,2,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(float *)(param_10 + 0x2a0) = FLOAT_803e3b7c;
    *(undefined *)(param_10 + 0x346) = 0;
    *(undefined *)(param_9 + 0x36) = 0xff;
    *(ushort *)(iVar2 + 0x400) = *(ushort *)(iVar2 + 0x400) | 0x100;
  }
  return *(char *)(param_10 + 0x346) != '\0';
}

/*
 * --INFO--
 *
 * Function: FUN_80161b58
 * EN v1.0 Address: 0x80161B58
 * EN v1.0 Size: 192b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80161b58(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  
  iVar1 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3b50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,8,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3b80;
  if ((*(uint *)(param_10 + 0x314) & 0x200) != 0) {
    FUN_8000bb38(param_9,0x233);
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffdff;
    (**(code **)(*DAT_803dd738 + 0x4c))(param_9,(int)*(short *)(iVar1 + 0x3f0),0xffffffff,1);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80161c18
 * EN v1.0 Address: 0x80161C18
 * EN v1.0 Size: 276b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool FUN_80161c18(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  ushort uVar1;
  float fVar2;
  int iVar3;
  
  iVar3 = *(int *)(*(int *)(param_9 + 0x5c) + 0x40c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3b50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,7,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8000bb38((uint)param_9,0x27a);
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3b84;
  uVar1 = *(ushort *)(iVar3 + 0x58);
  iVar3 = (int)(short)*param_9 - (uint)uVar1;
  if (0x8000 < iVar3) {
    iVar3 = iVar3 + -0xffff;
  }
  if (iVar3 < -0x8000) {
    iVar3 = iVar3 + 0xffff;
  }
  *param_9 = uVar1;
  if ((0x3ffc < iVar3) || (iVar3 < -0x3ffc)) {
    *param_9 = *param_9 + 0x8000;
  }
  fVar2 = FLOAT_803e3b50;
  *(float *)(param_10 + 0x280) = FLOAT_803e3b50;
  *(float *)(param_10 + 0x284) = fVar2;
  return *(char *)(param_10 + 0x346) != '\0';
}

/*
 * --INFO--
 *
 * Function: FUN_80161d2c
 * EN v1.0 Address: 0x80161D2C
 * EN v1.0 Size: 632b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80161d2c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  double dVar5;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34 [2];
  uint uStack_2c;
  
  iVar4 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6e) = 9;
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6f) = 1;
  FUN_80033a34(param_9);
  uVar1 = FUN_80022264(0,100);
  if ((int)uVar1 < 0x32) {
    if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e3b50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,1,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
  }
  else if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3b50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,4,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3b88;
  (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,1);
  uStack_2c = *(char *)(iVar4 + 0x45) * -2 + 1U ^ 0x80000000;
  local_34[1] = 176.0;
  (**(code **)(**(int **)(*(int *)(iVar4 + 0x38) + 0x68) + 0x28))
            ((double)(*(float *)(param_10 + 0x280) *
                     (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e3b70)),
             *(int *)(iVar4 + 0x38),iVar4 + 0x48);
  if (FLOAT_803e3b8c <= *(float *)(iVar4 + 0x48)) {
    if (FLOAT_803e3b90 < *(float *)(iVar4 + 0x48)) {
      *(float *)(iVar4 + 0x48) = FLOAT_803e3b90;
    }
  }
  else {
    *(float *)(iVar4 + 0x48) = FLOAT_803e3b8c;
  }
  (**(code **)(**(int **)(*(int *)(iVar4 + 0x38) + 0x68) + 0x24))
            ((double)(*(float *)(iVar4 + 0x48) - FLOAT_803e3b94),*(int *)(iVar4 + 0x38),&local_48,
             &local_44,&local_40);
  (**(code **)(**(int **)(*(int *)(iVar4 + 0x38) + 0x68) + 0x24))
            ((double)(FLOAT_803e3b94 + *(float *)(iVar4 + 0x48)),*(int *)(iVar4 + 0x38),&local_3c,
             &local_38,local_34);
  local_48 = local_48 - local_3c;
  local_44 = local_44 - local_38;
  local_40 = local_40 - local_34[0];
  dVar5 = FUN_80293900((double)(local_48 * local_48 + local_40 * local_40));
  local_48 = (float)dVar5;
  iVar2 = FUN_80021884();
  *(short *)(param_9 + 2) = (short)iVar2 * ((short)((int)*(char *)(iVar4 + 0x45) << 1) + -1);
  if (*(char *)(param_10 + 0x346) == '\0') {
    uVar3 = 0;
  }
  else {
    uVar3 = 5;
  }
  return uVar3;
}
