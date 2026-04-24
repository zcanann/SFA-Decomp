#include "ghidra_import.h"
#include "main/dll/LGT/LGTprojectedlight.h"

extern undefined4 FUN_8000a538();
extern undefined4 FUN_800168a8();
extern undefined8 FUN_80019940();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern undefined4 FUN_8002bac4();
extern undefined4 FUN_8003709c();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_8005cf74();
extern int FUN_80080490();
extern byte FUN_80089094();
extern undefined4 FUN_80089468();
extern undefined4 FUN_8008947c();
extern undefined4 FUN_80089484();
extern undefined4 FUN_800894c0();
extern undefined4 FUN_80089734();
extern undefined4 FUN_8008979c();
extern undefined4 FUN_80089804();
extern undefined4 FUN_8008986c();
extern undefined4 FUN_8008999c();
extern double FUN_8008f014();
extern undefined4 FUN_801d84c4();
extern undefined4 FUN_801d8650();
extern uint countLeadingZeros();

extern undefined4 DAT_802c2c44;
extern undefined4 DAT_802c2c48;
extern undefined4 DAT_802c2c4c;
extern undefined4 DAT_802c2c50;
extern undefined4 DAT_802c2c54;
extern undefined4 DAT_802c2c58;
extern undefined4 DAT_802c2c5c;
extern undefined4 DAT_802c2c60;
extern undefined4 DAT_802c2c64;
extern undefined4 DAT_803dcd78;
extern undefined4 DAT_803dcd7c;
extern undefined4 DAT_803dcd80;
extern undefined4 DAT_803dcd84;
extern undefined4 DAT_803dcd88;
extern undefined4 DAT_803dcd8c;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de910;
extern undefined4 DAT_803de914;
extern undefined4 DAT_803de918;
extern undefined4 DAT_803de91c;
extern f64 DOUBLE_803e6b00;
extern f64 DOUBLE_803e6b20;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803de908;
extern f32 FLOAT_803de90c;
extern f32 FLOAT_803e6b08;
extern f32 FLOAT_803e6b0c;
extern f32 FLOAT_803e6b10;
extern f32 FLOAT_803e6b14;
extern f32 FLOAT_803e6b18;
extern f32 FLOAT_803e6b1c;
extern undefined bRam803dcd79;
extern undefined2 bRam803dcd7a;
extern undefined bRam803dcd7d;
extern undefined2 bRam803dcd7e;
extern undefined bRam803dcd81;
extern undefined2 bRam803dcd82;
extern undefined bRam803dcd85;
extern undefined2 bRam803dcd86;
extern undefined bRam803dcd89;
extern undefined2 bRam803dcd8a;
extern undefined bRam803dcd8d;
extern undefined2 bRam803dcd8e;
extern undefined bRam803de91d;
extern undefined2 bRam803de91e;
extern undefined uRam803de915;
extern undefined2 uRam803de916;
extern undefined uRam803de919;
extern undefined2 uRam803de91a;

/*
 * --INFO--
 *
 * Function: FUN_801f44c0
 * EN v1.0 Address: 0x801F44B4
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x801F44C0
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f44c0(undefined2 *param_1,int param_2)
{
  float *pfVar1;
  
  *param_1 = 0;
  pfVar1 = *(float **)(param_1 + 0x5c);
  *pfVar1 = (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x18) << 2 ^ 0x80000000) -
                   DOUBLE_803e6b00);
  *(undefined2 *)(pfVar1 + 1) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(pfVar1 + 2) = *(undefined2 *)(param_2 + 0x1c);
  *(undefined2 *)(pfVar1 + 3) = 0;
  if (*(short *)(pfVar1 + 2) < 1) {
    *(int *)(param_1 + 0x7a) = (int)*(short *)(pfVar1 + 2);
  }
  else {
    *(undefined4 *)(param_1 + 0x7a) = 0;
  }
  pfVar1[4] = *(float *)(param_1 + 6);
  pfVar1[5] = *(float *)(param_1 + 8);
  pfVar1[6] = *(float *)(param_1 + 10);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f4550
 * EN v1.0 Address: 0x801F456C
 * EN v1.0 Size: 1528b
 * EN v1.1 Address: 0x801F4550
 * EN v1.1 Size: 1300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4550(int param_1)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  char cVar10;
  byte bVar11;
  double dVar12;
  
  fVar9 = DAT_802c2c64;
  fVar8 = DAT_802c2c60;
  fVar7 = DAT_802c2c5c;
  fVar6 = DAT_802c2c58;
  fVar5 = DAT_802c2c54;
  fVar4 = DAT_802c2c50;
  fVar3 = DAT_802c2c4c;
  fVar2 = DAT_802c2c48;
  fVar1 = DAT_802c2c44;
  cVar10 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0xac));
  if (cVar10 != '\a') {
    FUN_8005cf74(0);
    bVar11 = FUN_80089094(0);
    if (bVar11 == 0) {
      FUN_8008947c(1);
      FUN_80089468(0x88,0xb7,0xba);
      if ((*(uint *)(param_1 + 0xf4) & 4) == 0) {
        FUN_8008999c(1,1,0);
        *(uint *)(param_1 + 0xf4) = *(uint *)(param_1 + 0xf4) | 4;
      }
      else {
        FUN_8008999c(1,1,1);
      }
      dVar12 = FUN_8008f014();
      if ((double)FLOAT_803e6b08 < dVar12) {
        FLOAT_803de908 = FLOAT_803e6b0c;
        FLOAT_803de90c = FLOAT_803e6b0c;
      }
      FLOAT_803de90c = -(FLOAT_803e6b10 * FLOAT_803dc074 - FLOAT_803de90c);
      if (FLOAT_803de90c < FLOAT_803e6b08) {
        FLOAT_803de90c = FLOAT_803e6b08;
      }
      DAT_803de91c = (byte)(int)(FLOAT_803de90c *
                                 (float)((double)CONCAT44(0x43300000,
                                                          (uint)DAT_803dcd84 - (uint)DAT_803dcd80 ^
                                                          0x80000000) - DOUBLE_803e6b20) +
                                (float)((double)CONCAT44(0x43300000,DAT_803dcd80 ^ 0x80000000) -
                                       DOUBLE_803e6b20));
      bRam803de91d = (byte)(int)(FLOAT_803de90c *
                                 (float)((double)CONCAT44(0x43300000,
                                                          (uint)bRam803dcd85 - (uint)bRam803dcd81 ^
                                                          0x80000000) - DOUBLE_803e6b20) +
                                (float)((double)CONCAT44(0x43300000,bRam803dcd81 ^ 0x80000000) -
                                       DOUBLE_803e6b20));
      bRam803de91e = (byte)(int)(FLOAT_803de90c *
                                 (float)((double)CONCAT44(0x43300000,
                                                          (uint)bRam803dcd86 - (uint)bRam803dcd82 ^
                                                          0x80000000) - DOUBLE_803e6b20) +
                                (float)((double)CONCAT44(0x43300000,bRam803dcd82 ^ 0x80000000) -
                                       DOUBLE_803e6b20));
      FUN_8008986c(1,DAT_803de91c,bRam803de91d,bRam803de91e,0x40,0x40);
      DAT_803de918 = (undefined)
                     (int)(FLOAT_803de90c *
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)DAT_803dcd7c - (uint)DAT_803dcd78 ^
                                                    0x80000000) - DOUBLE_803e6b20) +
                          (float)((double)CONCAT44(0x43300000,DAT_803dcd78 ^ 0x80000000) -
                                 DOUBLE_803e6b20));
      uRam803de919 = (undefined)
                     (int)(FLOAT_803de90c *
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)bRam803dcd7d - (uint)bRam803dcd79 ^
                                                    0x80000000) - DOUBLE_803e6b20) +
                          (float)((double)CONCAT44(0x43300000,bRam803dcd79 ^ 0x80000000) -
                                 DOUBLE_803e6b20));
      uRam803de91a = (undefined)
                     (int)(FLOAT_803de90c *
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)bRam803dcd7e - (uint)bRam803dcd7a ^
                                                    0x80000000) - DOUBLE_803e6b20) +
                          (float)((double)CONCAT44(0x43300000,bRam803dcd7a ^ 0x80000000) -
                                 DOUBLE_803e6b20));
      FUN_8008979c(1,DAT_803de918,uRam803de919,uRam803de91a);
      DAT_803de914 = (undefined)
                     (int)(FLOAT_803de90c *
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)DAT_803dcd8c - (uint)DAT_803dcd88 ^
                                                    0x80000000) - DOUBLE_803e6b20) +
                          (float)((double)CONCAT44(0x43300000,DAT_803dcd88 ^ 0x80000000) -
                                 DOUBLE_803e6b20));
      uRam803de915 = (undefined)
                     (int)(FLOAT_803de90c *
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)bRam803dcd8d - (uint)bRam803dcd89 ^
                                                    0x80000000) - DOUBLE_803e6b20) +
                          (float)((double)CONCAT44(0x43300000,bRam803dcd89 ^ 0x80000000) -
                                 DOUBLE_803e6b20));
      uRam803de916 = (undefined)
                     (int)(FLOAT_803de90c *
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)bRam803dcd8e - (uint)bRam803dcd8a ^
                                                    0x80000000) - DOUBLE_803e6b20) +
                          (float)((double)CONCAT44(0x43300000,bRam803dcd8a ^ 0x80000000) -
                                 DOUBLE_803e6b20));
      FUN_80089804(1,DAT_803de914,uRam803de915,uRam803de916);
      DAT_803de910 = (undefined)(int)(FLOAT_803de90c * FLOAT_803e6b18 + FLOAT_803e6b14);
      FUN_800894c0(1);
      FUN_80089484((double)(FLOAT_803de90c * (fVar7 - fVar4) + fVar4),
                   (double)(FLOAT_803de90c * (fVar8 - fVar5) + fVar5),
                   (double)(FLOAT_803de90c * (fVar9 - fVar6) + fVar6),(double)FLOAT_803e6b1c);
      FUN_80089734((double)fVar1,(double)fVar2,(double)fVar3,1);
    }
    else {
      FUN_8008947c(0);
      FUN_800894c0(0);
      FUN_8008999c(7,0,1);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f4a64
 * EN v1.0 Address: 0x801F4B64
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801F4A64
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4a64(int param_1)
{
  FUN_8003709c(param_1,9);
  FUN_8000a538((int *)0xa8,0);
  FUN_800201ac(0xa7f,0);
  FUN_800201ac(0x372,1);
  FUN_800201ac(0x390,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f4ab8
 * EN v1.0 Address: 0x801F4BB8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801F4AB8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4ab8(int param_1)
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
 * Function: FUN_801f4aec
 * EN v1.0 Address: 0x801F4BE0
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x801F4AEC
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4aec(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  uint uVar1;
  int iVar2;
  float *pfVar3;
  undefined8 uVar4;
  
  FUN_8002bac4();
  pfVar3 = *(float **)(param_9 + 0xb8);
  if (FLOAT_803e6b08 < *pfVar3) {
    uVar4 = FUN_80019940(0xff,0xff,0xff,0xff);
    FUN_800168a8(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x42c);
    *pfVar3 = *pfVar3 - FLOAT_803dc074;
    if (*pfVar3 < FLOAT_803e6b08) {
      *pfVar3 = FLOAT_803e6b08;
    }
  }
  if (*(char *)(pfVar3 + 5) == '\0') {
    uVar1 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_9 + 0xac));
    uVar1 = countLeadingZeros(6 - (uVar1 & 0xff));
    if (((uVar1 >> 5 == 0) || (iVar2 = FUN_80080490(), iVar2 == 0)) ||
       (uVar1 = FUN_80020078(0xa7f), uVar1 == 0)) {
      FUN_801d8650(pfVar3 + 4,0x10,-1,-1,0xa7f,(int *)0xa6);
      FUN_801d84c4(pfVar3 + 4,2,-1,-1,0xa7f,(int *)0xa8);
    }
    if (0x3c < (uint)pfVar3[6]) {
      FUN_801d84c4(pfVar3 + 4,1,-1,-1,0xada,(int *)0xac);
    }
    FUN_801d84c4(pfVar3 + 4,0x20,-1,-1,0xcbb,(int *)0xc4);
  }
  FUN_801f4550(param_9);
  pfVar3[6] = (float)((int)pfVar3[6] + 1);
  return;
}
