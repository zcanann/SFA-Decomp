#include "ghidra_import.h"
#include "main/dll/baddie/TumbleweedBush.h"

extern undefined8 FUN_80003494();
extern undefined4 FUN_8000a304();
extern undefined4 FUN_8000b9bc();
extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000da78();
extern undefined8 FUN_80014b44();
extern undefined4 FUN_80014b68();
extern undefined4 FUN_80014b84();
extern undefined4 FUN_80014b94();
extern undefined4 FUN_80014ba4();
extern char FUN_80014cec();
extern uint FUN_80014e9c();
extern undefined4 FUN_800161c4();
extern undefined4 FUN_800191fc();
extern undefined4 FUN_800198dc();
extern undefined4 FUN_80019940();
extern undefined4 FUN_8001be88();
extern undefined4 FUN_8001bee0();
extern uint FUN_80020078();
extern int FUN_80020800();
extern undefined4 FUN_800238c4();
extern int FUN_80023d8c();
extern undefined4 FUN_80054484();
extern int FUN_80054ed0();
extern undefined4 FUN_80077318();
extern undefined8 FUN_8007d858();
extern undefined8 FUN_8013049c();
extern undefined4 FUN_80130618();
extern undefined4 FUN_801307f4();
extern undefined8 FUN_80286824();
extern undefined2 FUN_8028683c();
extern undefined2 FUN_80286840();
extern undefined4 FUN_80286870();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_8031cdf8;
extern undefined4 DAT_8031ce04;
extern short DAT_8031cef8;
extern undefined2 DAT_803aa0b8;
extern undefined4 DAT_803aa0bc;
extern undefined4 DAT_803aa0c2;
extern undefined4 DAT_803aa0cc;
extern undefined4 DAT_803aa0ce;
extern undefined4 DAT_803aa0d2;
extern undefined4 DAT_803aa0d3;
extern undefined4 DAT_803aa0d4;
extern undefined4 DAT_803aa0d5;
extern undefined4 DAT_803aa0d6;
extern int DAT_803aaa18;
extern undefined4 DAT_803aaa1c;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803de578;
extern undefined4 DAT_803de579;
extern undefined4 DAT_803de57a;
extern undefined4 DAT_803de57c;
extern undefined4 DAT_803de57e;
extern undefined4 DAT_803de580;
extern undefined4 DAT_803de582;
extern undefined4 DAT_803de584;
extern undefined4* DAT_803de588;
extern undefined4 DAT_803de58c;
extern undefined4 DAT_803de58e;
extern undefined4 DAT_803de590;
extern undefined4 DAT_803de591;
extern undefined4 DAT_803de592;
extern undefined4 DAT_803de593;
extern undefined4 DAT_803de598;
extern undefined4 DAT_803de5a0;
extern f64 DOUBLE_803e2e78;
extern f32 FLOAT_803de59c;
extern f32 FLOAT_803e2e80;
extern f32 FLOAT_803e2e84;
extern f32 FLOAT_803e2e88;

/*
 * --INFO--
 *
 * Function: FUN_80131078
 * EN v1.0 Address: 0x80130CF0
 * EN v1.0 Size: 936b
 * EN v1.1 Address: 0x80131078
 * EN v1.1 Size: 1168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80131078(void)
{
  short sVar1;
  char cVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  char local_18;
  char local_17 [15];
  
  iVar6 = DAT_803de592 * 0x3c;
  if (DAT_803de591 == '\0') {
    uVar3 = 0xffffffff;
  }
  else {
    uVar3 = 0xffffffff;
    iVar4 = FUN_80020800();
    if (iVar4 == 0) {
      FUN_80014ba4(0,local_17,&local_18);
      cVar2 = local_17[0];
      if (DAT_803de579 != '\0') {
        local_17[0] = local_18;
        local_18 = -cVar2;
      }
      if (local_18 != '\0') {
        local_17[0] = '\0';
      }
      if (((local_17[0] != '\0') || (local_18 != '\0')) && (DAT_803de578 != '\0')) {
        if (((local_18 < '\0') && ((char)(&DAT_803aa0d3)[iVar6] != -1)) &&
           (((&DAT_803aa0ce)[(char)(&DAT_803aa0d3)[iVar6] * 0x1e] & 0x1000) == 0)) {
          FUN_80014b84(0);
          DAT_803de592 = (&DAT_803aa0d3)[iVar6];
          DAT_803de58e = 0xff;
        }
        else if ((('\0' < local_18) && ((char)(&DAT_803aa0d2)[iVar6] != -1)) &&
                (((&DAT_803aa0ce)[(char)(&DAT_803aa0d2)[iVar6] * 0x1e] & 0x1000) == 0)) {
          FUN_80014b84(0);
          DAT_803de592 = (&DAT_803aa0d2)[iVar6];
          DAT_803de58e = 0xff;
        }
        if ((char)(&DAT_803aa0d6)[iVar6] == -1) {
          if (((local_17[0] < '\0') && ((char)(&DAT_803aa0d4)[iVar6] != -1)) &&
             (((&DAT_803aa0ce)[(char)(&DAT_803aa0d4)[iVar6] * 0x1e] & 0x1000) == 0)) {
            FUN_80014b94(0);
            DAT_803de592 = (&DAT_803aa0d4)[iVar6];
            DAT_803de58e = 0xff;
          }
          else if ((('\0' < local_17[0]) && ((char)(&DAT_803aa0d5)[iVar6] != -1)) &&
                  (((&DAT_803aa0ce)[(char)(&DAT_803aa0d5)[iVar6] * 0x1e] & 0x1000) == 0)) {
            FUN_80014b94(0);
            DAT_803de592 = (&DAT_803aa0d5)[iVar6];
            DAT_803de58e = 0xff;
          }
        }
        else {
          iVar6 = (char)(&DAT_803aa0d6)[iVar6] * 0x3c;
          if ((local_17[0] < '\0') && ((&DAT_803aa0d4)[iVar6] != -1)) {
            FUN_80014b94(0);
            (&DAT_803aa0d6)[DAT_803de592 * 0x3c] = (&DAT_803aa0d4)[iVar6];
            DAT_803de58e = 0xff;
          }
          else if (('\0' < local_17[0]) && ((&DAT_803aa0d5)[iVar6] != -1)) {
            FUN_80014b94(0);
            (&DAT_803aa0d6)[DAT_803de592 * 0x3c] = (&DAT_803aa0d5)[iVar6];
            DAT_803de58e = 0xff;
          }
        }
        if (DAT_803de592 < '\0') {
          DAT_803de592 = DAT_803de591 + -1;
        }
        if (DAT_803de591 <= DAT_803de592) {
          DAT_803de592 = '\0';
        }
      }
      if (DAT_803de593 != '\0') {
        uVar5 = FUN_80014e9c(0);
        if ((uVar5 & 0x1100) == 0) {
          if ((uVar5 & 0x200) != 0) {
            FUN_80014b68(0,0x200);
            uVar3 = 0;
          }
        }
        else if ((((&DAT_803aa0ce)[DAT_803de592 * 0x1e] & 0x20) == 0) &&
                (uVar5 = FUN_80020078(0x44f), uVar5 == 0)) {
          FUN_80014b68(0,0x1100);
          uVar3 = 1;
        }
      }
      if (DAT_803de590 == 0) {
        sVar1 = (ushort)DAT_803dc070 * -5;
      }
      else {
        sVar1 = (ushort)DAT_803dc070 * 5;
      }
      DAT_803de58e = DAT_803de58e + sVar1;
      if (DAT_803de58e < 0x100) {
        if (DAT_803de58e < 0) {
          DAT_803de58e = -DAT_803de58e;
          DAT_803de590 = DAT_803de590 ^ 1;
        }
      }
      else {
        DAT_803de58e = 0xff - (DAT_803de58e + -0xff);
        DAT_803de590 = DAT_803de590 ^ 1;
      }
      DAT_803de593 = '\x01';
      FUN_80130618();
      FUN_801307f4();
    }
    else {
      uVar3 = 0xffffffff;
    }
  }
  return uVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_80131508
 * EN v1.0 Address: 0x80131098
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x80131508
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80131508(void)
{
  int iVar1;
  undefined2 *puVar2;
  
  puVar2 = &DAT_803aa0b8;
  for (iVar1 = 0; iVar1 < DAT_803de591; iVar1 = iVar1 + 1) {
    if (*(int *)(puVar2 + 8) != 0) {
      FUN_80054484();
    }
    puVar2 = puVar2 + 0x1e;
  }
  DAT_803de591 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80131574
 * EN v1.0 Address: 0x801310FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80131574
 * EN v1.1 Size: 640b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80131574(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined param_11,undefined *param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16,
                 undefined2 param_17,undefined2 param_18,undefined2 param_19,undefined2 param_20)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801317f4
 * EN v1.0 Address: 0x80131100
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x801317F4
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801317f4(void)
{
  int iVar1;
  
  iVar1 = 0;
  do {
    FUN_80054484();
    iVar1 = iVar1 + 1;
  } while (iVar1 < 6);
  FUN_8001be88(3);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8013184c
 * EN v1.0 Address: 0x80131140
 * EN v1.0 Size: 392b
 * EN v1.1 Address: 0x8013184C
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013184c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  undefined4 uVar1;
  undefined4 extraout_r4;
  int iVar2;
  undefined4 *puVar3;
  undefined8 uVar4;
  
  iVar2 = 0;
  puVar3 = &DAT_8031ce04;
  do {
    uVar1 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (int)*(short *)(puVar3 + 1),param_10,param_11,param_12,param_13,param_14,
                         param_15,param_16);
    *puVar3 = uVar1;
    puVar3 = puVar3 + 2;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 6);
  uVar4 = FUN_80014b44(10);
  DAT_803de58c = 0xff;
  FUN_8001bee0(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,3,extraout_r4,param_11,
               param_12,param_13,param_14,param_15,param_16);
  DAT_803de579 = 0;
  DAT_803de578 = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80131920
 * EN v1.0 Address: 0x801312C8
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x80131920
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80131920(int param_1,int param_2)
{
  if (param_2 == 0) {
    *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) & 0xfe;
  }
  else {
    if ((*(byte *)(param_1 + 4) & 1) == 0) {
      DAT_803de598 = 0;
      FLOAT_803de59c =
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xc) ^ 0x80000000) -
                  DOUBLE_803e2e78);
    }
    *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801319a0
 * EN v1.0 Address: 0x80131348
 * EN v1.0 Size: 964b
 * EN v1.1 Address: 0x801319A0
 * EN v1.1 Size: 808b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801319a0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  byte bVar1;
  char cVar2;
  uint uVar3;
  byte *pbVar4;
  int iVar5;
  
  bVar1 = *(byte *)((int)param_9 + 5);
  if (bVar1 == 1) {
    if ((*(byte *)(param_9 + 2) & 1) == 0) {
      if (param_9[6] == 0) {
        iVar5 = 5;
      }
      else {
        iVar5 = 3;
      }
    }
    else if (param_9[6] == 0) {
      iVar5 = 4;
    }
    else {
      iVar5 = 2;
    }
    if ((*(byte *)(param_9 + 2) & 0x20) == 0) {
      uVar3 = param_11 & 0xff;
    }
    else {
      uVar3 = (int)(param_11 & 0xff) >> 1;
    }
    FUN_80077318((double)(float)((double)CONCAT44(0x43300000,(int)*param_9 ^ 0x80000000) -
                                DOUBLE_803e2e78),
                 (double)(float)((double)CONCAT44(0x43300000,(int)param_9[1] ^ 0x80000000) -
                                DOUBLE_803e2e78),(&DAT_803aaa18)[iVar5],uVar3,0x100);
  }
  else if (bVar1 == 0) {
    FUN_80077318((double)(float)((double)CONCAT44(0x43300000,(int)*param_9 ^ 0x80000000) -
                                DOUBLE_803e2e78),
                 (double)(float)((double)CONCAT44(0x43300000,(int)param_9[1] ^ 0x80000000) -
                                DOUBLE_803e2e78),DAT_803aaa1c,(int)((param_11 & 0xff) * 0xb4) >> 8,
                 0x100);
    FUN_80077318((double)(float)((double)CONCAT44(0x43300000,
                                                  (int)(((float)((double)CONCAT44(0x43300000,
                                                                                  (int)param_9[7] ^
                                                                                  0x80000000) -
                                                                DOUBLE_803e2e78) *
                                                         ((float)((double)CONCAT44(0x43300000,
                                                                                   (int)param_9[6] -
                                                                                   (int)param_9[4] ^
                                                                                   0x80000000) -
                                                                 DOUBLE_803e2e78) /
                                                         (float)((double)CONCAT44(0x43300000,
                                                                                  (int)param_9[5] -
                                                                                  (int)param_9[4] ^
                                                                                  0x80000000) -
                                                                DOUBLE_803e2e78)) +
                                                        (float)((double)CONCAT44(0x43300000,
                                                                                 (int)*param_9 ^
                                                                                 0x80000000) -
                                                               DOUBLE_803e2e78)) -
                                                       (float)((double)CONCAT44(0x43300000,
                                                                                (int)(uint)*(ushort 
                                                  *)(DAT_803aaa18 + 10) >> 1 ^ 0x80000000) -
                                                  DOUBLE_803e2e78)) ^ 0x80000000) - DOUBLE_803e2e78)
                 ,(double)(float)((double)CONCAT44(0x43300000,(int)param_9[1] - 4U ^ 0x80000000) -
                                 DOUBLE_803e2e78),DAT_803aaa18,(int)((param_11 & 0xff) * 0xff) >> 8,
                 0x100);
  }
  else if (bVar1 < 3) {
    if ((*(byte *)(param_9 + 2) & 0x80) == 0) {
      iVar5 = (int)param_9[6];
    }
    else {
      iVar5 = 0;
    }
    pbVar4 = (byte *)FUN_800191fc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                  (uint)(ushort)param_9[7],iVar5,param_11,param_12,param_13,param_14
                                  ,param_15,param_16);
    FUN_80019940(0,0,0,(byte)((param_11 & 0xff) * 0x96 >> 8));
    FUN_800198dc((uint)(ushort)param_9[8],2,2);
    FUN_800161c4(pbVar4,(uint)(ushort)param_9[8]);
    FUN_80019940(0xff,0xff,0xff,(byte)param_11);
    FUN_800198dc((uint)(ushort)param_9[8],0,0);
    FUN_800161c4(pbVar4,(uint)(ushort)param_9[8]);
  }
  cVar2 = *(char *)(param_9 + 3);
  *(char *)(param_9 + 3) = cVar2 + -1;
  if ((char)(cVar2 + -1) < '\0') {
    *(undefined *)(param_9 + 3) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80131cc8
 * EN v1.0 Address: 0x8013170C
 * EN v1.0 Size: 940b
 * EN v1.1 Address: 0x80131CC8
 * EN v1.1 Size: 948b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80131cc8(int param_1)
{
  byte bVar1;
  short sVar2;
  char cVar4;
  uint uVar3;
  short sVar5;
  short sVar6;
  undefined8 local_20;
  undefined8 local_18;
  
  if ((*(byte *)(param_1 + 4) & 1) == 0) {
    return;
  }
  *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) & 0xe3;
  sVar2 = *(short *)(param_1 + 0xc);
  *(undefined *)(param_1 + 6) = 4;
  bVar1 = *(byte *)(param_1 + 5);
  if (bVar1 != 1) {
    if (bVar1 == 0) {
      cVar4 = FUN_80014cec(0);
      uVar3 = (uint)cVar4;
      sVar6 = ((short)((int)uVar3 >> 4) + (ushort)((int)uVar3 < 0 && (uVar3 & 0xf) != 0)) * 0xa0;
      if (((sVar6 == 0) ||
          ((FLOAT_803de59c <
            (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 8) ^ 0x80000000) -
                   DOUBLE_803e2e78) && (sVar6 < 0)))) ||
         (((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 10) ^ 0x80000000) -
                  DOUBLE_803e2e78) < FLOAT_803de59c && (0 < sVar6)))) {
        DAT_803de598 = 0;
      }
      else {
        local_20 = (double)CONCAT44(0x43300000,(int)DAT_803de598 ^ 0x80000000);
        DAT_803de598 = (short)(int)(FLOAT_803e2e80 *
                                    (float)((double)CONCAT44(0x43300000,
                                                             (int)(short)(sVar6 - DAT_803de598) ^
                                                             0x80000000) - DOUBLE_803e2e78) +
                                   (float)(local_20 - DOUBLE_803e2e78));
        FUN_8000da78(0,0x3b9);
      }
      local_18 = (double)CONCAT44(0x43300000,(int)DAT_803de598 ^ 0x80000000);
      FLOAT_803de59c = FLOAT_803de59c + (float)(local_18 - DOUBLE_803e2e78) / FLOAT_803e2e84;
      *(short *)(param_1 + 0xc) = (short)(int)(FLOAT_803e2e88 + FLOAT_803de59c);
      if ((*(byte *)(param_1 + 4) & 0x40) != 0) {
        sVar6 = *(short *)(param_1 + 0xc);
        sVar5 = sVar6;
        if (0x7f < sVar6) {
          sVar5 = 0x7f;
        }
        if (sVar5 < 0) {
          sVar6 = 0;
        }
        else if (0x7f < sVar6) {
          sVar6 = 0x7f;
        }
        FUN_8000b9bc((double)FLOAT_803e2e88,0,0x3b9,(byte)sVar6);
      }
      goto LAB_80131fc8;
    }
    if (bVar1 < 3) {
      cVar4 = FUN_80014cec(0);
      if (cVar4 < '$') {
        if (cVar4 < -0x23) {
          sVar6 = -1;
        }
        else {
          sVar6 = 0;
        }
      }
      else {
        sVar6 = 1;
      }
      sVar5 = sVar6;
      if (DAT_803de5a0 != '\0') {
        sVar5 = 0;
      }
      DAT_803de5a0 = (char)sVar6;
      if (sVar5 < 0) {
        FUN_8000bb38(0,0xf3);
        *(short *)(param_1 + 0xc) = *(short *)(param_1 + 0xc) + -1;
        *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 4;
      }
      else if (0 < sVar5) {
        FUN_8000bb38(0,0xf3);
        *(short *)(param_1 + 0xc) = *(short *)(param_1 + 0xc) + 1;
        *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 8;
      }
      goto LAB_80131fc8;
    }
  }
  if (((*(byte *)(param_1 + 4) & 0x20) == 0) && (uVar3 = FUN_80014e9c(0), (uVar3 & 0x100) != 0)) {
    FUN_8000bb38(0,0xf4);
    *(ushort *)(param_1 + 0xc) = *(ushort *)(param_1 + 0xc) ^ 1;
  }
LAB_80131fc8:
  sVar6 = *(short *)(param_1 + 10);
  if (sVar6 < *(short *)(param_1 + 0xc)) {
    if ((*(byte *)(param_1 + 4) & 2) == 0) {
      *(short *)(param_1 + 0xc) = sVar6;
    }
    else {
      *(undefined2 *)(param_1 + 0xc) = 0;
    }
  }
  else if (*(short *)(param_1 + 0xc) < *(short *)(param_1 + 8)) {
    if ((*(byte *)(param_1 + 4) & 2) == 0) {
      *(short *)(param_1 + 0xc) = *(short *)(param_1 + 8);
    }
    else {
      *(short *)(param_1 + 0xc) = sVar6;
    }
  }
  if (sVar2 != *(short *)(param_1 + 0xc)) {
    *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 0x10;
  }
  if (((*(byte *)(param_1 + 4) & 0x80) != 0) && ((*(byte *)(param_1 + 4) & 0x10) != 0)) {
    FUN_8000a304((int)*(short *)(param_1 + 0xc));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8013207c
 * EN v1.0 Address: 0x80131AB8
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8013207C
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013207c(uint param_1)
{
  FUN_800238c4(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8013209c
 * EN v1.0 Address: 0x80131AD8
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x8013209C
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013209c(undefined4 param_1,undefined4 param_2,short param_3,short param_4,short param_5)
{
  undefined2 uVar2;
  int iVar1;
  undefined2 extraout_r4;
  
  uVar2 = FUN_80286840();
  if (param_5 < param_3) {
    param_5 = param_3;
  }
  if (param_4 < param_5) {
    param_5 = param_4;
  }
  iVar1 = FUN_80023d8c(0x12,5);
  *(undefined *)(iVar1 + 5) = 2;
  *(undefined2 *)(iVar1 + 0xe) = uVar2;
  *(undefined2 *)(iVar1 + 0x10) = extraout_r4;
  *(short *)(iVar1 + 0xc) = param_5;
  *(short *)(iVar1 + 8) = param_3;
  *(short *)(iVar1 + 10) = param_4;
  *(undefined *)(iVar1 + 4) = 2;
  *(undefined *)(iVar1 + 6) = 4;
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132144
 * EN v1.0 Address: 0x80131B78
 * EN v1.0 Size: 164b
 * EN v1.1 Address: 0x80132144
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132144(undefined4 param_1,undefined4 param_2,short param_3,short param_4,short param_5)
{
  undefined2 uVar2;
  undefined2 *puVar1;
  undefined2 extraout_r4;
  
  uVar2 = FUN_80286840();
  if (param_5 < param_3) {
    param_5 = param_3;
  }
  if (param_4 < param_5) {
    param_5 = param_4;
  }
  puVar1 = (undefined2 *)FUN_80023d8c(0xe,5);
  *(undefined *)((int)puVar1 + 5) = 1;
  puVar1[6] = param_5;
  puVar1[4] = param_3;
  puVar1[5] = param_4;
  *puVar1 = uVar2;
  puVar1[1] = extraout_r4;
  *(undefined *)(puVar1 + 2) = 0;
  *(undefined *)(puVar1 + 3) = 4;
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801321e8
 * EN v1.0 Address: 0x80131C1C
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x801321E8
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801321e8(undefined4 param_1,undefined4 param_2,short param_3,short param_4,short param_5,
                 undefined2 param_6)
{
  undefined2 uVar2;
  undefined2 *puVar1;
  undefined2 extraout_r4;
  
  uVar2 = FUN_8028683c();
  if (param_5 < param_3) {
    param_5 = param_3;
  }
  if (param_4 < param_5) {
    param_5 = param_4;
  }
  puVar1 = (undefined2 *)FUN_80023d8c(0x10,5);
  *(undefined *)((int)puVar1 + 5) = 0;
  puVar1[6] = param_5;
  puVar1[4] = param_3;
  puVar1[5] = param_4;
  *puVar1 = uVar2;
  puVar1[1] = extraout_r4;
  *(undefined *)(puVar1 + 2) = 0;
  *(undefined *)(puVar1 + 3) = 4;
  puVar1[7] = param_6;
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132294
 * EN v1.0 Address: 0x80131CC4
 * EN v1.0 Size: 288b
 * EN v1.1 Address: 0x80132294
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132294(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  int iVar2;
  short *psVar3;
  int *piVar4;
  
  iVar2 = 0;
  piVar4 = &DAT_803aaa18;
  psVar3 = &DAT_8031cef8;
  do {
    if (*piVar4 == 0) {
      iVar1 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           (int)*psVar3,param_10,param_11,param_12,param_13,param_14,param_15,
                           param_16);
      *piVar4 = iVar1;
    }
    piVar4 = piVar4 + 1;
    psVar3 = psVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 6);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132308
 * EN v1.0 Address: 0x80131DE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80132308
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132308(void)
{
}
