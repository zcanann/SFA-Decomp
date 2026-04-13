// Function: FUN_801319a0
// Entry: 801319a0
// Size: 808 bytes

/* WARNING: Removing unreachable block (ram,0x801319d8) */

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

