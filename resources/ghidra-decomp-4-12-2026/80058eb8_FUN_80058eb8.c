// Function: FUN_80058eb8
// Entry: 80058eb8
// Size: 364 bytes

void FUN_80058eb8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,short param_11,short param_12,int param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  short *psVar2;
  short *psVar3;
  uint uVar4;
  short sVar5;
  short sVar6;
  undefined8 extraout_f1;
  undefined8 uVar7;
  
  uVar7 = FUN_8028683c();
  psVar2 = DAT_803ddaf8;
  psVar3 = (short *)((ulonglong)uVar7 >> 0x20);
  iVar1 = param_13 * 0x1c;
  FUN_8001f7e0(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803ddaf8,0x1d
               ,*(int *)(DAT_803ddafc + iVar1),
               *(int *)(DAT_803ddafc + iVar1 + 8) - *(int *)(DAT_803ddafc + iVar1),param_13,param_14
               ,param_15,param_16);
  *(int *)(psVar2 + 6) =
       (int)psVar2 + (*(int *)(DAT_803ddafc + iVar1 + 4) - *(int *)(DAT_803ddafc + iVar1));
  *psVar3 = param_11 - psVar2[2];
  psVar3[2] = param_12 - psVar2[3];
  psVar3[1] = *psVar3 + *psVar2 + -1;
  psVar3[3] = psVar3[2] + psVar2[1] + -1;
  *(char *)(psVar3 + 4) = (char)psVar2[2];
  *(char *)((int)psVar3 + 9) = (char)psVar2[3];
  for (sVar6 = 0; sVar6 < psVar2[1]; sVar6 = sVar6 + 1) {
    for (sVar5 = 0; (int)sVar5 < (int)*psVar2; sVar5 = sVar5 + 1) {
      uVar4 = (int)sVar5 + (int)sVar6 * (int)*psVar2;
      if ((*(uint *)(*(int *)(psVar2 + 6) + uVar4 * 4) >> 0x17 & 0xff) != 0xff) {
        *(byte *)((int)uVar7 + ((int)uVar4 >> 3)) =
             *(byte *)((int)uVar7 + ((int)uVar4 >> 3)) | (byte)(1 << (uVar4 & 7));
      }
    }
  }
  FUN_80286888();
  return;
}

