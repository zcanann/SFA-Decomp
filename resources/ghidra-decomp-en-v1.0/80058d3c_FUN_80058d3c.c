// Function: FUN_80058d3c
// Entry: 80058d3c
// Size: 364 bytes

void FUN_80058d3c(undefined4 param_1,undefined4 param_2,short param_3,short param_4,int param_5)

{
  short *psVar1;
  short *psVar2;
  uint uVar3;
  short sVar4;
  short sVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_802860d8();
  psVar1 = DAT_803dce78;
  psVar2 = (short *)((ulonglong)uVar6 >> 0x20);
  param_5 = param_5 * 0x1c;
  FUN_8001f71c(DAT_803dce78,0x1d,*(int *)(DAT_803dce7c + param_5),
               *(int *)(DAT_803dce7c + param_5 + 8) - *(int *)(DAT_803dce7c + param_5));
  *(int *)(psVar1 + 6) =
       (int)psVar1 + (*(int *)(DAT_803dce7c + param_5 + 4) - *(int *)(DAT_803dce7c + param_5));
  *psVar2 = param_3 - psVar1[2];
  psVar2[2] = param_4 - psVar1[3];
  psVar2[1] = *psVar2 + *psVar1 + -1;
  psVar2[3] = psVar2[2] + psVar1[1] + -1;
  *(char *)(psVar2 + 4) = (char)psVar1[2];
  *(char *)((int)psVar2 + 9) = (char)psVar1[3];
  for (sVar5 = 0; sVar5 < psVar1[1]; sVar5 = sVar5 + 1) {
    for (sVar4 = 0; (int)sVar4 < (int)*psVar1; sVar4 = sVar4 + 1) {
      uVar3 = (int)sVar4 + (int)sVar5 * (int)*psVar1;
      if ((*(uint *)(*(int *)(psVar1 + 6) + uVar3 * 4) >> 0x17 & 0xff) != 0xff) {
        *(byte *)((int)uVar6 + ((int)uVar3 >> 3)) =
             *(byte *)((int)uVar6 + ((int)uVar3 >> 3)) | (byte)(1 << (uVar3 & 7));
      }
    }
  }
  FUN_80286124();
  return;
}

