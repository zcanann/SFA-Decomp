// Function: FUN_801a4bf8
// Entry: 801a4bf8
// Size: 440 bytes

void FUN_801a4bf8(int param_1)

{
  uint uVar1;
  int iVar2;
  short *psVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  *(undefined4 *)(iVar4 + 8) = 0;
  *(undefined *)(iVar4 + 0xd) = 0xff;
  FUN_8008016c(iVar4);
  FUN_80080178(iVar4,0x1e0);
  *(byte *)(iVar4 + 0xc) = *(byte *)(iVar4 + 0xc) & 0xbf;
  *(code **)(param_1 + 0xbc) = FUN_801a4524;
  iVar2 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
  FUN_800200e8(0x983,(0x2cefU - iVar2 | iVar2 - 0x2cefU) >> 0x1f);
  iVar2 = FUN_8001ffb4(0x2fe);
  if (iVar2 == 0) {
    iVar2 = 0;
    psVar3 = &DAT_80323008;
    do {
      FUN_800200e8((int)*psVar3,0);
      psVar3 = psVar3 + 1;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 0x17);
  }
  (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),4,0);
  (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0x11,0);
  (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0x15,0);
  (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0x16,0);
  uVar1 = FUN_8001ffb4(0x974);
  *(byte *)(iVar4 + 0xc) = (byte)((uVar1 & 0xff) << 5) & 0x20 | *(byte *)(iVar4 + 0xc) & 0xdf;
  uVar1 = FUN_8001ffb4(0x975);
  *(byte *)(iVar4 + 0xc) = (byte)((uVar1 & 0xff) << 4) & 0x10 | *(byte *)(iVar4 + 0xc) & 0xef;
  FUN_8002b8c8(param_1,0x51);
  *(byte *)(iVar4 + 0xc) = *(byte *)(iVar4 + 0xc) & 0xf7 | 8;
  return;
}

