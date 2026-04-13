// Function: FUN_801a51ac
// Entry: 801a51ac
// Size: 440 bytes

void FUN_801a51ac(int param_1)

{
  uint uVar1;
  int iVar2;
  short *psVar3;
  float *pfVar4;
  
  pfVar4 = *(float **)(param_1 + 0xb8);
  pfVar4[2] = 0.0;
  *(undefined *)((int)pfVar4 + 0xd) = 0xff;
  FUN_800803f8(pfVar4);
  FUN_80080404(pfVar4,0x1e0);
  *(byte *)(pfVar4 + 3) = *(byte *)(pfVar4 + 3) & 0xbf;
  *(code **)(param_1 + 0xbc) = FUN_801a4ad8;
  iVar2 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
  FUN_800201ac(0x983,(0x2cefU - iVar2 | iVar2 - 0x2cefU) >> 0x1f);
  uVar1 = FUN_80020078(0x2fe);
  if (uVar1 == 0) {
    iVar2 = 0;
    psVar3 = &DAT_80323c58;
    do {
      FUN_800201ac((int)*psVar3,0);
      psVar3 = psVar3 + 1;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 0x17);
  }
  (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),4,0);
  (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),0x11,0);
  (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),0x15,0);
  (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),0x16,0);
  uVar1 = FUN_80020078(0x974);
  *(byte *)(pfVar4 + 3) = (byte)((uVar1 & 0xff) << 5) & 0x20 | *(byte *)(pfVar4 + 3) & 0xdf;
  uVar1 = FUN_80020078(0x975);
  *(byte *)(pfVar4 + 3) = (byte)((uVar1 & 0xff) << 4) & 0x10 | *(byte *)(pfVar4 + 3) & 0xef;
  FUN_8002b9a0(param_1,'Q');
  *(byte *)(pfVar4 + 3) = *(byte *)(pfVar4 + 3) & 0xf7 | 8;
  return;
}

