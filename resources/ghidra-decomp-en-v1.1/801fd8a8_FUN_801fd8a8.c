// Function: FUN_801fd8a8
// Entry: 801fd8a8
// Size: 264 bytes

void FUN_801fd8a8(int param_1)

{
  int iVar1;
  uint uVar2;
  short sVar4;
  int iVar3;
  short *psVar5;
  double dVar6;
  
  psVar5 = *(short **)(param_1 + 0xb8);
  sVar4 = 1;
  iVar1 = FUN_8002bac4();
  if (iVar1 != 0) {
    if ((int)psVar5[1] != 0xffffffff) {
      uVar2 = FUN_80020078((int)psVar5[1]);
      sVar4 = (short)uVar2;
    }
    uVar2 = FUN_80020078((int)*psVar5);
    if ((((short)uVar2 == 0) && (*(char *)(psVar5 + 2) == '\0')) && (sVar4 != 0)) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      iVar3 = (**(code **)(*DAT_803dd6e8 + 0x20))(DAT_803de948);
      if ((iVar3 != 0) &&
         (dVar6 = (double)FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar1 + 0x18)),
         dVar6 < (double)FLOAT_803e6de8)) {
        FUN_800201ac((int)*psVar5,1);
        *(undefined *)(psVar5 + 2) = 1;
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
    }
  }
  return;
}

