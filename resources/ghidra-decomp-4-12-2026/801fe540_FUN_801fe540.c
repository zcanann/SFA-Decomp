// Function: FUN_801fe540
// Entry: 801fe540
// Size: 368 bytes

void FUN_801fe540(int param_1)

{
  uint uVar1;
  byte bVar3;
  int iVar2;
  short *psVar4;
  
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 4) == '\0') &&
     (uVar1 = FUN_80020078((int)*(short *)(*(int *)(param_1 + 0xb8) + 2)), uVar1 != 0)) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  FUN_80041110();
  if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
    bVar3 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0xac));
    if (bVar3 == 2) {
      psVar4 = *(short **)(param_1 + 0xb8);
      iVar2 = (**(code **)(*DAT_803dd6e8 + 0x20))(0x83b);
      if (iVar2 != 0) {
        FUN_800201ac((int)*psVar4,1);
        FUN_800201ac((int)psVar4[1],0);
        *(undefined *)(psVar4 + 2) = 1;
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
    }
    else if ((bVar3 < 2) && (bVar3 != 0)) {
      psVar4 = *(short **)(param_1 + 0xb8);
      iVar2 = (**(code **)(*DAT_803dd6e8 + 0x20))(0x123);
      if (iVar2 != 0) {
        FUN_800201ac((int)*psVar4,1);
        FUN_800201ac((int)psVar4[1],0);
        *(undefined *)(psVar4 + 2) = 1;
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
    }
  }
  return;
}

