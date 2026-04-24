// Function: FUN_802090c4
// Entry: 802090c4
// Size: 424 bytes

void FUN_802090c4(int param_1)

{
  int iVar1;
  byte bVar2;
  short *psVar3;
  
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 4) == '\0') &&
     (iVar1 = FUN_8001ffb4((int)*(short *)(*(int *)(param_1 + 0xb8) + 2)), iVar1 != 0)) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  FUN_80041018(param_1);
  if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
    bVar2 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
    if (bVar2 == 2) {
      psVar3 = *(short **)(param_1 + 0xb8);
      iVar1 = (**(code **)(*DAT_803dca68 + 0x20))(0x83c);
      if (iVar1 != 0) {
        FUN_800200e8((int)*psVar3,1);
        FUN_800200e8((int)psVar3[1],0);
        *(undefined *)(psVar3 + 2) = 1;
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
        (**(code **)(*DAT_803dcaac + 0x44))(7,8);
        (**(code **)(*DAT_803dcaac + 0x44))(0xd,2);
      }
    }
    else if ((bVar2 < 2) && (bVar2 != 0)) {
      psVar3 = *(short **)(param_1 + 0xb8);
      iVar1 = (**(code **)(*DAT_803dca68 + 0x20))(0x2e8);
      if (iVar1 != 0) {
        FUN_800200e8((int)*psVar3,1);
        FUN_800200e8((int)psVar3[1],0);
        *(undefined *)(psVar3 + 2) = 1;
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
    }
  }
  return;
}

