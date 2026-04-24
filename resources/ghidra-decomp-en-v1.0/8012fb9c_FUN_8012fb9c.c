// Function: FUN_8012fb9c
// Entry: 8012fb9c
// Size: 336 bytes

void FUN_8012fb9c(void)

{
  int iVar1;
  int *piVar2;
  byte bVar3;
  
  FUN_802860d4();
  iVar1 = 0;
  piVar2 = &DAT_803a89b0;
  do {
    if (*piVar2 != 0) {
      FUN_80054308();
    }
    piVar2 = piVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 0x66);
  FUN_8011f250();
  for (bVar3 = 0; bVar3 < 0x40; bVar3 = bVar3 + 1) {
    if ((&DAT_803a91b8)[bVar3] != 0) {
      FUN_80054308();
      (&DAT_803a91b8)[bVar3] = 0;
    }
    (&DAT_803a9138)[bVar3] = 0xffff;
    (&DAT_803a8c38)[bVar3] = 1;
  }
  if (DAT_803dd7c8 != 0) {
    FUN_80054308();
    DAT_803dd7c8 = 0;
  }
  if (DAT_803dd834 != 0) {
    FUN_80054308();
  }
  DAT_803dd830 = 0xffff;
  DAT_803dd834 = 0;
  for (bVar3 = 0; bVar3 < 0x40; bVar3 = bVar3 + 1) {
    if ((&DAT_803a91b8)[bVar3] != 0) {
      FUN_80054308();
      (&DAT_803a91b8)[bVar3] = 0;
    }
    (&DAT_803a9138)[bVar3] = 0xffff;
    (&DAT_803a8c38)[bVar3] = 1;
  }
  FUN_80054308(DAT_803dd8c4);
  FUN_80286120();
  return;
}

