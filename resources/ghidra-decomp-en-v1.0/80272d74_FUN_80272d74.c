// Function: FUN_80272d74
// Entry: 80272d74
// Size: 240 bytes

void FUN_80272d74(uint param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = 0;
  for (uVar2 = 0; uVar2 < DAT_803bd360; uVar2 = uVar2 + 1) {
    iVar1 = DAT_803de268 + iVar3;
    if ((param_1 & 0xff) == (uint)*(byte *)(iVar1 + 0x11f)) {
      if (*(int *)(iVar1 + 0xf4) == -1) {
        iVar1 = FUN_80283254(uVar2);
        if (iVar1 != 0) {
          FUN_80283b0c(uVar2);
        }
      }
      else {
        FUN_8027a0cc(*(undefined4 *)(*(int *)(iVar1 + 0xf8) + 8));
      }
    }
    iVar3 = iVar3 + 0x404;
  }
  FUN_80284af4();
  (&DAT_803bd9c4)[param_1 & 0xff] = 0;
  (&DAT_803bda04)[param_1 & 0xff] = 0;
  (&DAT_803de254)[param_1 & 0xff] = 0xff;
  (&DAT_803de244)[param_1 & 0xff] = 0xff;
  FUN_80284abc();
  FUN_80283b80(param_1);
  return;
}

