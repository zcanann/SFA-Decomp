// Function: FUN_80279fac
// Entry: 80279fac
// Size: 128 bytes

void FUN_80279fac(int param_1)

{
  int iVar1;
  
  if (param_1 != -1) {
    iVar1 = FUN_80283254(param_1);
    if (iVar1 != 0) {
      FUN_8028343c(param_1);
    }
    iVar1 = param_1 * 0x404;
    *(int *)(DAT_803de268 + iVar1 + 0xf4) = param_1;
    FUN_80279b98(DAT_803de268 + iVar1);
    *(undefined *)(DAT_803de268 + iVar1 + 0x11c) = 0;
  }
  return;
}

