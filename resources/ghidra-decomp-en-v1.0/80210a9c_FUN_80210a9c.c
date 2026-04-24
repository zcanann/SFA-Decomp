// Function: FUN_80210a9c
// Entry: 80210a9c
// Size: 236 bytes

void FUN_80210a9c(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(int *)(param_1 + 0xf8) == 0) {
    iVar1 = FUN_8001ffb4(0xdcb);
    if (iVar1 != 0) {
      FUN_80008b74(param_1,param_1,0x174,0);
      FUN_80008b74(param_1,param_1,0x1e1,0);
      FUN_800200e8(0xdcb,0);
      FUN_8004350c(0,0,1);
    }
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  FUN_802107cc(param_1);
  *(byte *)(iVar2 + 9) = *(byte *)(iVar2 + 9) & 0xfe;
  FUN_801d7ed4(iVar2 + 0xc,1,0xffffffff,0xffffffff,0xe24,0xe8);
  FUN_801d7ed4(iVar2 + 0xc,2,0xffffffff,0xffffffff,0xe24,0x38);
  return;
}

