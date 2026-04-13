// Function: FUN_8021a7e4
// Entry: 8021a7e4
// Size: 268 bytes

undefined4 FUN_8021a7e4(uint param_1)

{
  uint uVar1;
  int *piVar2;
  int iVar3;
  undefined4 uVar4;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  piVar2 = *(int **)(param_1 + 0xb8);
  if (*piVar2 == 0) {
    uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x1e));
    if (uVar1 != 0) {
      FUN_8000b7dc(param_1,8);
      return 4;
    }
    uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x20));
    if (*(byte *)(piVar2 + 1) >> 7 != uVar1) {
      FUN_8000bb38(param_1,0x192);
      FUN_8000bb38(param_1,0x193);
      uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x20));
      if (uVar1 == 0) {
        FUN_8000b7dc(param_1,8);
      }
      else {
        FUN_8000bb38(param_1,0x194);
      }
    }
    uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x20));
    *(byte *)(piVar2 + 1) = (byte)((uVar1 & 0xff) << 7) | *(byte *)(piVar2 + 1) & 0x7f;
  }
  uVar4 = 0;
  if ((*piVar2 == 0) && (uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x20)), uVar1 == 0)) {
    uVar4 = 1;
  }
  return uVar4;
}

