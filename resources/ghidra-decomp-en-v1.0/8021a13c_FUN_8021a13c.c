// Function: FUN_8021a13c
// Entry: 8021a13c
// Size: 268 bytes

undefined4 FUN_8021a13c(int param_1)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  int iVar4;
  undefined4 uVar5;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  piVar3 = *(int **)(param_1 + 0xb8);
  if (*piVar3 == 0) {
    iVar1 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x1e));
    if (iVar1 != 0) {
      FUN_8000b7bc(param_1,8);
      return 4;
    }
    uVar2 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x20));
    if (*(byte *)(piVar3 + 1) >> 7 != uVar2) {
      FUN_8000bb18(param_1,0x192);
      FUN_8000bb18(param_1,0x193);
      iVar1 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x20));
      if (iVar1 == 0) {
        FUN_8000b7bc(param_1,8);
      }
      else {
        FUN_8000bb18(param_1,0x194);
      }
    }
    uVar2 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x20));
    *(byte *)(piVar3 + 1) = (byte)((uVar2 & 0xff) << 7) | *(byte *)(piVar3 + 1) & 0x7f;
  }
  uVar5 = 0;
  if ((*piVar3 == 0) && (iVar4 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x20)), iVar4 == 0)) {
    uVar5 = 1;
  }
  return uVar5;
}

