// Function: FUN_80239778
// Entry: 80239778
// Size: 108 bytes

void FUN_80239778(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  if (*piVar1 != 0) {
    FUN_80023800();
    *piVar1 = 0;
  }
  *(byte *)((int)piVar1 + 0x1b) = *(byte *)((int)piVar1 + 0x1b) & 0xf;
  *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  return;
}

