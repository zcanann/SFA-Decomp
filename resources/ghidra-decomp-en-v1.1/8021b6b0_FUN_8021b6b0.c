// Function: FUN_8021b6b0
// Entry: 8021b6b0
// Size: 180 bytes

void FUN_8021b6b0(int param_1)

{
  int iVar1;
  char in_r8;
  int iVar2;
  int *piVar3;
  int *piVar4;
  
  piVar3 = *(int **)(param_1 + 0xb8);
  if ((-1 < *(char *)((int)piVar3 + 0x1a)) && (in_r8 != '\0')) {
    FUN_8003b9ec(param_1);
    piVar4 = piVar3;
    for (iVar2 = 0; iVar2 < piVar3[5]; iVar2 = iVar2 + 1) {
      iVar1 = *piVar4;
      if (iVar1 != 0) {
        FUN_80038524(param_1,(uint)*(byte *)((int)piVar3 + iVar2 + 0x1b),(float *)(iVar1 + 0xc),
                     (undefined4 *)(iVar1 + 0x10),(float *)(iVar1 + 0x14),0);
      }
      piVar4 = piVar4 + 1;
    }
  }
  return;
}

