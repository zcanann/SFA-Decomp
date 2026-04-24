// Function: FUN_8021b008
// Entry: 8021b008
// Size: 180 bytes

void FUN_8021b008(int param_1)

{
  int iVar1;
  char in_r8;
  int iVar2;
  int *piVar3;
  int *piVar4;
  
  piVar3 = *(int **)(param_1 + 0xb8);
  if ((-1 < *(char *)((int)piVar3 + 0x1a)) && (in_r8 != '\0')) {
    FUN_8003b8f4((double)FLOAT_803e6a2c);
    piVar4 = piVar3;
    for (iVar2 = 0; iVar2 < piVar3[5]; iVar2 = iVar2 + 1) {
      iVar1 = *piVar4;
      if (iVar1 != 0) {
        FUN_8003842c(param_1,*(undefined *)((int)piVar3 + iVar2 + 0x1b),iVar1 + 0xc,iVar1 + 0x10,
                     iVar1 + 0x14,0);
      }
      piVar4 = piVar4 + 1;
    }
  }
  return;
}

