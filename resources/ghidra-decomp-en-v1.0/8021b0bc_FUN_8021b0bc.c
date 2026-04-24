// Function: FUN_8021b0bc
// Entry: 8021b0bc
// Size: 188 bytes

void FUN_8021b0bc(int param_1)

{
  int iVar1;
  int iVar2;
  double dVar3;
  undefined auStack40 [16];
  longlong local_18;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_8000b578(param_1,1);
  if ((iVar1 == 0) && (*(char *)(iVar2 + 0x1a) < '\0')) {
    FUN_80247754(param_1 + 0xc,iVar2 + 8,auStack40);
    dVar3 = (double)FUN_802477f0(auStack40);
    local_18 = (longlong)(int)((double)FLOAT_803e6a30 * dVar3);
    iVar1 = 200 - (int)((double)FLOAT_803e6a30 * dVar3);
    if (iVar1 < 1) {
      iVar1 = 1;
    }
    else if (200 < iVar1) {
      iVar1 = 200;
    }
    iVar1 = FUN_800221a0(0,iVar1);
    if (iVar1 == 0) {
      FUN_8000bb18(param_1,0x1b3);
    }
  }
  return;
}

