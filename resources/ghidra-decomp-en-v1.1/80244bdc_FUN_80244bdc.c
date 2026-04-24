// Function: FUN_80244bdc
// Entry: 80244bdc
// Size: 112 bytes

void FUN_80244bdc(int param_1)

{
  int *piVar1;
  int iVar2;
  
  while (piVar1 = *(int **)(param_1 + 0x2f4), piVar1 != (int *)0x0) {
    iVar2 = piVar1[4];
    if (iVar2 == 0) {
      *(undefined4 *)(param_1 + 0x2f8) = 0;
    }
    else {
      *(undefined4 *)(iVar2 + 0x14) = 0;
    }
    *(int *)(param_1 + 0x2f4) = iVar2;
    piVar1[3] = 0;
    piVar1[2] = 0;
    FUN_802472b0(piVar1);
  }
  return;
}

