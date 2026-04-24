// Function: FUN_8021a694
// Entry: 8021a694
// Size: 128 bytes

void FUN_8021a694(int param_1,int param_2)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  if (((*piVar1 != 0) && (param_2 == 0)) && (*(int *)(*piVar1 + 0x50) != 0)) {
    if (piVar1[1] != 0) {
      *(undefined4 *)(piVar1[1] + 0xf4) = 0;
    }
    *(undefined4 *)(*piVar1 + 0xf4) = 0;
    FUN_8002cbc4(*piVar1);
  }
  FUN_80036fa4(param_1,0x18);
  return;
}

