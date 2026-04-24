// Function: FUN_80241588
// Entry: 80241588
// Size: 124 bytes

void FUN_80241588(int param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = DAT_803dde10 + param_1 * 0xc;
  uVar2 = *(undefined4 *)(iVar3 + 8);
  if (*(int **)(param_2 + -0x1c) != (int *)0x0) {
    **(int **)(param_2 + -0x1c) = *(int *)(param_2 + -0x20);
  }
  iVar1 = *(int *)(param_2 + -0x20);
  if (iVar1 == 0) {
    uVar2 = *(undefined4 *)(param_2 + -0x1c);
  }
  else {
    *(undefined4 *)(iVar1 + 4) = *(undefined4 *)(param_2 + -0x1c);
  }
  *(undefined4 *)(iVar3 + 8) = uVar2;
  uVar2 = FUN_802413e0(*(undefined4 *)(iVar3 + 4));
  *(undefined4 *)(iVar3 + 4) = uVar2;
  return;
}

