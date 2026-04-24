// Function: FUN_80026c88
// Entry: 80026c88
// Size: 116 bytes

void FUN_80026c88(int *param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  for (iVar1 = 0; iVar1 < param_1[1]; iVar1 = iVar1 + 1) {
    FUN_80023800(*(undefined4 *)(*param_1 + iVar2));
    iVar2 = iVar2 + 0xc;
  }
  FUN_80023800(*param_1);
  FUN_80023800(param_1);
  return;
}

