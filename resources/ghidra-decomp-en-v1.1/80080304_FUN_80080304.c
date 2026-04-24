// Function: FUN_80080304
// Entry: 80080304
// Size: 136 bytes

void FUN_80080304(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  
  for (iVar2 = 0; iVar2 < param_2; iVar2 = iVar2 + 1) {
    iVar3 = 0;
    if (0 < param_2) {
      if ((8 < param_2) && (uVar4 = param_2 - 1U >> 3, 0 < param_2 + -8)) {
        do {
          iVar3 = iVar3 + 8;
          uVar4 = uVar4 - 1;
        } while (uVar4 != 0);
      }
      iVar1 = param_2 - iVar3;
      if (iVar3 < param_2) {
        do {
          iVar1 = iVar1 + -1;
        } while (iVar1 != 0);
      }
    }
  }
  if (0x10 < param_2) {
    FUN_80080138(param_1,param_2);
  }
  return;
}

