// Function: FUN_8019c4ac
// Entry: 8019c4ac
// Size: 96 bytes

void FUN_8019c4ac(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (param_2 == 0) {
    iVar2 = 0;
    do {
      if (*(int *)(iVar1 + 0x68c) != 0) {
        FUN_8002cbc4();
      }
      iVar1 = iVar1 + 4;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 6);
  }
  return;
}

