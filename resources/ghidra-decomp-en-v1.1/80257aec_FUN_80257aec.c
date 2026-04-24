// Function: FUN_80257aec
// Entry: 80257aec
// Size: 112 bytes

void FUN_80257aec(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  iVar1 = 0;
  do {
    *(int *)(param_1 + iVar2) = iVar1;
    FUN_80257938(iVar1,(uint *)((int *)(param_1 + iVar2) + 1));
    iVar1 = iVar1 + 1;
    iVar2 = iVar2 + 8;
  } while (iVar1 < 0x1a);
  *(undefined4 *)(param_1 + iVar1 * 8) = 0xff;
  return;
}

