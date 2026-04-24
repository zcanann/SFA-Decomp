// Function: FUN_80257388
// Entry: 80257388
// Size: 112 bytes

void FUN_80257388(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  iVar1 = 0;
  do {
    *(int *)(param_1 + iVar2) = iVar1;
    FUN_802571d4(iVar1,(int *)(param_1 + iVar2) + 1);
    iVar1 = iVar1 + 1;
    iVar2 = iVar2 + 8;
  } while (iVar1 < 0x1a);
  *(undefined4 *)(param_1 + iVar1 * 8) = 0xff;
  return;
}

