// Function: FUN_8019ff74
// Entry: 8019ff74
// Size: 72 bytes

void FUN_8019ff74(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_80036974(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
  if (iVar1 == 0x13) {
    *(undefined *)(iVar2 + 0x37) = 7;
  }
  return;
}

