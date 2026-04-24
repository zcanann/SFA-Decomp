// Function: FUN_80114b1c
// Entry: 80114b1c
// Size: 148 bytes

void FUN_80114b1c(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  uVar1 = FUN_800394a0();
  iVar2 = *(int *)(param_1 + 0xb8);
  (**(code **)(*DAT_803dca50 + 0x48))(0);
  *(undefined *)(iVar2 + 0x600) = 0;
  FUN_8003acfc(param_1,uVar1,*(undefined *)(iVar2 + 0x610),iVar2 + 0x1c);
  *(undefined4 *)(iVar2 + 0x5f8) = 0x50;
  FUN_8003a9c0(iVar2 + 0x1c,*(undefined *)(iVar2 + 0x610),0,0);
  return;
}

