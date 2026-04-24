// Function: FUN_80035fcc
// Entry: 80035fcc
// Size: 120 bytes

int FUN_80035fcc(int param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_80022e24(param_2);
  *(int *)(param_1 + 0x54) = iVar1;
  iVar2 = *(int *)(param_1 + 0x54);
  FUN_80036044(param_1);
  *(undefined *)(iVar2 + 0xae) = 1;
  if ((*(byte *)(iVar2 + 0x62) & 0x30) != 0) {
    *(undefined *)(iVar2 + 0xaf) = 2;
  }
  return iVar1 + 0xb8;
}

