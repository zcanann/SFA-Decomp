// Function: FUN_800360c4
// Entry: 800360c4
// Size: 120 bytes

int FUN_800360c4(int param_1,uint param_2)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = FUN_80022ee8(param_2);
  *(uint *)(param_1 + 0x54) = uVar1;
  iVar2 = *(int *)(param_1 + 0x54);
  FUN_8003613c(param_1);
  *(undefined *)(iVar2 + 0xae) = 1;
  if ((*(byte *)(iVar2 + 0x62) & 0x30) != 0) {
    *(undefined *)(iVar2 + 0xaf) = 2;
  }
  return uVar1 + 0xb8;
}

