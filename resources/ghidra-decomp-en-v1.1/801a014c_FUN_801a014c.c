// Function: FUN_801a014c
// Entry: 801a014c
// Size: 172 bytes

void FUN_801a014c(undefined2 *param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *(undefined *)(iVar2 + 0x38) = 1;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(code **)(param_1 + 0x5e) = FUN_8019fabc;
  FUN_80037a5c((int)param_1,4);
  *(undefined *)(iVar2 + 0x36) = 1;
  uVar1 = FUN_80020078(0x4d);
  if (uVar1 != 0) {
    *(byte *)(iVar2 + 0x38) = *(byte *)(iVar2 + 0x38) | 4;
  }
  *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xef;
  *(byte *)(iVar2 + 0x39) = *(byte *)(iVar2 + 0x39) & 0x7f | 0x80;
  return;
}

