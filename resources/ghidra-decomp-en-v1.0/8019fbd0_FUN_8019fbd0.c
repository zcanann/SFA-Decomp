// Function: FUN_8019fbd0
// Entry: 8019fbd0
// Size: 172 bytes

void FUN_8019fbd0(undefined2 *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *(undefined *)(iVar2 + 0x38) = 1;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(code **)(param_1 + 0x5e) = FUN_8019f540;
  FUN_80037964(param_1,4);
  *(undefined *)(iVar2 + 0x36) = 1;
  iVar1 = FUN_8001ffb4(0x4d);
  if (iVar1 != 0) {
    *(byte *)(iVar2 + 0x38) = *(byte *)(iVar2 + 0x38) | 4;
  }
  *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xef;
  *(byte *)(iVar2 + 0x39) = *(byte *)(iVar2 + 0x39) & 0x7f | 0x80;
  return;
}

