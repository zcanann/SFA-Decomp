// Function: FUN_80219f4c
// Entry: 80219f4c
// Size: 180 bytes

void FUN_80219f4c(undefined2 *param_1,int param_2)

{
  undefined2 uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x1e) << 8);
  *(undefined2 *)(puVar2 + 1) = *(undefined2 *)(param_2 + 0x18);
  *(undefined2 *)((int)puVar2 + 6) = *(undefined2 *)(param_2 + 0x1c);
  uVar1 = FUN_800221a0(0,(int)*(short *)((int)puVar2 + 6));
  *(undefined2 *)(puVar2 + 2) = uVar1;
  *(short *)((int)puVar2 + 10) = (short)*(char *)(param_2 + 0x1f);
  *puVar2 = (uint)*(byte *)(param_2 + 0x20);
  *(byte *)(puVar2 + 6) = *(byte *)(puVar2 + 6) & 0x7f | 0x80;
  FUN_800200e8(0x5dd,0);
  *(code **)(param_1 + 0x5e) = FUN_80219a88;
  return;
}

