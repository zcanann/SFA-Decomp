// Function: FUN_8021a5f4
// Entry: 8021a5f4
// Size: 180 bytes

void FUN_8021a5f4(undefined2 *param_1,int param_2)

{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x1e) << 8);
  *(undefined2 *)(puVar2 + 1) = *(undefined2 *)(param_2 + 0x18);
  *(undefined2 *)((int)puVar2 + 6) = *(undefined2 *)(param_2 + 0x1c);
  uVar1 = FUN_80022264(0,(int)*(short *)((int)puVar2 + 6));
  *(short *)(puVar2 + 2) = (short)uVar1;
  *(short *)((int)puVar2 + 10) = (short)*(char *)(param_2 + 0x1f);
  *puVar2 = (uint)*(byte *)(param_2 + 0x20);
  *(byte *)(puVar2 + 6) = *(byte *)(puVar2 + 6) & 0x7f | 0x80;
  FUN_800201ac(0x5dd,0);
  *(code **)(param_1 + 0x5e) = FUN_8021a100;
  return;
}

