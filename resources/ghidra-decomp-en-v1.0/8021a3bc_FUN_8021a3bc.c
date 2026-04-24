// Function: FUN_8021a3bc
// Entry: 8021a3bc
// Size: 104 bytes

void FUN_8021a3bc(int param_1,int param_2)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = *(undefined4 **)(param_1 + 0xb8);
  *(code **)(param_1 + 0xbc) = FUN_8021a13c;
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  if (iVar1 == 0) {
    *puVar2 = 0;
  }
  else {
    *(byte *)(puVar2 + 1) = *(byte *)(puVar2 + 1) & 0xdf | 0x20;
    *puVar2 = 2;
  }
  return;
}

