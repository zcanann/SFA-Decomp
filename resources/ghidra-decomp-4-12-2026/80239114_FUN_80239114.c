// Function: FUN_80239114
// Entry: 80239114
// Size: 148 bytes

void FUN_80239114(int param_1,int param_2)

{
  undefined4 *puVar1;
  
  puVar1 = *(undefined4 **)(param_1 + 0xb8);
  FUN_800803f8(puVar1);
  *(undefined *)(puVar1 + 3) = *(undefined *)(param_2 + 0x19);
  puVar1[2] = FLOAT_803e80bc;
  *(byte *)((int)puVar1 + 0xd) = *(byte *)((int)puVar1 + 0xd) & 0x7f;
  *(byte *)((int)puVar1 + 0xd) = *(byte *)((int)puVar1 + 0xd) & 0xbf;
  puVar1[1] = 0;
  FUN_800372f8(param_1,0x4c);
  *(byte *)((int)puVar1 + 0xd) = *(byte *)((int)puVar1 + 0xd) & 0xdf;
  return;
}

