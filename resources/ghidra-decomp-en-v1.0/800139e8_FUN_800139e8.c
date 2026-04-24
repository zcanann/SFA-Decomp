// Function: FUN_800139e8
// Entry: 800139e8
// Size: 108 bytes

void FUN_800139e8(int param_1,int param_2)

{
  undefined2 *puVar1;
  
  puVar1 = (undefined2 *)FUN_80023cc8(param_2 * param_1 + 0x10,0x1a,0);
  *(undefined2 **)(puVar1 + 6) = puVar1 + 8;
  *puVar1 = 0;
  puVar1[1] = (short)param_1;
  puVar1[2] = (short)param_2;
  puVar1[4] = 0;
  return;
}

