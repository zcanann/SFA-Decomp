// Function: FUN_8029fddc
// Entry: 8029fddc
// Size: 104 bytes

void FUN_8029fddc(int param_1)

{
  undefined2 *puVar1;
  
  *(uint *)(*(int *)(param_1 + 100) + 0x30) = *(uint *)(*(int *)(param_1 + 100) + 0x30) & 0xffffefff
  ;
  *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xfff7;
  *(undefined2 *)(param_1 + 0xa2) = 0xffff;
  puVar1 = (undefined2 *)FUN_800396d0(param_1,9);
  if (puVar1 != (undefined2 *)0x0) {
    *puVar1 = 0;
    puVar1[1] = 0;
    puVar1[2] = 0;
  }
  return;
}

