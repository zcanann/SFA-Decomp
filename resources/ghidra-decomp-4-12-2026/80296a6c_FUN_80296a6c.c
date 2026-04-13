// Function: FUN_80296a6c
// Entry: 80296a6c
// Size: 28 bytes

uint FUN_80296a6c(int param_1)

{
  int iVar1;
  
  iVar1 = (int)*(short *)(*(int *)(param_1 + 0xb8) + 0x274);
  return (0x26U - iVar1 | iVar1 - 0x26U) >> 0x1f;
}

