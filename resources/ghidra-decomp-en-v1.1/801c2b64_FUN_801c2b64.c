// Function: FUN_801c2b64
// Entry: 801c2b64
// Size: 132 bytes

void FUN_801c2b64(int param_1,int param_2)

{
  undefined4 *puVar1;
  
  puVar1 = *(undefined4 **)(param_1 + 0xb8);
  if ((&DAT_803dcbc0)[*(byte *)(param_2 + 0x1b)] == '\0') {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xff7f;
  }
  FUN_800372f8(param_1,0x17);
  *(code **)(param_1 + 0xbc) = FUN_801c21a4;
  puVar1[0xb] = 0;
  *puVar1 = 0;
  *(undefined *)(param_1 + 0x36) = 0x46;
  return;
}

