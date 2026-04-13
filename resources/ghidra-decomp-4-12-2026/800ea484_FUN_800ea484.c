// Function: FUN_800ea484
// Entry: 800ea484
// Size: 56 bytes

ushort FUN_800ea484(void)

{
  undefined *puVar1;
  
  puVar1 = FUN_800e82c8();
  return *(ushort *)(&DAT_80312630 + (uint)(byte)puVar1[5] * 2) & 0xff;
}

