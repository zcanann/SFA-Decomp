// Function: FUN_8000e360
// Entry: 8000e360
// Size: 64 bytes

int FUN_8000e360(void)

{
  FUN_8000e1a0();
  DAT_803dd508 = DAT_803dd508 + '\x01';
  return DAT_803dd508 + -1;
}

