// Function: FUN_80248300
// Entry: 80248300
// Size: 44 bytes

undefined4 FUN_80248300(undefined4 param_1)

{
  write_volatile_4(DAT_cc006004,2);
  DAT_803ddea0 = 0;
  DAT_803ddea8 = param_1;
  DAT_803ddebc = 1;
  return 1;
}

