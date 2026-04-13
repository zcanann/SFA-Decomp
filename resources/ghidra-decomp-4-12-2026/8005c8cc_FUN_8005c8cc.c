// Function: FUN_8005c8cc
// Entry: 8005c8cc
// Size: 152 bytes

void FUN_8005c8cc(void)

{
  DAT_803dda68 = DAT_803dda68 | 0x21;
  if ((DAT_803ddb24 == '\x01') || (DAT_803ddb24 == '\x03')) {
    DAT_803dda68 = DAT_803dda68 & 0xfffffffe;
  }
  FUN_8000f11c();
  FUN_8005acec();
  FUN_8005ab2c();
  FUN_8000faf8();
  FUN_8000f584();
  FUN_8000fb20();
  FUN_8001f0c0();
  DAT_803ddb28 = FUN_8000facc();
  FUN_8005c2f0();
  FUN_8000e964();
  DAT_803dda68 = DAT_803dda68 & 0xfffffffd;
  return;
}

