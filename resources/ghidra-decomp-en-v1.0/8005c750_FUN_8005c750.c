// Function: FUN_8005c750
// Entry: 8005c750
// Size: 152 bytes

void FUN_8005c750(void)

{
  DAT_803dcde8 = DAT_803dcde8 | 0x21;
  if ((DAT_803dcea4 == '\x01') || (DAT_803dcea4 == '\x03')) {
    DAT_803dcde8 = DAT_803dcde8 & 0xfffffffe;
  }
  FUN_8000f0fc(0,0);
  FUN_8005ab70();
  FUN_8005a9b0();
  FUN_8000fad8();
  FUN_8000f564();
  FUN_8000fb00();
  FUN_8001effc();
  DAT_803dcea8 = FUN_8000faac();
  FUN_8005c174();
  FUN_8000e944(0);
  DAT_803dcde8 = DAT_803dcde8 & 0xfffffffd;
  return;
}

