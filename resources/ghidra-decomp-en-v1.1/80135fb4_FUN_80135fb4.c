// Function: FUN_80135fb4
// Entry: 80135fb4
// Size: 152 bytes

void FUN_80135fb4(int param_1)

{
  char in_r8;
  
  if ((in_r8 != '\0') && (DAT_803de62b != '\0')) {
    FUN_8003b9ec(param_1);
    if ((DAT_803de613 != '\0') && (DAT_803de62a == '\0')) {
      FUN_800201ac(0xdf6,1);
      DAT_803de62a = '\x01';
      (**(code **)(*DAT_803dd6d4 + 0x50))(0x57,0,0,0);
      FUN_801163b8();
      DAT_803de624 = 0;
    }
  }
  return;
}

