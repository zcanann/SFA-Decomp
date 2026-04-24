// Function: FUN_800968c4
// Entry: 800968c4
// Size: 208 bytes

void FUN_800968c4(void)

{
  int iVar1;
  
  iVar1 = FUN_80023cc8(0x22b0,0x13,0);
  if (iVar1 == 0) {
    FUN_801378a8(s_Could_not_allocate_memory_for_wa_8030f86c);
  }
  else {
    DAT_803dd240 = iVar1 + 0x3c0;
    DAT_803dd24c = iVar1 + 0x780;
    DAT_803dd244 = iVar1 + 0xf00;
    DAT_803dd238 = iVar1 + 0x1680;
    DAT_803dd230 = iVar1 + 0x19c8;
    DAT_803dd220 = iVar1 + 0x1c20;
    DAT_803dd228 = iVar1 + 0x1f68;
    DAT_803dd23c = 0;
    DAT_803dd234 = 0;
    DAT_803dd224 = 0;
    DAT_803dd22c = 0;
    DAT_803dd248 = iVar1;
    DAT_803dd21c = FUN_80054d54(0x56);
    DAT_803dd218 = FUN_80054d54(0xc2a);
    DAT_803dd214 = FUN_80054d54(0xc2c);
    DAT_803dd210 = FUN_80054d54(0xc2d);
    FUN_800964dc();
    FUN_800953fc();
  }
  return;
}

