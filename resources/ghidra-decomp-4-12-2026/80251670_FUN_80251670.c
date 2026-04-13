// Function: FUN_80251670
// Entry: 80251670
// Size: 184 bytes

void FUN_80251670(void)

{
  ushort uVar1;
  
  FUN_80251830();
  if (DAT_803dece0 != 1) {
    FUN_80243e74();
    FUN_80243ec0(7,&LAB_80251880);
    FUN_802442c4(0x1000000);
    uVar1 = DAT_cc00500a;
    DAT_cc00500a = uVar1 & 0xff57 | 0x800;
    uVar1 = DAT_cc00500a;
    DAT_cc00500a = uVar1 & 0xff53;
    DAT_803decf0 = 0;
    DAT_803decfc = 0;
    DAT_803decf4 = 0;
    DAT_803decf8 = 0;
    DAT_803dece0 = 1;
    FUN_80243e9c();
  }
  return;
}

