// Function: FUN_80244abc
// Entry: 80244abc
// Size: 288 bytes

void FUN_80244abc(void)

{
  uint uVar1;
  
  uVar1 = DAT_800000f0;
  FUN_80243e74();
  if (uVar1 < 0x1800001) {
    FUN_80244aa4();
  }
  else if (uVar1 < 0x3000001) {
    FUN_80244aa4();
  }
  DAT_cc004020 = 0;
  DAT_cc004010 = 0xff;
  FUN_8024423c(0xf0000000);
  FUN_80243ec0(0,&LAB_80244938);
  FUN_80243ec0(1,&LAB_80244938);
  FUN_80243ec0(2,&LAB_80244938);
  FUN_80243ec0(3,&LAB_80244938);
  FUN_80243ec0(4,&LAB_80244938);
  FUN_80244e64(-0x7fcd1ba0);
  if ((DAT_800000f0 < DAT_80000028) && (DAT_800000f0 == 0x1800000)) {
    DAT_cc004028 = 2;
  }
  FUN_802442c4(0x8000000);
  FUN_80243e9c();
  return;
}

