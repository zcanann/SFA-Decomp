// Function: FUN_80254b20
// Entry: 80254b20
// Size: 276 bytes

void FUN_80254b20(void)

{
  uint uVar1;
  
  FUN_8024423c(0x7f8000);
  DAT_cc006800 = 0;
  DAT_cc006814 = 0;
  DAT_cc006828 = 0;
  DAT_cc006800 = 0x2000;
  FUN_80243ec0(9,&LAB_80254770);
  FUN_80243ec0(10,&LAB_80254838);
  FUN_80243ec0(0xb,&LAB_80254a50);
  FUN_80243ec0(0xc,&LAB_80254770);
  FUN_80243ec0(0xd,&LAB_80254838);
  FUN_80243ec0(0xe,&LAB_80254a50);
  FUN_80243ec0(0xf,&LAB_80254770);
  FUN_80243ec0(0x10,&LAB_80254838);
  uVar1 = FUN_80240ad0();
  if ((uVar1 & 0x10000000) != 0) {
    DAT_800030c4 = 0;
    DAT_800030c0 = 0;
    DAT_803af0c0 = 0;
    DAT_803af080 = 0;
    FUN_802540c4(0);
    FUN_802540c4(1);
  }
  return;
}

