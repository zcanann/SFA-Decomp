// Function: FUN_8024a6a4
// Entry: 8024a6a4
// Size: 204 bytes

void FUN_8024a6a4(void)

{
  undefined *puVar1;
  
  if (DAT_803deba4 == 0xd) {
LAB_8024a6ec:
    FUN_8024c0d4();
    puVar1 = DAT_803deb88;
    DAT_803deb88 = &DAT_803aebe0;
    if (*(code **)(puVar1 + 0x28) != (code *)0x0) {
      (**(code **)(puVar1 + 0x28))(0xfffffffc);
    }
    FUN_8024a91c();
  }
  else {
    if (DAT_803deba4 < 0xd) {
      if ((DAT_803deba4 < 6) && (3 < DAT_803deba4)) goto LAB_8024a6ec;
    }
    else if (DAT_803deba4 == 0xf) goto LAB_8024a6ec;
    FUN_8024ba40();
    FUN_80241478((undefined4 *)&DAT_803aec10);
    FUN_802416d4((undefined4 *)&DAT_803aec10,0x10624dd3,0,(DAT_800000f8 / 4000) * 0x47e,
                 &LAB_8024a660);
  }
  return;
}

