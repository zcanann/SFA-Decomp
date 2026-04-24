// Function: FUN_8024bdd8
// Entry: 8024bdd8
// Size: 360 bytes

void FUN_8024bdd8(void)

{
  int iVar1;
  undefined *puVar2;
  undefined auStack64 [52];
  
  FUN_802416f0();
  DAT_803ddf58 = auStack64;
  DAT_803ddf54 = &DAT_803ae000;
  FUN_8024b2dc();
  FUN_8024ae40(&DAT_803ae038,DAT_803ddf58,&LAB_8024bd00);
  do {
    iVar1 = FUN_8024b36c();
  } while (iVar1 != 0);
  DAT_80000038 = *(undefined4 *)(DAT_803ddf54 + 0x10);
  DAT_8000003c = *(undefined4 *)(DAT_803ddf54 + 0xc);
  FUN_80003494(0x80000000,DAT_803ddf58,0x20);
  FUN_8007d6dc(&DAT_803dc570);
  FUN_8007d6dc(s__Game_Name______c_c_c_c_8032dd80,(int)DAT_80000000,(int)DAT_80000001,
               (int)DAT_80000002,(int)DAT_80000003);
  FUN_8007d6dc(s__Company________c_c_8032dd9c,(int)DAT_80000004,(int)DAT_80000005);
  FUN_8007d6dc(s__Disk___________d_8032ddb4,DAT_80000006);
  FUN_8007d6dc(s__Game_ver_______d_8032ddc8,DAT_80000007);
  if (DAT_80000008 == '\0') {
    puVar2 = &DAT_803dc574;
  }
  else {
    puVar2 = &DAT_803dc578;
  }
  FUN_8007d6dc(s__Streaming______s_8032dddc,puVar2);
  FUN_8007d6dc(&DAT_803dc570);
  FUN_80241700(*(undefined4 *)(DAT_803ddf54 + 0x10));
  return;
}

