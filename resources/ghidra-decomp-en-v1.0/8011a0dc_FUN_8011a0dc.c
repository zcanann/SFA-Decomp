// Function: FUN_8011a0dc
// Entry: 8011a0dc
// Size: 420 bytes

void FUN_8011a0dc(int param_1,int param_2)

{
  int iVar1;
  char cVar2;
  
  iVar1 = (int)DAT_803db9fb;
  if (param_1 == 0) {
    if (DAT_803dd6b8 != 0) {
      (**(code **)(*DAT_803dcaa4 + 0x10))();
      DAT_803dd6b8 = 0;
    }
    FUN_8000bb18(0,0x419);
    FUN_8011a7e4(0);
  }
  else {
    FUN_8000bb18(0,0x418);
    if (DAT_803dd6c5 == '\0') {
      if (param_2 == 0) {
        FUN_8011a4e8();
      }
      else {
        *(ushort *)((&PTR_DAT_8031a7bc)[iVar1 * 3] + 0x16) =
             *(ushort *)((&PTR_DAT_8031a7bc)[iVar1 * 3] + 0x16) | 0x4000;
        (&PTR_DAT_8031a7bc)[iVar1 * 3][0x56] = 0xff;
        *(undefined2 *)((&PTR_DAT_8031a7bc)[iVar1 * 3] + 0x3c) = 0x3d8;
        DAT_803dd6c5 = '\x01';
        DAT_803dd6b8 = (**(code **)(*DAT_803dcaa4 + 0xc))(0x3d7,0x29,0,1,0);
        (**(code **)(*DAT_803dcaa4 + 0x20))(DAT_803dd6b8,1);
        (**(code **)(*DAT_803dcaa0 + 0x2c))((&PTR_DAT_8031a7bc)[iVar1 * 3]);
      }
    }
    else {
      cVar2 = (**(code **)(*DAT_803dcaa4 + 0x24))(DAT_803dd6b8);
      if (cVar2 == '\x01') {
        FUN_800e85a0(DAT_803dd6a4);
      }
      (**(code **)(*DAT_803dcaa4 + 0x10))(DAT_803dd6b8);
      DAT_803dd6b8 = 0;
      FUN_8011a7e4(0);
    }
  }
  return;
}

