// Function: FUN_8011bfc8
// Entry: 8011bfc8
// Size: 848 bytes

void FUN_8011bfc8(int param_1,int param_2)

{
  int iVar1;
  undefined uVar2;
  
  if (((&DAT_803a87d0)[param_2] != 0) && (iVar1 = (**(code **)(*DAT_803dcaa4 + 0x2c))(), iVar1 != 0)
     ) {
    if (param_2 == 3) {
      uVar2 = (**(code **)(*DAT_803dcaa4 + 0x24))((&DAT_803a87d0)[3]);
      FUN_80009a28(uVar2,10,0,0,1);
    }
    else if (param_2 < 3) {
      if (param_2 == 1) {
        uVar2 = (**(code **)(*DAT_803dcaa4 + 0x24))((&DAT_803a87d0)[1]);
        FUN_80009a28(uVar2,10,1,0,0);
        (**(code **)(*DAT_803dcaa4 + 0x24))((&DAT_803a87d0)[1]);
        (**(code **)(*DAT_803dca70 + 0x28))();
      }
      else if (param_2 < 1) {
        if (-1 < param_2) {
          uVar2 = (**(code **)(*DAT_803dcaa4 + 0x24))((&DAT_803a87d0)[param_2]);
          FUN_80009920(uVar2,1);
        }
      }
      else {
        uVar2 = (**(code **)(*DAT_803dcaa4 + 0x24))((&DAT_803a87d0)[param_2]);
        FUN_80009a28(uVar2,10,0,1,0);
      }
    }
    else if (param_2 == 5) {
      DAT_803dd6fc = (**(code **)(*DAT_803dcaa4 + 0x24))((&DAT_803a87d0)[5]);
    }
  }
  if (((&DAT_803a87d0)[param_2] == 0) || (((param_2 != 2 && (param_2 != 1)) && (param_2 != 3)))) {
    FUN_8000b824(0,0x3b9);
  }
  if (param_1 == 0) {
    FUN_8000bb18(0,0x100);
    (**(code **)(*DAT_803dca4c + 8))(0x14,5);
    DAT_803dd704 = 0x23;
    DAT_803dd705 = 1;
  }
  else if ((param_1 == 1) && (param_2 == 4)) {
    FUN_800e7f1c();
    (**(code **)(*DAT_803dcaa4 + 0x28))(DAT_803a87d4,*(undefined *)(DAT_803dd708 + 10));
    (**(code **)(*DAT_803dcaa4 + 0x28))(DAT_803a87d8,*(undefined *)(DAT_803dd708 + 0xb));
    (**(code **)(*DAT_803dcaa4 + 0x28))(DAT_803a87dc,*(undefined *)(DAT_803dd708 + 0xc));
    uVar2 = (**(code **)(*DAT_803dcaa4 + 0x24))(DAT_803a87d4);
    FUN_80009a28(uVar2,10,0,1,0);
    uVar2 = (**(code **)(*DAT_803dcaa4 + 0x24))(DAT_803a87d8);
    FUN_80009a28(uVar2,10,1,0,0);
    uVar2 = (**(code **)(*DAT_803dcaa4 + 0x24))(DAT_803a87dc);
    FUN_80009a28(uVar2,10,0,0,1);
    FUN_8000bb18(0,0x418);
  }
  return;
}

