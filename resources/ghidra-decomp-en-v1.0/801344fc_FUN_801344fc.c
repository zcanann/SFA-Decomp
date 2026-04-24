// Function: FUN_801344fc
// Entry: 801344fc
// Size: 676 bytes

void FUN_801344fc(undefined4 param_1)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  double local_28;
  
  FUN_8012fdcc(0);
  if (DAT_803dd988 == 4) {
    FUN_80019908(0xff,0xff,0xff,(int)FLOAT_803dd97c);
    FUN_80016810(0x3dd,200,DAT_803dbc04);
    if (DAT_803dd978 == 0) {
      uVar1 = FUN_801343cc(&DAT_8031cc50,&DAT_803a9dd0,&DAT_8031cc38,6,&DAT_803a9f38);
      (**(code **)(*DAT_803dcaa0 + 4))(&DAT_803a9dd0,uVar1,0,0,0,0,0x14,200,0xff,0xff,0xff,0xff);
      DAT_803dd978 = 1;
    }
    iVar2 = (**(code **)(*DAT_803dcaa0 + 0xc))();
    iVar3 = (**(code **)(*DAT_803dcaa0 + 0x14))();
    if (0 < iVar2) {
      (**(code **)(*DAT_803dcaac + 0x44))
                (0x42,(&DAT_8031cc3a)[*(int *)(&DAT_803a9f38 + iVar3 * 4) * 4]);
    }
    (**(code **)(*DAT_803dcaa0 + 0x10))(param_1);
    goto LAB_80134754;
  }
  if (DAT_803dd988 < 4) {
    if (DAT_803dd988 == 1) {
      local_28 = (double)CONCAT44(0x43300000,DAT_803dbbfc - 0x1dU ^ 0x80000000);
      FUN_8007719c((double)(float)(local_28 - DOUBLE_803e22d0),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dbc00 + 0xdU ^ 0x80000000) -
                                  DOUBLE_803e22d0),DAT_803dd980,(int)FLOAT_803dd97c,0xff);
      FUN_80019908(0xff,0xff,0xff,(int)FLOAT_803dd97c);
      FUN_80016870(0x37c);
      FUN_80016870(0x37d);
      FUN_80016870(0x37e);
      goto LAB_80134754;
    }
    if (DAT_803dd988 == 0) goto LAB_80134754;
  }
  else if (5 < DAT_803dd988) goto LAB_80134754;
  FUN_80019908(0xff,0xff,0xff,(int)FLOAT_803dd97c);
  FUN_80016810(0x3dd,200,DAT_803dbbf8);
LAB_80134754:
  if ((DAT_803dd978 != 0) && (DAT_803dd988 != 4)) {
    (**(code **)(*DAT_803dcaa0 + 8))();
    DAT_803dd978 = 0;
  }
  return;
}

