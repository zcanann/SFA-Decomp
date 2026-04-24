// Function: FUN_8024b428
// Entry: 8024b428
// Size: 624 bytes

undefined4 FUN_8024b428(int param_1,code *param_2)

{
  int iVar1;
  undefined4 uVar2;
  undefined *puVar3;
  
  uVar2 = FUN_8024377c();
  switch(*(undefined4 *)(param_1 + 0xc)) {
  case 1:
    if (DAT_803ddf28 != 0) {
      FUN_802437a4(uVar2);
      return 0;
    }
    DAT_803ddf28 = 1;
    if ((*(int *)(param_1 + 8) == 4) || (DAT_803ddf2c = param_2, *(int *)(param_1 + 8) == 1)) {
      DAT_803ddf2c = param_2;
      FUN_80248800();
    }
    break;
  case 2:
    FUN_8024bb08(param_1);
    *(undefined4 *)(param_1 + 0xc) = 10;
    if (*(code **)(param_1 + 0x28) != (code *)0x0) {
      (**(code **)(param_1 + 0x28))(0xfffffffd,param_1);
    }
    if (param_2 != (code *)0x0) {
      (*param_2)(0,param_1);
    }
    break;
  case 3:
    iVar1 = *(int *)(param_1 + 8);
    if (iVar1 == 0xd) {
LAB_8024b558:
      if (param_2 != (code *)0x0) {
        (*param_2)(0,param_1);
      }
    }
    else {
      if (iVar1 < 0xd) {
        if ((iVar1 < 6) && (3 < iVar1)) goto LAB_8024b558;
      }
      else if (iVar1 == 0xf) goto LAB_8024b558;
      if (DAT_803ddf28 != 0) {
        FUN_802437a4(uVar2);
        return 0;
      }
      DAT_803ddf28 = 1;
      DAT_803ddf2c = param_2;
    }
    break;
  case 4:
  case 5:
  case 6:
  case 7:
  case 0xb:
    puVar3 = (undefined *)FUN_80248814();
    if (puVar3 != &LAB_8024a0d4) {
      FUN_802437a4(uVar2);
      return 0;
    }
    if (*(int *)(param_1 + 0xc) == 4) {
      DAT_803ddf30 = 3;
    }
    if (*(int *)(param_1 + 0xc) == 5) {
      DAT_803ddf30 = 4;
    }
    if (*(int *)(param_1 + 0xc) == 6) {
      DAT_803ddf30 = 1;
    }
    if (*(int *)(param_1 + 0xc) == 0xb) {
      DAT_803ddf30 = 2;
    }
    if (*(int *)(param_1 + 0xc) == 7) {
      DAT_803ddf30 = 7;
    }
    *(undefined4 *)(param_1 + 0xc) = 10;
    if (*(code **)(param_1 + 0x28) != (code *)0x0) {
      (**(code **)(param_1 + 0x28))(0xfffffffd,param_1);
    }
    if (param_2 != (code *)0x0) {
      (*param_2)(0,param_1);
    }
    FUN_8024a1b8();
    break;
  case 0xffffffff:
  case 0:
  case 10:
    if (param_2 != (code *)0x0) {
      (*param_2)(0,param_1);
    }
  }
  FUN_802437a4(uVar2);
  return 1;
}

