// Function: FUN_800552ac
// Entry: 800552ac
// Size: 440 bytes

void FUN_800552ac(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined4 *puVar1;
  int iVar2;
  undefined8 uVar3;
  
  puVar1 = (undefined4 *)(**(code **)(*DAT_803dd72c + 0x90))();
  if ((DAT_803ddb38 != -1) && (DAT_803dda60 = DAT_803dda60 + -1, DAT_803dda60 < '\0')) {
    if ((-1 < DAT_803ddb38) && (DAT_803ddb3c != '\0')) {
      (**(code **)(*DAT_803dd6cc + 0xc))(3,1);
    }
    DAT_803ddb38 = -1;
    FUN_80130110(0);
  }
  if ((DAT_803ddb3d != '\0') &&
     ((iVar2 = (**(code **)(*DAT_803dd6cc + 0x14))(), iVar2 != 0 || (DAT_803ddb3c == '\0')))) {
    (**(code **)(*DAT_803dd6e4 + 0x14))();
    (**(code **)(*DAT_803dd6e4 + 8))();
    (**(code **)(*DAT_803dd6dc + 8))();
    (**(code **)(*DAT_803dd6d8 + 8))();
    uVar3 = (**(code **)(*DAT_803dd6e0 + 8))();
    FUN_8011f534(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    DAT_803ddb3d = '\0';
    *puVar1 = DAT_80388600;
    puVar1[1] = DAT_80388604;
    puVar1[2] = DAT_80388608;
    *(char *)((int)puVar1 + 0xd) = (char)DAT_8038860c;
    *(char *)(puVar1 + 3) = (char)DAT_8038860e;
    FUN_8002080c();
    DAT_803ddb38 = DAT_803ddb3a;
    DAT_803ddb3a = -1;
    DAT_803dda60 = '\b';
    DAT_803dd6c0 = 1;
    FUN_8001ff84(1);
  }
  return;
}

