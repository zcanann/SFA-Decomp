// Function: FUN_8024bb8c
// Entry: 8024bb8c
// Size: 624 bytes

undefined4 FUN_8024bb8c(int *param_1,undefined *param_2)

{
  int iVar1;
  undefined *puVar2;
  
  FUN_80243e74();
  switch(param_1[3]) {
  case 1:
    if (DAT_803deba8 != 0) {
      FUN_80243e9c();
      return 0;
    }
    DAT_803deba8 = 1;
    if ((param_1[2] == 4) || (DAT_803debac = param_2, param_1[2] == 1)) {
      DAT_803debac = param_2;
      FUN_80248f64();
    }
    break;
  case 2:
    FUN_8024c26c(param_1);
    param_1[3] = 10;
    if ((code *)param_1[10] != (code *)0x0) {
      (*(code *)param_1[10])(0xfffffffd,param_1);
    }
    if (param_2 != (undefined *)0x0) {
      (*(code *)param_2)(0,param_1);
    }
    break;
  case 3:
    iVar1 = param_1[2];
    if (iVar1 == 0xd) {
LAB_8024bcbc:
      if (param_2 != (undefined *)0x0) {
        (*(code *)param_2)(0,param_1);
      }
    }
    else {
      if (iVar1 < 0xd) {
        if ((iVar1 < 6) && (3 < iVar1)) goto LAB_8024bcbc;
      }
      else if (iVar1 == 0xf) goto LAB_8024bcbc;
      if (DAT_803deba8 != 0) {
        FUN_80243e9c();
        return 0;
      }
      DAT_803deba8 = 1;
      DAT_803debac = param_2;
    }
    break;
  case 4:
  case 5:
  case 6:
  case 7:
  case 0xb:
    puVar2 = (undefined *)FUN_80248f78();
    if (puVar2 != &LAB_8024a838) {
      FUN_80243e9c();
      return 0;
    }
    if (param_1[3] == 4) {
      DAT_803debb0 = 3;
    }
    if (param_1[3] == 5) {
      DAT_803debb0 = 4;
    }
    if (param_1[3] == 6) {
      DAT_803debb0 = 1;
    }
    if (param_1[3] == 0xb) {
      DAT_803debb0 = 2;
    }
    if (param_1[3] == 7) {
      DAT_803debb0 = 7;
    }
    param_1[3] = 10;
    if ((code *)param_1[10] != (code *)0x0) {
      (*(code *)param_1[10])(0xfffffffd,param_1);
    }
    if (param_2 != (undefined *)0x0) {
      (*(code *)param_2)(0,param_1);
    }
    FUN_8024a91c();
    break;
  case -1:
  case 0:
  case 10:
    if (param_2 != (undefined *)0x0) {
      (*(code *)param_2)(0,param_1);
    }
  }
  FUN_80243e9c();
  return 1;
}

