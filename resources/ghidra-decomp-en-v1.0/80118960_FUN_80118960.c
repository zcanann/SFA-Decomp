// Function: FUN_80118960
// Entry: 80118960
// Size: 552 bytes

bool FUN_80118960(uint param_1,undefined param_2)

{
  int iVar1;
  int local_18 [3];
  
  DAT_803dd680 = 0;
  if ((DAT_803a5df8 == 0) || (DAT_803a5dfc != '\0')) {
    DAT_803dd680 = 0;
    return false;
  }
  if ((int)param_1 < 1) {
    DAT_803a5e10 = DAT_803a5dc4;
    DAT_803a5e14 = DAT_803a5db4;
  }
  else {
    if (DAT_803a5dc0 == 0) {
      DAT_803dd680 = 0;
      return false;
    }
    if (DAT_803a5db0 <= param_1) {
      DAT_803dd680 = 0;
      return false;
    }
    iVar1 = FUN_80015850(&DAT_803a5d60,&DAT_803a5d20,0x20,DAT_803a5dc0 + (param_1 - 1) * 4);
    if (iVar1 < 0) {
      return false;
    }
    DAT_803a5e10 = DAT_803a5dc4 + DAT_803a5d20;
    DAT_803a5e14 = DAT_803a5d24 - DAT_803a5d20;
  }
  DAT_803a5e30 = 0;
  DAT_803a5dfe = param_2;
  DAT_803a5e18 = param_1;
  if (DAT_803a5e08 == 0) {
    FUN_80119b58(0xf,0);
    if (DAT_803a5dff != '\0') {
      FUN_801175a4(0xc,0);
    }
    FUN_80119688(8);
  }
  else {
    iVar1 = FUN_80015850(&DAT_803a5d60,DAT_803a5e0c,DAT_803a5db8,DAT_803a5dc4);
    if (iVar1 < 0) {
      return false;
    }
    iVar1 = (DAT_803a5e0c + DAT_803a5e10) - DAT_803a5dc4;
    FUN_80119b58(0xf,iVar1);
    if (DAT_803a5dff != '\0') {
      FUN_801175a4(0xc,iVar1);
    }
  }
  FUN_80118bb8();
  FUN_80119b24();
  if (DAT_803a5dff != '\0') {
    FUN_80117570();
  }
  if (DAT_803a5e08 == 0) {
    FUN_80119654();
  }
  FUN_80244128(&DAT_803a5cec,local_18,1);
  if (local_18[0] != 0) {
    DAT_803a5dfc = '\x01';
    DAT_803a5dfd = 0;
    DAT_803a5e4c = 0;
    DAT_803a5e50 = 0;
    DAT_803a5e44 = 0;
    DAT_803a5e48 = 0;
    DAT_803dd664 = FUN_8024c1ac(FUN_8011846c);
  }
  return local_18[0] != 0;
}

