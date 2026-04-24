// Function: FUN_8024b854
// Entry: 8024b854
// Size: 284 bytes

void FUN_8024b854(code *param_1)

{
  code *pcVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 uVar5;
  
  uVar2 = FUN_8024377c();
  FUN_8024b970();
  pcVar1 = param_1;
  if (DAT_803ddf28 == 0) {
    if (DAT_803ddf08 != 0) {
      *(undefined4 *)(DAT_803ddf08 + 0x28) = 0;
    }
    uVar3 = FUN_8024377c();
    FUN_8024377c();
    DAT_803ddf14 = 1;
    if (DAT_803ddf08 == 0) {
      DAT_803ddf18 = 1;
    }
    FUN_802437a4();
    while (iVar4 = FUN_8024ba10(), iVar4 != 0) {
      FUN_8024b428(iVar4,0);
    }
    if (DAT_803ddf08 == 0) {
      if (param_1 != (code *)0x0) {
        (*param_1)(0,0);
      }
    }
    else {
      FUN_8024b428(DAT_803ddf08,param_1);
    }
    uVar5 = FUN_8024377c();
    DAT_803ddf14 = 0;
    if (DAT_803ddf18 != 0) {
      DAT_803ddf18 = 0;
      FUN_8024a1b8();
    }
    FUN_802437a4(uVar5);
    FUN_802437a4(uVar3);
    pcVar1 = DAT_803ddf2c;
  }
  DAT_803ddf2c = pcVar1;
  FUN_802437a4(uVar2);
  return;
}

