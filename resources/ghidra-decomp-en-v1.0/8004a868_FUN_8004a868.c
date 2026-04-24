// Function: FUN_8004a868
// Entry: 8004a868
// Size: 444 bytes

void FUN_8004a868(void)

{
  undefined4 uVar1;
  uint uVar2;
  double dVar3;
  
  FUN_80245a68(&DAT_8035f680);
  FUN_80245b34(&DAT_8035f680);
  dVar3 = (double)FUN_8028656c();
  FLOAT_803dccc0 =
       (float)(dVar3 / (double)(float)((double)CONCAT44(0x43300000,(DAT_800000f8 >> 2) / 1000) -
                                      DOUBLE_803dea80));
  FUN_80245ba4(&DAT_8035f680);
  FUN_80245a2c(&DAT_8035f680);
  FLOAT_803db414 = FLOAT_803dea9c * FLOAT_803deaa0 * FLOAT_803dccc0;
  if (DAT_803dc950 != '\0') {
    FLOAT_803db414 = FLOAT_803dea70;
  }
  if (FLOAT_803dea74 < FLOAT_803db414) {
    FLOAT_803db414 = FLOAT_803dea74;
  }
  FLOAT_803db418 = FLOAT_803dea78;
  if (FLOAT_803dea7c < FLOAT_803db414) {
    FLOAT_803db418 = FLOAT_803dea78 / FLOAT_803db414;
  }
  uVar2 = (int)(FLOAT_803db414 + FLOAT_803dccb4) & 0xff;
  DAT_803db411 = (undefined)uVar2;
  FLOAT_803dccb4 =
       (FLOAT_803db414 + FLOAT_803dccb4) -
       (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803dea80);
  DAT_803db410 = DAT_803db411;
  if (uVar2 == 0) {
    DAT_803db410 = 1;
  }
  uVar1 = FUN_8024377c();
  DAT_803dccdc = FUN_80245d88();
  if (*(short *)(DAT_803dccdc + 0x2c8) != 2) {
    FUN_8007d6dc(s_thread__state__d_attr__d_suspend_8030c858,*(short *)(DAT_803dccdc + 0x2c8),
                 *(undefined2 *)(DAT_803dccdc + 0x2ca),*(undefined4 *)(DAT_803dccdc + 0x2cc));
  }
  uVar2 = FUN_80013754(&DAT_8035f730);
  if (1 < uVar2) {
    DAT_803dccac = 0;
    FUN_80246a60(&DAT_803dccc4);
  }
  FUN_802437a4(uVar1);
  FUN_8000f780();
  FUN_80257f00();
  FUN_8025aaac();
  return;
}

