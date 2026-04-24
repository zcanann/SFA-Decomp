// Function: FUN_80253960
// Entry: 80253960
// Size: 372 bytes

undefined4 FUN_80253960(int param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  int *piVar3;
  int extraout_r4;
  uint *puVar4;
  uint uVar5;
  undefined8 uVar6;
  
  if (param_1 == 2) {
    uVar1 = 1;
  }
  else {
    uVar1 = 1;
    uVar2 = FUN_8024377c();
    puVar4 = &DAT_cc006800 + param_1 * 5;
    uVar5 = *puVar4;
    if ((*(uint *)(&DAT_803ae40c + param_1 * 0x40) & 8) == 0) {
      if ((uVar5 & 0x800) != 0) {
        *puVar4 = *puVar4 & 0x7f5 | 0x800;
        (&DAT_803ae420)[param_1 * 0x10] = 0;
        (&DAT_800030c0)[param_1] = 0;
      }
      if ((uVar5 & 0x1000) == 0) {
        (&DAT_803ae420)[param_1 * 0x10] = 0;
        (&DAT_800030c0)[param_1] = 0;
        uVar1 = 0;
      }
      else {
        uVar5 = DAT_800000f8 >> 2;
        uVar6 = FUN_80246c50();
        uVar6 = FUN_8028622c((int)((ulonglong)uVar6 >> 0x20),(int)uVar6,0,uVar5 / 1000);
        FUN_8028622c((int)((ulonglong)uVar6 >> 0x20),(int)uVar6,0,100);
        piVar3 = &DAT_800030c0 + param_1;
        if (*piVar3 == 0) {
          *piVar3 = extraout_r4 + 1;
        }
        if ((extraout_r4 + 1) - *piVar3 < 3) {
          uVar1 = 0;
        }
      }
    }
    else if (((uVar5 & 0x1000) == 0) || ((uVar5 & 0x800) != 0)) {
      (&DAT_803ae420)[param_1 * 0x10] = 0;
      (&DAT_800030c0)[param_1] = 0;
      uVar1 = 0;
    }
    FUN_802437a4(uVar2);
  }
  return uVar1;
}

