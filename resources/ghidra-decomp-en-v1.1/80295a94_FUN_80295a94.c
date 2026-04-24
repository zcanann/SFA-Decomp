// Function: FUN_80295a94
// Entry: 80295a94
// Size: 728 bytes

/* WARNING: Removing unreachable block (ram,0x80295ad4) */

void FUN_80295a94(undefined4 param_1,undefined4 param_2,float *param_3,undefined4 param_4,
                 uint param_5)

{
  double dVar1;
  float afStack_78 [12];
  float afStack_48 [12];
  undefined4 local_18;
  uint uStack_14;
  
  if (DAT_803dd2d4 == 3) {
    FLOAT_803dd2d8 = FLOAT_803e8b18;
    FLOAT_803dd2dc = FLOAT_803e8b1c;
    FLOAT_803dd2e0 = FLOAT_803e8b20;
    uStack_14 = param_5 ^ 0x80000000;
    local_18 = 0x43300000;
    dVar1 = (double)FUN_80294b54();
    FUN_8024782c((double)(float)((double)FLOAT_803e8b4c * dVar1),afStack_48,0x79);
    if (param_5 == 1) {
      FUN_8024782c((double)FLOAT_803e8b54,afStack_78,0x78);
      FUN_80247618(afStack_78,afStack_48,afStack_48);
    }
    FUN_80247cd8(afStack_48,param_3,param_3);
  }
  else if (DAT_803dd2d4 < 3) {
    if (DAT_803dd2d4 == 1) {
      FLOAT_803dd2d8 = FLOAT_803e8b18;
      FLOAT_803dd2dc = FLOAT_803e8b1c;
      FLOAT_803dd2e0 = FLOAT_803e8b20;
      uStack_14 = param_5 ^ 0x80000000;
      local_18 = 0x43300000;
      dVar1 = (double)FUN_80294b54();
      FUN_8024782c((double)(float)((double)FLOAT_803e8b24 * dVar1),afStack_48,0x79);
      FUN_80247cd8(afStack_48,param_3,param_3);
    }
    else if (DAT_803dd2d4 == 0) {
      FLOAT_803dd2d8 = FLOAT_803e8b18;
      FLOAT_803dd2dc = FLOAT_803e8b1c;
      FLOAT_803dd2e0 = FLOAT_803e8b20;
    }
    else {
      FLOAT_803dd2d8 = FLOAT_803e8b38;
      FLOAT_803dd2dc = FLOAT_803e8b3c;
      FLOAT_803dd2e0 = FLOAT_803e8b40;
      dVar1 = (double)FUN_80294b54();
      FUN_8024782c((double)(float)((double)FLOAT_803e8b44 * dVar1),afStack_48,0x79);
      FUN_8024782c((double)FLOAT_803e8b48,afStack_78,0x78);
      FUN_80247618(afStack_78,afStack_48,afStack_48);
      FUN_80247cd8(afStack_48,param_3,param_3);
    }
  }
  else if (DAT_803dd2d4 == 5) {
    FLOAT_803dd2d8 = FLOAT_803e8b34;
    FLOAT_803dd2dc = FLOAT_803e8b1c;
    FLOAT_803dd2e0 = FLOAT_803e8b20;
    uStack_14 = param_5 ^ 0x80000000;
    local_18 = 0x43300000;
    dVar1 = (double)FUN_80294b54();
    FUN_8024782c((double)(float)((double)FLOAT_803e8b24 * dVar1),afStack_48,0x79);
    FUN_80247cd8(afStack_48,param_3,param_3);
  }
  else if (DAT_803dd2d4 < 5) {
    FLOAT_803dd2d8 = FLOAT_803e8b30;
    FLOAT_803dd2dc = FLOAT_803e8b1c;
    FLOAT_803dd2e0 = FLOAT_803e8b20;
    uStack_14 = param_5 ^ 0x80000000;
    local_18 = 0x43300000;
    dVar1 = (double)FUN_80294b54();
    FUN_8024782c((double)(float)((double)FLOAT_803e8b24 * dVar1),afStack_48,0x79);
    FUN_80247cd8(afStack_48,param_3,param_3);
  }
  return;
}

