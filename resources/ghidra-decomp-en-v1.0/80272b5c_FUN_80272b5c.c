// Function: FUN_80272b5c
// Entry: 80272b5c
// Size: 360 bytes

void FUN_80272b5c(uint param_1,int param_2,undefined4 param_3,char param_4,undefined4 param_5,
                 int param_6,undefined4 param_7,char param_8,undefined4 param_9)

{
  uint uVar1;
  undefined uVar2;
  
  FUN_80284af4();
  if (param_2 == 0) {
    (&DAT_803bd9c4)[param_1 & 0xff] = 0;
    (&DAT_803de254)[param_1 & 0xff] = 0xff;
  }
  else {
    uVar1 = param_1 & 0xff;
    (&DAT_803de254)[uVar1] = param_4;
    if (param_4 != -1) {
      uVar2 = FUN_8026c41c(param_5);
      (&DAT_803de24c)[uVar1] = uVar2;
      (&DAT_803bd9c4)[uVar1] = param_2;
      (&DAT_803bd9a4)[uVar1] = param_3;
    }
  }
  if (param_6 == 0) {
    (&DAT_803bda04)[param_1 & 0xff] = 0;
    (&DAT_803de244)[param_1 & 0xff] = 0xff;
  }
  else {
    uVar1 = param_1 & 0xff;
    (&DAT_803de244)[uVar1] = param_8;
    if (param_8 != -1) {
      uVar2 = FUN_8026c41c(param_9);
      (&DAT_803de23c)[uVar1] = uVar2;
      (&DAT_803bda04)[uVar1] = param_6;
      (&DAT_803bd9e4)[uVar1] = param_7;
    }
  }
  FUN_80283b38(param_1,param_2,param_3,param_6,param_7);
  FUN_80284abc();
  return;
}

