// Function: FUN_80250d64
// Entry: 80250d64
// Size: 348 bytes

void FUN_80250d64(undefined4 *param_1,undefined4 param_2,undefined4 param_3,int param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,int param_8)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  
  *param_1 = 0;
  param_1[1] = param_2;
  param_1[2] = param_3;
  param_1[4] = param_5;
  param_1[5] = param_6;
  param_1[6] = param_7;
  if (param_8 == 0) {
    param_1[7] = &DAT_80250c2c;
  }
  else {
    param_1[7] = param_8;
  }
  uVar5 = FUN_8024377c();
  puVar3 = DAT_803de040;
  puVar4 = DAT_803de044;
  if (param_4 == 1) {
    puVar1 = param_1;
    puVar2 = param_1;
    if (DAT_803de038 != (undefined4 *)0x0) {
      *DAT_803de03c = param_1;
      puVar1 = DAT_803de038;
      puVar2 = param_1;
      puVar3 = DAT_803de040;
      puVar4 = DAT_803de044;
    }
  }
  else {
    puVar1 = DAT_803de038;
    puVar2 = DAT_803de03c;
    if (((param_4 < 1) && (-1 < param_4)) &&
       (puVar3 = param_1, puVar4 = param_1, DAT_803de040 != (undefined4 *)0x0)) {
      *DAT_803de044 = param_1;
      puVar1 = DAT_803de038;
      puVar2 = DAT_803de03c;
      puVar3 = DAT_803de040;
      puVar4 = param_1;
    }
  }
  DAT_803de044 = puVar4;
  DAT_803de040 = puVar3;
  DAT_803de03c = puVar2;
  DAT_803de038 = puVar1;
  if ((DAT_803de048 == (undefined4 *)0x0) && (DAT_803de04c == 0)) {
    if (DAT_803de038 != (undefined4 *)0x0) {
      if (DAT_803de038[2] == 0) {
        FUN_8024ffe4(0,DAT_803de038[4],DAT_803de038[5],DAT_803de038[6]);
      }
      else {
        FUN_8024ffe4(DAT_803de038[2],DAT_803de038[5],DAT_803de038[4],DAT_803de038[6]);
      }
      DAT_803de050 = DAT_803de038[7];
      DAT_803de048 = DAT_803de038;
      DAT_803de038 = (undefined4 *)*DAT_803de038;
    }
    if (DAT_803de048 == (undefined4 *)0x0) {
      FUN_80250b2c();
    }
  }
  FUN_802437a4(uVar5);
  return;
}

