// Function: FUN_802514c8
// Entry: 802514c8
// Size: 348 bytes

void FUN_802514c8(undefined4 *param_1,undefined4 param_2,undefined4 param_3,int param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,int param_8)

{
  int *piVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  *param_1 = 0;
  param_1[1] = param_2;
  param_1[2] = param_3;
  param_1[4] = param_5;
  param_1[5] = param_6;
  param_1[6] = param_7;
  if (param_8 == 0) {
    param_1[7] = &DAT_80251390;
  }
  else {
    param_1[7] = param_8;
  }
  FUN_80243e74();
  puVar3 = DAT_803decc0;
  puVar4 = DAT_803decc4;
  if (param_4 == 1) {
    piVar1 = param_1;
    puVar2 = param_1;
    if (DAT_803decb8 != (int *)0x0) {
      *DAT_803decbc = param_1;
      piVar1 = DAT_803decb8;
      puVar2 = param_1;
      puVar3 = DAT_803decc0;
      puVar4 = DAT_803decc4;
    }
  }
  else {
    piVar1 = DAT_803decb8;
    puVar2 = DAT_803decbc;
    if (((param_4 < 1) && (-1 < param_4)) &&
       (puVar3 = param_1, puVar4 = param_1, DAT_803decc0 != (undefined4 *)0x0)) {
      *DAT_803decc4 = param_1;
      piVar1 = DAT_803decb8;
      puVar2 = DAT_803decbc;
      puVar3 = DAT_803decc0;
      puVar4 = param_1;
    }
  }
  DAT_803decc4 = puVar4;
  DAT_803decc0 = puVar3;
  DAT_803decbc = puVar2;
  DAT_803decb8 = piVar1;
  if ((DAT_803decc8 == (int *)0x0) && (DAT_803deccc == 0)) {
    if (DAT_803decb8 != (int *)0x0) {
      if (DAT_803decb8[2] == 0) {
        FUN_80250748(0,DAT_803decb8[4],DAT_803decb8[5],DAT_803decb8[6]);
      }
      else {
        FUN_80250748(DAT_803decb8[2],DAT_803decb8[5],DAT_803decb8[4],DAT_803decb8[6]);
      }
      DAT_803decd0 = DAT_803decb8[7];
      DAT_803decc8 = DAT_803decb8;
      DAT_803decb8 = (int *)*DAT_803decb8;
    }
    if (DAT_803decc8 == (int *)0x0) {
      FUN_80251290();
    }
  }
  FUN_80243e9c();
  return;
}

