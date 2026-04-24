// Function: FUN_80016848
// Entry: 80016848
// Size: 96 bytes

void FUN_80016848(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11)

{
  int iVar1;
  int iVar2;
  
  iVar2 = DAT_803dd648;
  if (DAT_803dd5ec == 0) {
    iVar1 = DAT_803dd648 * 5;
    DAT_803dd648 = DAT_803dd648 + 1;
    (&DAT_8033b1a0)[iVar1] = 2;
    (&DAT_8033b1a4)[iVar2 * 5] = param_9;
    (&DAT_8033b1a8)[iVar2 * 5] = param_10;
    (&DAT_8033b1ac)[iVar2 * 5] = param_11;
  }
  else {
    FUN_800165c4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,
                 param_11);
  }
  return;
}

