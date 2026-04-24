// Function: FUN_800ea8d4
// Entry: 800ea8d4
// Size: 260 bytes

void FUN_800ea8d4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  int *local_18 [3];
  
  local_18[0] = (int *)0x0;
  if (DAT_803de124 != param_9) {
    uVar4 = FUN_8001f82c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_18,
                         0x19,param_11,param_12,param_13,param_14,param_15,param_16);
    iVar2 = 0;
    for (piVar1 = local_18[0]; *piVar1 != -1; piVar1 = piVar1 + 1) {
      iVar2 = iVar2 + 1;
    }
    if ((param_9 < 0) || (iVar2 + -1 <= param_9)) {
      param_9 = 0;
    }
    iVar3 = local_18[0][param_9];
    iVar2 = local_18[0][param_9 + 1] - iVar3;
    if (iVar2 != DAT_803de11c) {
      if (DAT_803de118 != 0) {
        uVar4 = FUN_800238c4(DAT_803de118);
      }
      DAT_803de118 = FUN_80023d8c(iVar2,2);
    }
    DAT_803de11c = iVar2;
    FUN_8001f7e0(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803de118,0x18,
                 iVar3,iVar2,param_13,param_14,param_15,param_16);
    FUN_800238c4((uint)local_18[0]);
    DAT_803de124 = param_9;
  }
  DAT_803de120 = 1;
  return;
}

