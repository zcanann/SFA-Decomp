// Function: FUN_802428c8
// Entry: 802428c8
// Size: 300 bytes

void FUN_802428c8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  bool bVar1;
  undefined4 *puVar2;
  uint uVar3;
  byte in_cr1;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined4 local_1c;
  undefined *local_18;
  undefined4 *local_14;
  
  if ((bool)(in_cr1 >> 1 & 1)) {
    local_68 = param_1;
    local_60 = param_2;
    local_58 = param_3;
    local_50 = param_4;
    local_48 = param_5;
    local_40 = param_6;
    local_38 = param_7;
    local_30 = param_8;
  }
  local_88 = param_9;
  local_84 = param_10;
  local_80 = param_11;
  local_7c = param_12;
  local_78 = param_13;
  local_74 = param_14;
  local_70 = param_15;
  local_6c = param_16;
  FUN_8024377c();
  local_1c = 0x3000000;
  local_18 = &stack0x00000008;
  local_14 = &local_88;
  FUN_8028f7e0(param_11,&local_1c);
  FUN_8007d6dc(s__in___s__on_line__d__8032c9a8,param_9,param_10);
  FUN_8007d6dc(s__Address__Back_Chain_LR_Save_8032c9c0);
  uVar3 = 0;
  puVar2 = (undefined4 *)FUN_8024246c();
  while (((puVar2 != (undefined4 *)0x0 && (puVar2 != (undefined4 *)0xffffffff)) &&
         (bVar1 = uVar3 < 0x10, uVar3 = uVar3 + 1, bVar1))) {
    FUN_8007d6dc(s_0x_08x__0x_08x_0x_08x_8032c9e8,puVar2,*puVar2,puVar2[1]);
    puVar2 = (undefined4 *)*puVar2;
  }
  FUN_80294648();
  return;
}

