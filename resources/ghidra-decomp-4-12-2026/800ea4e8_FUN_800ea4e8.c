// Function: FUN_800ea4e8
// Entry: 800ea4e8
// Size: 88 bytes

undefined4
FUN_800ea4e8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined4 uVar1;
  undefined *puVar2;
  
  uVar1 = FUN_80019c28();
  puVar2 = FUN_800e82c8();
  FUN_800199a8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               (uint)(byte)(&DAT_803a4e78)[*(short *)(&DAT_80312630 + (uint)(byte)puVar2[5] * 2)]);
  return uVar1;
}

