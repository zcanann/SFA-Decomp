// Function: FUN_800e81c8
// Entry: 800e81c8
// Size: 256 bytes

void FUN_800e81c8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  FUN_8005ced0(DAT_803a3e2a);
  FUN_8001bd8c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)DAT_803a3e26);
  FUN_800154d0(DAT_803a3e2c);
  FUN_80009920(DAT_803a3e2d,'\0');
  (**(code **)(*DAT_803dd6e8 + 0x50))(DAT_803a3e27);
  (**(code **)(*DAT_803dd6d0 + 0x6c))(DAT_803a3e28);
  FUN_80009a28((uint)DAT_803a3e2f,10,0,1,0);
  FUN_80009a28((uint)DAT_803a3e2e,10,1,0,0);
  FUN_80009a28((uint)DAT_803a3e30,10,0,0,1);
  return;
}

