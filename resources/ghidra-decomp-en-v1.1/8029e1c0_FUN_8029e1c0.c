// Function: FUN_8029e1c0
// Entry: 8029e1c0
// Size: 128 bytes

undefined4 FUN_8029e1c0(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  
  *(undefined *)(param_2 + 0x34d) = 3;
  *(float *)(param_2 + 0x2a0) = FLOAT_803e8c70;
  *(float *)(param_2 + 0x280) = FLOAT_803e8b3c;
  (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_2,2);
  if (*(char *)(param_2 + 0x346) == '\0') {
    uVar1 = 0;
  }
  else {
    *(code **)(param_2 + 0x308) = FUN_802a58ac;
    uVar1 = 2;
  }
  return uVar1;
}

