// Function: FUN_800357e8
// Entry: 800357e8
// Size: 132 bytes

int FUN_800357e8(ushort *param_1,uint param_2)

{
  uint uVar1;
  
  uVar1 = FUN_80022ee8(param_2);
  *(uint *)(param_1 + 0x2c) = uVar1;
  if (*(int *)(param_1 + 0x2c) != 0) {
    *(undefined *)(*(int *)(param_1 + 0x2c) + 0x10c) = 0;
    *(undefined *)(*(int *)(param_1 + 0x2c) + 0x10d) = 10;
    *(undefined *)(*(int *)(param_1 + 0x2c) + 0x10f) = 0;
    FUN_80032508(param_1,1);
    FUN_80032508(param_1,1);
  }
  return uVar1 + 0x110;
}

