// Function: FUN_801e5a2c
// Entry: 801e5a2c
// Size: 296 bytes

undefined4 FUN_801e5a2c(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  undefined auStack40 [6];
  undefined2 local_22;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  iVar1 = FUN_800221a0(0,1);
  if (iVar1 == 0) {
    *(undefined *)(param_3 + 0x90) = 8;
  }
  else {
    *(undefined *)(param_3 + 0x90) = 4;
  }
  *(undefined *)(param_3 + 0x56) = 0;
  *(undefined2 *)(param_3 + 0x6e) = 0xffff;
  *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffdf;
  iVar1 = FUN_8002b9ec();
  if ((iVar1 != 0) && ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
    local_20 = FLOAT_803e597c;
    local_22 = 0xc0d;
    local_1c = local_1c - *(float *)(param_1 + 0x18);
    local_18 = local_18 - *(float *)(param_1 + 0x1c);
    local_14 = local_14 - *(float *)(param_1 + 0x20);
    for (iVar1 = 0; iVar1 < (int)(uint)DAT_803db410; iVar1 = iVar1 + 1) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7a8,auStack40,6,0xffffffff,0);
    }
  }
  return 0;
}

