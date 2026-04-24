// Function: FUN_80114320
// Entry: 80114320
// Size: 256 bytes

undefined4 FUN_80114320(undefined4 param_1,undefined2 *param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  float local_28 [2];
  longlong local_20;
  longlong local_18;
  
  local_28[0] = FLOAT_803e290c;
  iVar1 = (**(code **)(*DAT_803dd71c + 0x40))();
  if (iVar1 < 0) {
    uVar3 = 0;
  }
  else {
    iVar1 = (**(code **)(*DAT_803dd71c + 0x1c))();
    *(undefined4 *)(param_2 + 6) = *(undefined4 *)(iVar1 + 8);
    *(undefined4 *)(param_2 + 8) = *(undefined4 *)(iVar1 + 0xc);
    *(undefined4 *)(param_2 + 10) = *(undefined4 *)(iVar1 + 0x10);
    iVar2 = FUN_80036d78(8,param_2 + 6,local_28);
    if (iVar2 == 0) {
      *param_2 = (short)((int)*(char *)(iVar1 + 0x2c) << 8);
    }
    else {
      local_20 = (longlong)(int)(*(float *)(iVar2 + 0xc) - *(float *)(param_2 + 6));
      local_18 = (longlong)(int)(*(float *)(iVar2 + 0x14) - *(float *)(param_2 + 10));
      iVar1 = FUN_800218b8();
      *param_2 = (short)iVar1;
    }
    uVar3 = 1;
  }
  return uVar3;
}

