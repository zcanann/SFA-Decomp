// Function: FUN_80114084
// Entry: 80114084
// Size: 256 bytes

undefined4 FUN_80114084(undefined4 param_1,undefined2 *param_2)

{
  int iVar1;
  int iVar2;
  undefined2 uVar4;
  undefined4 uVar3;
  float local_28 [2];
  longlong local_20;
  longlong local_18;
  
  local_28[0] = FLOAT_803e1c8c;
  iVar1 = (**(code **)(*DAT_803dca9c + 0x40))();
  if (iVar1 < 0) {
    uVar3 = 0;
  }
  else {
    iVar1 = (**(code **)(*DAT_803dca9c + 0x1c))();
    *(undefined4 *)(param_2 + 6) = *(undefined4 *)(iVar1 + 8);
    *(undefined4 *)(param_2 + 8) = *(undefined4 *)(iVar1 + 0xc);
    *(undefined4 *)(param_2 + 10) = *(undefined4 *)(iVar1 + 0x10);
    iVar2 = FUN_80036c80(8,param_2 + 6,local_28);
    if (iVar2 == 0) {
      *param_2 = (short)((int)*(char *)(iVar1 + 0x2c) << 8);
    }
    else {
      iVar1 = (int)(*(float *)(iVar2 + 0xc) - *(float *)(param_2 + 6));
      local_20 = (longlong)iVar1;
      iVar2 = (int)(*(float *)(iVar2 + 0x14) - *(float *)(param_2 + 10));
      local_18 = (longlong)iVar2;
      uVar4 = FUN_800217f4(iVar1,iVar2);
      *param_2 = uVar4;
    }
    uVar3 = 1;
  }
  return uVar3;
}

