// Function: FUN_800d8ee8
// Entry: 800d8ee8
// Size: 96 bytes

void FUN_800d8ee8(int param_1,int param_2,undefined4 param_3)

{
  undefined4 uVar1;
  undefined4 local_18 [5];
  
  local_18[0] = param_3;
  uVar1 = (**(code **)(*DAT_803dd71c + 0x14))
                    ((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                     (double)*(float *)(param_1 + 0x14),local_18,1,(int)*(char *)(param_2 + 0x344));
  *(undefined4 *)(param_2 + 0x33c) = uVar1;
  return;
}

