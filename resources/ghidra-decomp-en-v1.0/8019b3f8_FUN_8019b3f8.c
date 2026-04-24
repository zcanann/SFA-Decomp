// Function: FUN_8019b3f8
// Entry: 8019b3f8
// Size: 208 bytes

int FUN_8019b3f8(int param_1,undefined4 param_2,undefined4 *param_3,int param_4)

{
  int iVar1;
  int iVar2;
  undefined4 local_18;
  undefined4 local_14;
  
  iVar2 = 0;
  if (param_4 == 1) {
    local_18 = 0;
    local_14 = 0;
  }
  else {
    local_18 = 0x19;
    local_14 = 0x15;
  }
  iVar1 = (**(code **)(*DAT_803dca9c + 0x14))
                    ((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                     (double)*(float *)(param_1 + 0x14),&local_18,2,param_2);
  if ((-1 < iVar1) && (iVar2 = (**(code **)(*DAT_803dca9c + 0x1c))(), param_3 != (undefined4 *)0x0))
  {
    *param_3 = *(undefined4 *)(iVar2 + 8);
    param_3[1] = *(undefined4 *)(iVar2 + 0xc);
    param_3[2] = *(undefined4 *)(iVar2 + 0x10);
  }
  return iVar2;
}

