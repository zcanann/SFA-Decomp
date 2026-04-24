// Function: FUN_8000f3f8
// Entry: 8000f3f8
// Size: 128 bytes

void FUN_8000f3f8(undefined4 *param_1,int *param_2,uint *param_3,int *param_4)

{
  uint uVar1;
  
  uVar1 = FUN_80070050();
  *param_1 = 0;
  *param_3 = uVar1 & 0xffff;
  *param_2 = DAT_803dd504 + 6;
  *param_4 = (uVar1 >> 0x10) - (DAT_803dd504 + 6);
  return;
}

