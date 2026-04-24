// Function: FUN_8000f3d8
// Entry: 8000f3d8
// Size: 128 bytes

void FUN_8000f3d8(undefined4 *param_1,int *param_2,uint *param_3,int *param_4)

{
  uint uVar1;
  
  uVar1 = FUN_8006fed4();
  *param_1 = 0;
  *param_3 = uVar1 & 0xffff;
  *param_2 = DAT_803dc884 + 6;
  *param_4 = (uVar1 >> 0x10) - (DAT_803dc884 + 6);
  return;
}

