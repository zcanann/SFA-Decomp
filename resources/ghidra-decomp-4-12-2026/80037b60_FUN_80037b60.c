// Function: FUN_80037b60
// Entry: 80037b60
// Size: 216 bytes

int FUN_80037b60(int param_1,float *param_2,undefined4 *param_3,float *param_4)

{
  int iVar1;
  
  iVar1 = 0;
  *param_2 = *param_2 - FLOAT_803dc074;
  if (*param_2 <= FLOAT_803df5f0) {
    if (param_4 == (float *)0x0) {
      iVar1 = FUN_80036974(param_1,param_3,(int *)0x0,(uint *)0x0);
    }
    else {
      iVar1 = FUN_80036868(param_1,param_3,(int *)0x0,(uint *)0x0,param_4,param_4 + 1,param_4 + 2);
      if (iVar1 != 0) {
        FUN_800550f0(param_1,param_4);
      }
    }
    if (iVar1 != 0) {
      *param_2 = FLOAT_803df5f4;
    }
  }
  return iVar1;
}

