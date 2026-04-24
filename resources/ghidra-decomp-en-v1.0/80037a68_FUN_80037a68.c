// Function: FUN_80037a68
// Entry: 80037a68
// Size: 216 bytes

int FUN_80037a68(undefined4 param_1,float *param_2,undefined4 param_3,int param_4)

{
  int iVar1;
  
  iVar1 = 0;
  *param_2 = *param_2 - FLOAT_803db414;
  if (*param_2 <= FLOAT_803de970) {
    if (param_4 == 0) {
      iVar1 = FUN_8003687c(param_1,param_3,0,0);
    }
    else {
      iVar1 = FUN_80036770(param_1,param_3,0,0,param_4,param_4 + 4,param_4 + 8);
      if (iVar1 != 0) {
        FUN_80054f74(param_1,param_4);
      }
    }
    if (iVar1 != 0) {
      *param_2 = FLOAT_803de974;
    }
  }
  return iVar1;
}

