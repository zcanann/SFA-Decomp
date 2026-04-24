// Function: FUN_80276a70
// Entry: 80276a70
// Size: 100 bytes

void FUN_80276a70(int param_1,int param_2,uint param_3,undefined4 param_4)

{
  if (param_2 == 0) {
    param_3 = param_3 & 0x1f;
    if (param_3 < 0x10) {
      *(undefined4 *)(param_1 + param_3 * 4 + 0xac) = param_4;
    }
    else {
      *(undefined4 *)(&DAT_803bd9f4 + param_3 * 4) = param_4;
    }
  }
  else {
    FUN_80282dc4(param_1,param_3,(int)(short)param_4);
  }
  return;
}

