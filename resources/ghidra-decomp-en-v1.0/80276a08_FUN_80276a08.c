// Function: FUN_80276a08
// Entry: 80276a08
// Size: 104 bytes

int FUN_80276a08(int param_1,int param_2,uint param_3)

{
  short sVar1;
  
  if (param_2 == 0) {
    param_3 = param_3 & 0x1f;
    if (param_3 < 0x10) {
      sVar1 = (short)*(undefined4 *)(param_1 + param_3 * 4 + 0xac);
    }
    else {
      sVar1 = (short)*(undefined4 *)(&DAT_803bd9f4 + param_3 * 4);
    }
  }
  else {
    sVar1 = FUN_80282d24(param_1,param_3);
  }
  return (int)sVar1;
}

