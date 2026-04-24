// Function: FUN_802769a4
// Entry: 802769a4
// Size: 100 bytes

uint FUN_802769a4(int param_1,int param_2,uint param_3)

{
  uint uVar1;
  
  if (param_2 == 0) {
    param_3 = param_3 & 0x1f;
    if (param_3 < 0x10) {
      uVar1 = *(uint *)(param_1 + param_3 * 4 + 0xac);
    }
    else {
      uVar1 = *(uint *)(&DAT_803bd9f4 + param_3 * 4);
    }
  }
  else {
    uVar1 = FUN_80282d24(param_1,param_3);
    uVar1 = uVar1 & 0xffff;
  }
  return uVar1;
}

