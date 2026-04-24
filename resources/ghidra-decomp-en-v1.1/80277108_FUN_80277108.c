// Function: FUN_80277108
// Entry: 80277108
// Size: 100 bytes

uint FUN_80277108(int param_1,int param_2,uint param_3)

{
  uint uVar1;
  
  if (param_2 == 0) {
    uVar1 = param_3 & 0x1f;
    if (uVar1 < 0x10) {
      uVar1 = *(uint *)(param_1 + uVar1 * 4 + 0xac);
    }
    else {
      uVar1 = *(uint *)(&DAT_803be654 + uVar1 * 4);
    }
  }
  else {
    uVar1 = FUN_80283488(param_1,param_3);
    uVar1 = uVar1 & 0xffff;
  }
  return uVar1;
}

