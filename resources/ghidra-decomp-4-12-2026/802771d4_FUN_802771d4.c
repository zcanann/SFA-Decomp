// Function: FUN_802771d4
// Entry: 802771d4
// Size: 100 bytes

void FUN_802771d4(int param_1,int param_2,uint param_3,undefined4 param_4)

{
  uint uVar1;
  
  if (param_2 == 0) {
    uVar1 = param_3 & 0x1f;
    if (uVar1 < 0x10) {
      *(undefined4 *)(param_1 + uVar1 * 4 + 0xac) = param_4;
    }
    else {
      *(undefined4 *)(&DAT_803be654 + uVar1 * 4) = param_4;
    }
  }
  else {
    FUN_80283528(param_1,param_3,(short)param_4);
  }
  return;
}

