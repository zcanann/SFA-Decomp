// Function: FUN_8027716c
// Entry: 8027716c
// Size: 104 bytes

int FUN_8027716c(int param_1,int param_2,uint param_3)

{
  short sVar1;
  uint uVar2;
  
  if (param_2 == 0) {
    uVar2 = param_3 & 0x1f;
    if (uVar2 < 0x10) {
      sVar1 = (short)*(undefined4 *)(param_1 + uVar2 * 4 + 0xac);
    }
    else {
      sVar1 = (short)*(undefined4 *)(&DAT_803be654 + uVar2 * 4);
    }
  }
  else {
    uVar2 = FUN_80283488(param_1,param_3);
    sVar1 = (short)uVar2;
  }
  return (int)sVar1;
}

