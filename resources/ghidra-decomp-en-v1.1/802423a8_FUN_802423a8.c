// Function: FUN_802423a8
// Entry: 802423a8
// Size: 172 bytes

uint FUN_802423a8(uint param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = param_3 + 0x1fU >> 5;
  uVar1 = uVar2 + 0x7f;
  while (uVar2 != 0) {
    if (uVar2 < 0x80) {
      FUN_80242384(param_1);
      uVar2 = 0;
    }
    else {
      FUN_80242384(param_1);
      uVar2 = uVar2 - 0x80;
      param_1 = param_1 + 0x1000;
    }
  }
  return uVar1 >> 7;
}

