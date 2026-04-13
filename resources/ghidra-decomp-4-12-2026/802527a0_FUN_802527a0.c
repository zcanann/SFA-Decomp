// Function: FUN_802527a0
// Entry: 802527a0
// Size: 152 bytes

bool FUN_802527a0(int param_1)

{
  uint uVar1;
  uint uVar2;
  
  FUN_80243e74();
  uVar1 = DAT_cc006434;
  if (param_1 == 0) {
    uVar2 = uVar1 & 0xf7ffffff;
  }
  else {
    DAT_803af040 = 0;
    uVar2 = uVar1 | 0x8000000;
    DAT_803af044 = 0;
    DAT_803af048 = 0;
    DAT_803af04c = 0;
  }
  DAT_cc006434 = uVar2 & 0x7ffffffe;
  FUN_80243e9c();
  return (uVar1 & 0x8000000) != 0;
}

