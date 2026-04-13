// Function: FUN_802836f4
// Entry: 802836f4
// Size: 72 bytes

void FUN_802836f4(uint *param_1,int param_2)

{
  uint uVar1;
  
  uVar1 = FUN_8026fce8(param_2);
  *param_1 = ((*param_1 << 0x10) / uVar1) * 1000 >> 5;
  return;
}

