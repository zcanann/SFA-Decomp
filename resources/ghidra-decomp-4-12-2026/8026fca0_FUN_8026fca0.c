// Function: FUN_8026fca0
// Entry: 8026fca0
// Size: 72 bytes

void FUN_8026fca0(int param_1,byte param_2,uint param_3)

{
  uint uVar1;
  
  uVar1 = (uint)param_2;
  if (param_2 == 0xff) {
    uVar1 = 8;
  }
  *(uint *)(&DAT_803bd9f0 + (param_3 & 0xff) * 4 + uVar1 * 0x40) = (uint)(param_1 * 0x3000) / 0xf0;
  return;
}

