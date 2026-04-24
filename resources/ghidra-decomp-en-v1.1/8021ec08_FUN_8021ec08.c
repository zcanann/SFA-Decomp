// Function: FUN_8021ec08
// Entry: 8021ec08
// Size: 168 bytes

void FUN_8021ec08(uint param_1,int param_2,int param_3)

{
  uint uVar1;
  
  uVar1 = *(uint *)(param_3 + 0x314);
  if ((uVar1 & 0x81) != 0) {
    if ((uVar1 & 1) != 0) {
      param_2 = 0;
    }
    if ((uVar1 & 0x80) != 0) {
      param_2 = 1;
    }
    FUN_8000bb38(param_1,(&DAT_803dcf78)[param_2]);
  }
  if ((*(uint *)(param_3 + 0x314) & 0x100) != 0) {
    FUN_8009ab54((double)FLOAT_803e77c8,param_1);
    FUN_8000bb38(param_1,DAT_803dcf78);
  }
  return;
}

