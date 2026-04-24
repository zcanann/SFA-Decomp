// Function: FUN_80112250
// Entry: 80112250
// Size: 228 bytes

void FUN_80112250(int param_1,int param_2,byte param_3)

{
  FUN_8000b7dc(param_1,0x7f);
  if ((param_3 & *(byte *)(param_2 + 0x404)) == 0) {
    if (*(short *)(param_2 + 0x3fc) != 0) {
      (**(code **)(*DAT_803dd6f4 + 8))(param_1,*(short *)(param_2 + 0x3fc),0,0,0);
    }
    if (*(short *)(param_2 + 0x3fa) != 0) {
      (**(code **)(*DAT_803dd6f4 + 8))(param_1,*(short *)(param_2 + 0x3fa),0,0,0);
    }
  }
  FUN_80012868((uint *)(param_2 + 900));
  if (*(uint *)(param_2 + 0x3dc) != 0) {
    FUN_800238c4(*(uint *)(param_2 + 0x3dc));
    *(undefined4 *)(param_2 + 0x3dc) = 0;
  }
  return;
}

