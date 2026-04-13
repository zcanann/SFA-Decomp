// Function: FUN_8007048c
// Entry: 8007048c
// Size: 156 bytes

void FUN_8007048c(uint param_1,int param_2,uint param_3)

{
  if (((((uint)DAT_803ddc98 != (param_1 & 0xff)) || (DAT_803ddc94 != param_2)) ||
      ((uint)DAT_803ddc92 != (param_3 & 0xff))) || (DAT_803ddc9a == '\0')) {
    FUN_8025ce6c(param_1,param_2,param_3);
    DAT_803ddc98 = (byte)param_1;
    DAT_803ddc92 = (byte)param_3;
    DAT_803ddc9a = '\x01';
    DAT_803ddc94 = param_2;
  }
  return;
}

