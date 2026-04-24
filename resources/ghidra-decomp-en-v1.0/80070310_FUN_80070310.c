// Function: FUN_80070310
// Entry: 80070310
// Size: 156 bytes

void FUN_80070310(uint param_1,int param_2,uint param_3)

{
  if (((((uint)DAT_803dd018 != (param_1 & 0xff)) || (DAT_803dd014 != param_2)) ||
      ((uint)DAT_803dd012 != (param_3 & 0xff))) || (DAT_803dd01a == '\0')) {
    FUN_8025c708(param_1,param_2,param_3);
    DAT_803dd018 = (byte)param_1;
    DAT_803dd012 = (byte)param_3;
    DAT_803dd01a = '\x01';
    DAT_803dd014 = param_2;
  }
  return;
}

