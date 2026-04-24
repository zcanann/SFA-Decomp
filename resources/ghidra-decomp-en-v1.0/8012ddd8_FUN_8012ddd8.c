// Function: FUN_8012ddd8
// Entry: 8012ddd8
// Size: 316 bytes

void FUN_8012ddd8(undefined4 param_1,byte param_2,uint param_3,undefined param_4)

{
  int iVar1;
  
  if (((param_3 & 8) != 0) &&
     (DAT_803dd77a = param_2,
     iVar1 = FUN_8001ffb4(*(undefined2 *)(&DAT_8031b08a + (uint)param_2 * 0x1c)), iVar1 == 0)) {
    param_2 = 5;
  }
  if ((param_3 & 4) == 0) {
    if ((param_3 & 2) == 0) {
      if ((param_3 & 1) != 0) {
        DAT_803dd77f = 1;
      }
      DAT_803dba5c = (uint)param_2;
      DAT_803dba60 = param_1;
      if (DAT_803dd774 == 0) {
        DAT_803dd774 = 1;
      }
      else if (0x7f < DAT_803dd774) {
        DAT_803dd774 = 0xff - DAT_803dd774;
      }
    }
    else if (DAT_803dd774 != 0) {
      if (DAT_803dd774 < 0x7f) {
        DAT_803dd774 = 0xff - DAT_803dd774;
      }
      if (DAT_803dd774 < 0xd9) {
        DAT_803dd774 = 0xd9;
      }
      DAT_803dd77f = 0;
    }
  }
  else {
    DAT_803dd774 = 0;
  }
  DAT_803dd77b = param_4;
  return;
}

