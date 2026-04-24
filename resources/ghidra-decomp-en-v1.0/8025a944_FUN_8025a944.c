// Function: FUN_8025a944
// Entry: 8025a944
// Size: 288 bytes

void FUN_8025a944(uint *param_1,undefined param_2,uint param_3,int param_4,uint param_5,int param_6,
                 undefined4 param_7,int param_8)

{
  if (param_4 == 1) {
    param_8 = 4;
  }
  else if (param_4 < 1) {
    if (-1 < param_4) {
      param_8 = 3;
    }
  }
  else if (param_4 < 3) {
    param_8 = 5;
  }
  *param_1 = 0;
  *param_1 = *param_1 & 0xffff8000 | param_3 >> 5;
  *param_1 = *param_1 & 0xfffc7fff | param_8 << 0xf;
  *param_1 = *param_1 & 0xffe3ffff | param_8 << 0x12;
  *param_1 = *param_1 & 0xffdfffff;
  if (param_6 == 2) {
    param_8 = 5;
  }
  else if (param_6 < 2) {
    if (param_6 == 0) {
      param_8 = 3;
    }
    else if (-1 < param_6) {
      param_8 = 4;
    }
  }
  else if (param_6 < 4) {
    param_8 = 0;
  }
  param_1[1] = 0;
  param_1[1] = param_1[1] & 0xffff8000 | param_5 >> 5;
  param_1[1] = param_1[1] & 0xfffc7fff | param_8 << 0xf;
  param_1[1] = param_1[1] & 0xffe3ffff | param_8 << 0x12;
  *(undefined *)(param_1 + 3) = param_2;
  *(undefined *)((int)param_1 + 0xd) = 1;
  return;
}

