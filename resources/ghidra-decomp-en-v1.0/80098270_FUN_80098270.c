// Function: FUN_80098270
// Entry: 80098270
// Size: 268 bytes

void FUN_80098270(undefined8 param_1,double param_2,undefined4 param_3,char param_4,uint param_5)

{
  uint uVar1;
  float local_38;
  float local_34;
  float local_30;
  uint local_2c [5];
  uint local_18 [4];
  undefined4 local_8;
  
  local_18[0] = DAT_802c1ff8;
  local_18[1] = DAT_802c1ffc;
  local_18[2] = DAT_802c2000;
  local_18[3] = DAT_802c2004;
  local_8 = DAT_802c2008;
  local_2c[0] = DAT_802c200c;
  local_2c[1] = DAT_802c2010;
  local_2c[2] = DAT_802c2014;
  local_2c[3] = DAT_802c2018;
  local_2c[4] = DAT_802c201c;
  if (((param_4 != '\0') && (uVar1 = param_5 & 0xff, uVar1 != 0)) && (uVar1 < 5)) {
    if (FLOAT_803dd260 == FLOAT_803df35c) {
      uVar1 = local_2c[uVar1] & 0xff;
    }
    else {
      uVar1 = 0;
    }
    local_38 = FLOAT_803df35c;
    local_34 = (float)param_2;
    local_30 = FLOAT_803df35c;
    if (param_4 == '\x01') {
      FUN_80098b18(param_3,local_18[param_5 & 0xff] & 0xff,uVar1,0,&local_38);
    }
  }
  return;
}

