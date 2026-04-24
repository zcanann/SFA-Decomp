// Function: FUN_800984fc
// Entry: 800984fc
// Size: 268 bytes

void FUN_800984fc(undefined8 param_1,double param_2,undefined4 param_3,char param_4,uint param_5)

{
  uint uVar1;
  float local_38;
  float local_34;
  float local_30;
  uint local_2c [5];
  uint local_18 [4];
  undefined4 local_8;
  
  local_18[0] = DAT_802c2778;
  local_18[1] = DAT_802c277c;
  local_18[2] = DAT_802c2780;
  local_18[3] = DAT_802c2784;
  local_8 = DAT_802c2788;
  local_2c[0] = DAT_802c278c;
  local_2c[1] = DAT_802c2790;
  local_2c[2] = DAT_802c2794;
  local_2c[3] = DAT_802c2798;
  local_2c[4] = DAT_802c279c;
  if (((param_4 != '\0') && (uVar1 = param_5 & 0xff, uVar1 != 0)) && (uVar1 < 5)) {
    if (FLOAT_803ddee0 == FLOAT_803dffdc) {
      uVar1 = local_2c[uVar1] & 0xff;
    }
    else {
      uVar1 = 0;
    }
    local_38 = FLOAT_803dffdc;
    local_34 = (float)param_2;
    local_30 = FLOAT_803dffdc;
    if (param_4 == '\x01') {
      FUN_80098da4(param_3,local_18[param_5 & 0xff] & 0xff,uVar1,0,&local_38);
    }
  }
  return;
}

