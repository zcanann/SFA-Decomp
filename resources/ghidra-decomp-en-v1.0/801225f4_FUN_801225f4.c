// Function: FUN_801225f4
// Entry: 801225f4
// Size: 776 bytes

void FUN_801225f4(undefined4 param_1,undefined4 param_2,short param_3,uint param_4,uint param_5,
                 int *param_6,uint param_7)

{
  int iVar1;
  undefined4 uVar2;
  short extraout_r4;
  float local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  double local_30;
  double local_28;
  
  iVar1 = FUN_802860d8();
  local_3c = DAT_803e1e1c;
  local_38 = DAT_803e1e20;
  local_44 = DAT_803e1e24;
  local_40 = DAT_803e1e28;
  if ((param_4 & 0xff) == 0) goto LAB_801228e4;
  local_30 = (double)CONCAT44(0x43300000,param_5 ^ 0x80000000);
  if ((float)(local_30 - DOUBLE_803e1e78) < FLOAT_803e1f9c) {
LAB_801226a4:
    local_30 = (double)CONCAT44(0x43300000,0x23fU - *param_6 ^ 0x80000000);
    FUN_8007719c((double)(float)(local_30 - DOUBLE_803e1e78),(double)FLOAT_803e1fb8,
                 (&DAT_803a89b0)[iVar1],param_4,0x100);
    if (iVar1 == 0x1e) {
      if ((param_7 & 0xff) == 0) {
        FUN_8028f688(&local_3c,&DAT_803dbb50,(int)extraout_r4);
      }
      else {
        iVar1 = (int)extraout_r4;
        if (iVar1 < 0) {
          iVar1 = -iVar1;
        }
        FUN_8028f688(&local_3c,s__02d__02d_8031c0b0,iVar1,(int)param_3);
        iVar1 = (int)extraout_r4;
        if (iVar1 < 0) {
          iVar1 = -iVar1;
        }
        FUN_8028f688(&local_44,&DAT_803dbb48,iVar1);
      }
    }
    else {
      FUN_8028f688(&local_3c,&DAT_803dbb58,(int)extraout_r4);
    }
    uVar2 = FUN_80019b14();
    FUN_80019b1c(3,3);
    FUN_800186f0((double)FLOAT_803e1e68,&local_3c,&local_48,0,0,0,0xffffffff);
    if (((param_7 & 0xff) == 0) && (param_3 <= extraout_r4)) {
      FUN_80019908(0,0xff,0,param_4);
    }
    else {
      FUN_80019908(0xff,0xff,0xff,param_4);
    }
    local_30 = (double)CONCAT44(0x43300000,0x24fU - *param_6 ^ 0x80000000);
    iVar1 = (int)-(FLOAT_803e1e70 * local_48 - (float)(local_30 - DOUBLE_803e1e78));
    local_28 = (double)(longlong)iVar1;
    FUN_80015dc8(&local_3c,0x93,iVar1,0x1a9);
    if ((param_7 & 0xff) != 0) {
      if (extraout_r4 < 0) {
        FUN_80019908(0xff,0,0,param_4);
      }
      else {
        FUN_80019908(0,0xff,0,param_4);
      }
      local_28 = (double)CONCAT44(0x43300000,0x24fU - *param_6 ^ 0x80000000);
      iVar1 = (int)-(FLOAT_803e1e70 * local_48 - (float)(local_28 - DOUBLE_803e1e78));
      local_30 = (double)(longlong)iVar1;
      FUN_80015dc8(&local_44,0x93,iVar1,0x1a9);
    }
    FUN_80019b1c(uVar2,3);
  }
  else {
    local_30 = (double)CONCAT44(0x43300000,param_5 ^ 0x80000000);
    if (((FLOAT_803e1fa8 < (float)(local_30 - DOUBLE_803e1e78)) || ((param_5 & 8) != 0)) ||
       (iVar1 == 0x1e)) goto LAB_801226a4;
  }
  *param_6 = *param_6 + 0x28;
LAB_801228e4:
  FUN_80286124();
  return;
}

