// Function: FUN_8024983c
// Entry: 8024983c
// Size: 236 bytes

void FUN_8024983c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 *param_9,uint param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = param_9[0xc];
  uVar2 = uVar1;
  if ((uVar1 + param_11 & 0x7fff) != 0) {
    uVar2 = param_11;
    param_1 = FUN_80242fc0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           &DAT_803dd1c8,0x4a2,s_DVDPrepareStreamAsync____Specifi_8032e650,uVar1,
                           param_11,param_14,param_15,param_16);
  }
  if (param_10 == 0) {
    param_10 = param_9[0xd] - param_11;
  }
  if ((param_10 & 0x7fff) != 0) {
    param_1 = FUN_80242fc0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           &DAT_803dd1c8,0x4ac,s_DVDPrepareStreamAsync____Specifi_8032e6b8,param_10,
                           uVar2,param_14,param_15,param_16);
  }
  if (((uint)param_9[0xd] <= param_11) || ((uint)param_9[0xd] < param_11 + param_10)) {
    FUN_80242fc0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,&DAT_803dd1c8,0x4b4
                 ,s_DVDPrepareStreamAsync____The_are_8032e710,param_11,param_10,param_14,param_15,
                 param_16);
  }
  param_9[0xe] = param_12;
  FUN_8024b678(param_9,param_10,param_9[0xc] + param_11,&LAB_80249928);
  return;
}

