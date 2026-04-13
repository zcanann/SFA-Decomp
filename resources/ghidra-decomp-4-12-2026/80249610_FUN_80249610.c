// Function: FUN_80249610
// Entry: 80249610
// Size: 192 bytes

undefined4
FUN_80249610(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            undefined4 *param_9,undefined4 param_10,int param_11,uint param_12,undefined4 param_13,
            int param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  
  uVar1 = param_12;
  uVar2 = param_13;
  iVar3 = param_14;
  if (-1 < (int)param_12) {
    if (param_12 < (uint)param_9[0xd]) goto LAB_80249660;
  }
  param_1 = FUN_80242fc0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         &DAT_803dd1c8,0x2e3,s_DVDReadAsync____specified_area_i_8032e588,param_12,
                         param_13,param_14,param_15,param_16);
LAB_80249660:
  if (((int)(param_12 + param_11) < 0) || (param_9[0xd] + 0x20 <= param_12 + param_11)) {
    FUN_80242fc0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,&DAT_803dd1c8,0x2e9
                 ,s_DVDReadAsync____specified_area_i_8032e588,uVar1,uVar2,iVar3,param_15,param_16);
  }
  param_9[0xe] = param_13;
  FUN_8024b3f8(param_9,param_10,param_11,param_9[0xc] + param_12,&LAB_802496d0,param_14);
  return 1;
}

