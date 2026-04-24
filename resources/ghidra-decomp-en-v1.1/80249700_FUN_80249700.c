// Function: FUN_80249700
// Entry: 80249700
// Size: 280 bytes

undefined4
FUN_80249700(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            undefined4 *param_9,undefined4 param_10,int param_11,uint param_12,int param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  
  uVar3 = param_12;
  iVar1 = param_13;
  if (-1 < (int)param_12) {
    if (param_12 < (uint)param_9[0xd]) goto LAB_8024974c;
  }
  param_1 = FUN_80242fc0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         &DAT_803dd1c8,0x329,s_DVDRead____specified_area_is_out_8032e5bc,param_12,
                         param_13,param_14,param_15,param_16);
LAB_8024974c:
  if (((int)(param_12 + param_11) < 0) || (param_9[0xd] + 0x20 <= param_12 + param_11)) {
    FUN_80242fc0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,&DAT_803dd1c8,0x32f
                 ,s_DVDRead____specified_area_is_out_8032e5bc,uVar3,iVar1,param_14,param_15,param_16
                );
  }
  iVar1 = FUN_8024b3f8(param_9,param_10,param_11,param_9[0xc] + param_12,&LAB_80249818,param_13);
  if (iVar1 == 0) {
    uVar2 = 0xffffffff;
  }
  else {
    FUN_80243e74();
    while (iVar1 = param_9[3], iVar1 != 0) {
      if (iVar1 == -1) {
        uVar2 = 0xffffffff;
        goto LAB_802497f8;
      }
      if (iVar1 == 10) {
        uVar2 = 0xfffffffd;
        goto LAB_802497f8;
      }
      FUN_802471c4((int *)&DAT_803deb80);
    }
    uVar2 = param_9[8];
LAB_802497f8:
    FUN_80243e9c();
  }
  return uVar2;
}

