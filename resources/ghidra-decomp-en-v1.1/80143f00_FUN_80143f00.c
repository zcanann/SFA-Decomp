// Function: FUN_80143f00
// Entry: 80143f00
// Size: 140 bytes

undefined4
FUN_80143f00(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int *param_10,int param_11,undefined4 param_12,byte param_13,uint param_14,
            undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = FUN_80144994(param_9,param_10);
  if (iVar1 == 0) {
    iVar1 = FUN_8013b6f0((double)FLOAT_803e3098,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,param_10,param_11,param_12,param_13,param_14,param_15,
                         param_16);
    if (iVar1 == 1) {
      if (FLOAT_803e306c == (float)param_10[0x1c7]) {
        *(undefined *)((int)param_10 + 10) = 0;
      }
      uVar2 = 1;
    }
    else {
      *(undefined *)((int)param_10 + 10) = 0;
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}

