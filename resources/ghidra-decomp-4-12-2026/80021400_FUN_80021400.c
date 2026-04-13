// Function: FUN_80021400
// Entry: 80021400
// Size: 52 bytes

void FUN_80021400(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                 undefined4 param_10,undefined4 param_11,int param_12,undefined4 param_13,
                 int param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  undefined4 extraout_r4;
  undefined4 uVar2;
  undefined4 extraout_r4_00;
  undefined8 uVar3;
  
  DAT_803dd6bd = 0;
  DAT_803dd6c9 = 0;
  uVar3 = FUN_80020e50(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_803dd6c9 = 1;
  DAT_803dd6bd = 1;
  uVar2 = extraout_r4;
  do {
    uVar1 = FUN_80020390();
    uVar3 = FUN_80020cf0(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar2,
                         param_11,param_12,param_13,param_14,param_15,param_16);
    uVar2 = extraout_r4_00;
  } while( true );
}

