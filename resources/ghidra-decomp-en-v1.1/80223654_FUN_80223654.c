// Function: FUN_80223654
// Entry: 80223654
// Size: 276 bytes

undefined4
FUN_80223654(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,char param_12,undefined4 param_13,undefined4 param_14,undefined4 param_15,
            undefined4 param_16)

{
  byte bVar1;
  int iVar2;
  undefined4 uVar3;
  float *pfVar4;
  undefined8 uVar5;
  undefined8 extraout_f1;
  
  pfVar4 = *(float **)(param_9 + 0xb8);
  *(byte *)((int)pfVar4 + 0x659) = *(byte *)((int)pfVar4 + 0x659) & 0xfe;
  uVar5 = FUN_8003b408(param_9,(int)(pfVar4 + 0x189));
  uVar3 = 0;
  iVar2 = FUN_80114e4c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       param_11,pfVar4,0,0,param_14,param_15,param_16);
  if (iVar2 == 0) {
    uVar5 = extraout_f1;
    if (param_12 != '\0') {
      param_2 = (double)FLOAT_803dc074;
      uVar5 = FUN_8002fb40((double)FLOAT_803e7974,param_2);
    }
    for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar2 = iVar2 + 1) {
      bVar1 = *(byte *)(param_11 + iVar2 + 0x81);
      if (bVar1 == 2) {
        uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             param_9,0x200,0,uVar3,param_14,param_15,param_16);
      }
      else if ((bVar1 < 2) && (bVar1 != 0)) {
        uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             param_9,0x1fd,0,uVar3,param_14,param_15,param_16);
      }
    }
  }
  return 0;
}

