// Function: FUN_801bae34
// Entry: 801bae34
// Size: 216 bytes

undefined4
FUN_801bae34(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  undefined4 uVar2;
  
  *(float *)(param_10 + 0x2a0) = FLOAT_803e5888;
  fVar1 = FLOAT_803e5870;
  *(float *)(param_10 + 0x280) = FLOAT_803e5870;
  *(float *)(param_10 + 0x284) = fVar1;
  uVar2 = 0xffffffff;
  FUN_80035eec(param_9,10,1,-1);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e5870,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xf,0,uVar2,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if ((*(uint *)(param_10 + 0x314) & 1) != 0) {
    DAT_803de800 = DAT_803de800 | 0x4004;
    FUN_8000bb38(param_9,0x17d);
    FUN_8000faf8();
    FUN_8000e670((double)FLOAT_803e5860,(double)FLOAT_803e588c,(double)FLOAT_803e5890);
    FUN_80014acc((double)FLOAT_803e5894);
    FUN_800201ac(0x26b,1);
  }
  return 0;
}

