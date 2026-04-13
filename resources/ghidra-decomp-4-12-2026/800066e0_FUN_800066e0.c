// Function: FUN_800066e0
// Entry: 800066e0
// Size: 100 bytes

undefined4
FUN_800066e0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
            undefined4 param_10,uint param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  
  uVar1 = FUN_80023d8c(0x28,-1);
  FUN_8001f7e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,0xc,
               (param_11 & 0xffff) * 0x28,0x28,param_13,param_14,param_15,param_16);
  FUN_800238c4(uVar1);
  return 0;
}

