// Function: FUN_8007dd3c
// Entry: 8007dd3c
// Size: 156 bytes

undefined4
FUN_8007dd3c(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            undefined4 param_9)

{
  undefined4 uVar1;
  uint in_r9;
  uint in_r10;
  undefined8 uVar2;
  undefined8 extraout_f1;
  
  DAT_803ddcd8 = '\0';
  uVar2 = FUN_8007e7a0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  do {
    uVar1 = FUN_8007ed98(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,1,0,0,param_9
                         ,0,FUN_8007e99c,in_r9,in_r10);
    uVar2 = FUN_8007e328(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if (DAT_803ddcd8 != '\0') {
      uVar2 = FUN_8007e7a0(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
  } while (DAT_803ddcd8 != '\0');
  return uVar1;
}

