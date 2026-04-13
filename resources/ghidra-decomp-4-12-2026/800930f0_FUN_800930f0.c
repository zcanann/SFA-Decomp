// Function: FUN_800930f0
// Entry: 800930f0
// Size: 504 bytes

void FUN_800930f0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,uint param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  undefined4 extraout_r4;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  
  if (param_10 == 0) {
    if (param_9 == -1) {
      iVar4 = 0;
      uVar1 = 0;
      uVar3 = 0xffffffff;
      do {
        param_1 = FUN_80090304(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4
                               ,uVar1,param_11,param_12,param_13,uVar3,param_15,param_16);
        iVar4 = iVar4 + 1;
        uVar1 = extraout_r4;
      } while (iVar4 < 8);
    }
    else {
      FUN_80090304(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,0,
                   param_11,param_12,param_13,param_9,param_15,param_16);
    }
  }
  else {
    iVar4 = 0;
    if (((((((DAT_8039b488 == 0) || (param_9 != *(int *)(DAT_8039b488 + 0x13f0))) &&
           ((iVar4 = 1, DAT_8039b48c == 0 || (param_9 != *(int *)(DAT_8039b48c + 0x13f0))))) &&
          ((iVar4 = 2, DAT_8039b490 == 0 || (param_9 != *(int *)(DAT_8039b490 + 0x13f0))))) &&
         ((iVar4 = 3, DAT_8039b494 == 0 || (param_9 != *(int *)(DAT_8039b494 + 0x13f0))))) &&
        ((((iVar4 = 4, DAT_8039b498 == 0 || (param_9 != *(int *)(DAT_8039b498 + 0x13f0))) &&
          ((iVar4 = 5, DAT_8039b49c == 0 || (param_9 != *(int *)(DAT_8039b49c + 0x13f0))))) &&
         ((iVar4 = 6, DAT_8039b4a0 == 0 || (param_9 != *(int *)(DAT_8039b4a0 + 0x13f0))))))) &&
       ((iVar4 = 7, DAT_8039b4a4 == 0 || (param_9 != *(int *)(DAT_8039b4a4 + 0x13f0))))) {
      iVar4 = 8;
    }
    iVar2 = (&DAT_8039b488)[iVar4];
    if ((iVar2 != 0) && (iVar4 != 8)) {
      if (param_9 == *(int *)(iVar2 + 0x13f0)) {
        *(undefined4 *)(iVar2 + 0x13f8) = 1;
        *(float *)((&DAT_8039b488)[iVar4] + 0x1430) =
             -((float)((double)CONCAT44(0x43300000,param_10 ^ 0x80000000) - DOUBLE_803dfe28) /
              (float)((double)CONCAT44(0x43300000,
                                       *(uint *)((&DAT_8039b488)[iVar4] + 0x13fc) ^ 0x80000000) -
                     DOUBLE_803dfe28));
      }
      else {
        FUN_80137c30(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     s_____Error_non_existant_cloud_id___803102f0,param_9,iVar4 * 4,iVar2,iVar4,
                     param_9,param_15,param_16);
      }
    }
  }
  return;
}

