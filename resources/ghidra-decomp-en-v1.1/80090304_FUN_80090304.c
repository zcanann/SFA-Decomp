// Function: FUN_80090304
// Entry: 80090304
// Size: 504 bytes

void FUN_80090304(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  undefined8 extraout_f1;
  
  puVar1 = FUN_800e877c();
  if (((-1 < param_9) && (param_9 < 3)) &&
     (iVar2 = FUN_800e8a48(), param_1 = extraout_f1, iVar2 == 0)) {
    *(undefined2 *)((int)puVar1 + param_9 * 2 + 0xe) = 0xffff;
    *(undefined *)((int)puVar1 + param_9 + 0x41) = 0xff;
  }
  iVar2 = 0;
  if (((((((DAT_8039b488 == 0) || (param_9 != *(int *)(DAT_8039b488 + 0x13f0))) &&
         ((iVar2 = 1, DAT_8039b48c == 0 || (param_9 != *(int *)(DAT_8039b48c + 0x13f0))))) &&
        ((iVar2 = 2, DAT_8039b490 == 0 || (param_9 != *(int *)(DAT_8039b490 + 0x13f0))))) &&
       ((iVar2 = 3, DAT_8039b494 == 0 || (param_9 != *(int *)(DAT_8039b494 + 0x13f0))))) &&
      ((((iVar2 = 4, DAT_8039b498 == 0 || (param_9 != *(int *)(DAT_8039b498 + 0x13f0))) &&
        ((iVar2 = 5, DAT_8039b49c == 0 || (param_9 != *(int *)(DAT_8039b49c + 0x13f0))))) &&
       ((iVar2 = 6, DAT_8039b4a0 == 0 || (param_9 != *(int *)(DAT_8039b4a0 + 0x13f0))))))) &&
     ((iVar2 = 7, DAT_8039b4a4 == 0 || (param_9 != *(int *)(DAT_8039b4a4 + 0x13f0))))) {
    iVar2 = 8;
  }
  iVar3 = (&DAT_8039b488)[iVar2];
  if ((iVar3 != 0) && (iVar2 != 8)) {
    if (param_9 == *(int *)(iVar3 + 0x13f0)) {
      if (*(uint *)(iVar3 + 4) != 0) {
        FUN_800238c4(*(uint *)(iVar3 + 4));
        *(undefined4 *)((&DAT_8039b488)[iVar2] + 4) = 0;
      }
      if ((&DAT_8039b488)[iVar2] != 0) {
        FUN_800238c4((&DAT_8039b488)[iVar2]);
        (&DAT_8039b488)[iVar2] = 0;
      }
    }
    else {
      FUN_80137c30(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   s_____Error_non_existant_cloud_id___803101b0,param_9,iVar2,param_12,param_13,
                   param_14,param_15,param_16);
    }
  }
  return;
}

