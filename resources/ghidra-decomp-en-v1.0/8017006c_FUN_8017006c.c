// Function: FUN_8017006c
// Entry: 8017006c
// Size: 444 bytes

void FUN_8017006c(int param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar1 = *(int *)(iVar4 + 0x10);
  if (iVar1 == 2) {
    iVar1 = FUN_800801a8(iVar4 + 4);
    if (iVar1 == 0) {
      FUN_80035f20(param_1);
      FUN_80035df4(param_1,*(undefined4 *)(&DAT_803209c8 + *(char *)(iVar3 + 0x19) * 0xc),1,0);
      FUN_8002b95c((double)(*(float *)(param_1 + 0x24) * FLOAT_803db414),
                   (double)(*(float *)(param_1 + 0x28) * FLOAT_803db414),
                   (double)(*(float *)(param_1 + 0x2c) * FLOAT_803db414),param_1);
      FUN_80035974(param_1,(int)(*(float *)(iVar4 + 0xc) *
                                (((float)((double)CONCAT44(0x43300000,DAT_803dbd64 ^ 0x80000000) -
                                         DOUBLE_803e3398) - *(float *)(iVar4 + 4)) /
                                (float)((double)CONCAT44(0x43300000,DAT_803dbd64 ^ 0x80000000) -
                                       DOUBLE_803e3398))));
    }
    else {
      FUN_80035f00(param_1);
      FUN_8021fa38(param_1);
    }
  }
  else if ((iVar1 < 2) && (0 < iVar1)) {
    *(float *)(param_1 + 0x24) = FLOAT_803e338c;
    uVar2 = FUN_800221a0(100,0x96);
    *(float *)(param_1 + 0x2c) =
         FLOAT_803dbd68 *
         FLOAT_803e3390 *
         *(float *)(iVar4 + 8) *
         FLOAT_803e3394 * (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3398)
    ;
    FUN_80021ac8(param_1,param_1 + 0x24);
    *(float *)(iVar4 + 0xc) = FLOAT_803dbd6c * *(float *)(iVar4 + 8);
    FUN_80080178(iVar4 + 4,(int)(short)DAT_803dbd64);
    *(undefined4 *)(iVar4 + 0x10) = 2;
  }
  return;
}

