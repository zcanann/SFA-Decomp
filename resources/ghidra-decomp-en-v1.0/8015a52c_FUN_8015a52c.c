// Function: FUN_8015a52c
// Entry: 8015a52c
// Size: 308 bytes

void FUN_8015a52c(short *param_1)

{
  char cVar2;
  int iVar1;
  double dVar3;
  
  cVar2 = FUN_8002e04c();
  if (cVar2 != '\0') {
    iVar1 = FUN_8002bdf4(0x24,0x51b);
    *(undefined4 *)(iVar1 + 8) = *(undefined4 *)(param_1 + 6);
    *(float *)(iVar1 + 0xc) = FLOAT_803e2c98 + *(float *)(param_1 + 8);
    *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(param_1 + 10);
    *(undefined *)(iVar1 + 4) = 1;
    *(undefined *)(iVar1 + 5) = 4;
    *(undefined *)(iVar1 + 7) = 0xff;
    iVar1 = FUN_8002df90(iVar1,5,0xffffffff,0xffffffff,0);
    if (iVar1 != 0) {
      dVar3 = (double)FUN_80293e80((double)((FLOAT_803e2ca0 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*param_1 ^ 0x80000000) -
                                                   DOUBLE_803e2cb0)) / FLOAT_803e2ca4));
      *(float *)(iVar1 + 0x24) = (float)((double)FLOAT_803e2c9c * -dVar3);
      *(float *)(iVar1 + 0x28) = FLOAT_803e2ca8;
      dVar3 = (double)FUN_80294204((double)((FLOAT_803e2ca0 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*param_1 ^ 0x80000000) -
                                                   DOUBLE_803e2cb0)) / FLOAT_803e2ca4));
      *(float *)(iVar1 + 0x2c) = (float)((double)FLOAT_803e2c9c * -dVar3);
    }
  }
  return;
}

