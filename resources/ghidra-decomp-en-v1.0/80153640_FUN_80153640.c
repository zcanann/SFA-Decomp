// Function: FUN_80153640
// Entry: 80153640
// Size: 336 bytes

void FUN_80153640(int param_1,int param_2)

{
  float fVar1;
  char cVar5;
  int iVar2;
  int iVar3;
  uint uVar4;
  
  cVar5 = FUN_8002e04c();
  if (cVar5 != '\0') {
    iVar2 = FUN_8002bdf4(0x24,0x51b);
    *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(param_1 + 0xc);
    *(float *)(iVar2 + 0xc) = FLOAT_803e28f0 + *(float *)(param_1 + 0x10);
    *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(param_1 + 0x14);
    *(undefined *)(iVar2 + 4) = 1;
    *(undefined *)(iVar2 + 5) = 1;
    *(undefined *)(iVar2 + 6) = 0xff;
    *(undefined *)(iVar2 + 7) = 0xff;
    iVar3 = FUN_8002df90(iVar2,5,0xffffffff,0xffffffff,0);
    if (iVar3 != 0) {
      *(float *)(iVar3 + 0x24) =
           FLOAT_803e28f4 * (*(float *)(*(int *)(param_2 + 0x29c) + 0xc) - *(float *)(iVar2 + 8));
      uVar4 = FUN_800221a0(0xfffffff6,10);
      fVar1 = FLOAT_803e28f4;
      *(float *)(iVar3 + 0x28) =
           FLOAT_803e28f4 *
           ((FLOAT_803e28f0 + *(float *)(*(int *)(param_2 + 0x29c) + 0x10) +
            (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e28f8)) -
           *(float *)(iVar2 + 0xc));
      *(float *)(iVar3 + 0x2c) =
           fVar1 * (*(float *)(*(int *)(param_2 + 0x29c) + 0x14) - *(float *)(iVar2 + 0x10));
      *(int *)(iVar3 + 0xc4) = param_1;
    }
    FUN_8000bb18(param_1,0x49a);
  }
  return;
}

