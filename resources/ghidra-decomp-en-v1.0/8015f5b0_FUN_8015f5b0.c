// Function: FUN_8015f5b0
// Entry: 8015f5b0
// Size: 276 bytes

void FUN_8015f5b0(int param_1)

{
  float fVar1;
  char cVar4;
  int iVar2;
  int iVar3;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  cVar4 = FUN_8002e04c();
  if (cVar4 != '\0') {
    iVar2 = FUN_8002bdf4(0x24,0x51b);
    *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(param_1 + 0xc);
    *(float *)(iVar2 + 0xc) = FLOAT_803e2e20 + *(float *)(param_1 + 0x10);
    *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(param_1 + 0x14);
    *(undefined *)(iVar2 + 4) = 1;
    *(undefined *)(iVar2 + 5) = 4;
    *(undefined *)(iVar2 + 7) = 0xff;
    iVar2 = FUN_8002df90(iVar2,5,0xffffffff,0xffffffff,0);
    if (iVar2 != 0) {
      iVar3 = FUN_8002b9ec();
      fVar1 = FLOAT_803e2e24;
      *(float *)(iVar2 + 0x24) =
           (*(float *)(iVar3 + 0xc) - *(float *)(param_1 + 0xc)) / FLOAT_803e2e24;
      *(float *)(iVar2 + 0x28) =
           ((*(float *)(iVar3 + 0x10) +
            (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x15)) - DOUBLE_803e2e28)) -
           *(float *)(param_1 + 0x10)) / fVar1;
      *(float *)(iVar2 + 0x2c) = (*(float *)(iVar3 + 0x14) - *(float *)(param_1 + 0x14)) / fVar1;
    }
  }
  return;
}

