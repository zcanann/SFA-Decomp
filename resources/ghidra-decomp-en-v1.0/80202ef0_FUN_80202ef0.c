// Function: FUN_80202ef0
// Entry: 80202ef0
// Size: 272 bytes

void FUN_80202ef0(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  char cVar4;
  int iVar3;
  
  cVar4 = FUN_8002e04c();
  if (cVar4 != '\0') {
    iVar3 = FUN_8002bdf4(0x24,0x30a);
    *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(param_1 + 0xc);
    *(float *)(iVar3 + 0xc) = FLOAT_803e637c + *(float *)(param_1 + 0x10);
    *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(param_1 + 0x14);
    *(undefined *)(iVar3 + 4) = 1;
    *(undefined *)(iVar3 + 5) = 1;
    *(undefined *)(iVar3 + 6) = 0xff;
    *(undefined *)(iVar3 + 7) = 0xff;
    iVar3 = FUN_8002df90(iVar3,5,(int)*(char *)(param_1 + 0xac),0xffffffff,0);
    if (iVar3 != 0) {
      fVar1 = *(float *)(param_2 + 0x2c0) / FLOAT_803e62b4;
      fVar2 = FLOAT_803e62b8 * fVar1;
      *(float *)(iVar3 + 0x24) =
           (*(float *)(*(int *)(param_2 + 0x2d0) + 0xc) - *(float *)(param_1 + 0xc)) / fVar2;
      *(float *)(iVar3 + 0x28) =
           ((FLOAT_803e6380 * fVar1 + *(float *)(*(int *)(param_2 + 0x2d0) + 0x10)) -
           *(float *)(param_1 + 0x10)) / fVar2;
      *(float *)(iVar3 + 0x2c) =
           (*(float *)(*(int *)(param_2 + 0x2d0) + 0x14) - *(float *)(param_1 + 0x14)) / fVar2;
      *(int *)(iVar3 + 0xc4) = param_1;
    }
  }
  return;
}

