// Function: FUN_80217f80
// Entry: 80217f80
// Size: 328 bytes

void FUN_80217f80(int param_1)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  FUN_80035f20();
  *(undefined *)(piVar2 + 1) = 4;
  *(undefined2 *)(param_1 + 4) = 0;
  iVar1 = FUN_8001f4c8(param_1,1);
  if (iVar1 != 0) {
    FUN_8001db2c(iVar1,2);
    FUN_8001daf0(iVar1,0xff,0x80,0,0);
    FUN_8001db14(iVar1,1);
    FUN_8001dc38((double)FLOAT_803e6940,(double)FLOAT_803e6944,iVar1);
    FUN_8001d730((double)FLOAT_803e6948,iVar1,0,0,0xff,0xff,0x80);
    FUN_8001d714((double)FLOAT_803e694c,iVar1);
  }
  *piVar2 = iVar1;
  if (*piVar2 != 0) {
    FUN_8001dc38((double)FLOAT_803e6950,(double)FLOAT_803e6954);
  }
  *(undefined *)(param_1 + 0x36) = 0xff;
  *(float *)(param_1 + 8) = FLOAT_803e6958 * *(float *)(*(int *)(param_1 + 0x50) + 4);
  piVar2[2] = 0x960;
  FUN_80035960(param_1,4);
  FUN_80035df4(param_1,0x16,1,0);
  FUN_8000bb18(param_1,0x3c5);
  FUN_8000bb18(param_1,0x3c6);
  return;
}

