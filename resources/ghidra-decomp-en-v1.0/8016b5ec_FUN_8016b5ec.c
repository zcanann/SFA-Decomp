// Function: FUN_8016b5ec
// Entry: 8016b5ec
// Size: 284 bytes

void FUN_8016b5ec(undefined2 *param_1)

{
  float fVar1;
  char cVar3;
  int iVar2;
  int *piVar4;
  float local_18 [4];
  
  piVar4 = *(int **)(param_1 + 0x5c);
  FUN_80035f00();
  *(undefined *)(param_1 + 0x1b) = 0xff;
  fVar1 = FLOAT_803e31c8;
  *(float *)(param_1 + 0x12) = FLOAT_803e31c8;
  *(float *)(param_1 + 0x14) = FLOAT_803e31d4;
  *(float *)(param_1 + 0x16) = fVar1;
  param_1[1] = 0xc000;
  *param_1 = 0;
  param_1[2] = 0;
  FUN_80065684((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
               (double)*(float *)(param_1 + 10),param_1,local_18,0);
  piVar4[1] = (int)(*(float *)(param_1 + 8) - local_18[0]);
  cVar3 = FUN_8002e04c();
  if (cVar3 == '\0') {
    *piVar4 = 0;
  }
  else {
    iVar2 = FUN_8002bdf4(0x20,0xc);
    *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(param_1 + 10);
    *(undefined *)(iVar2 + 4) = 1;
    *(undefined *)(iVar2 + 5) = 1;
    *(undefined *)(iVar2 + 6) = 0xff;
    *(undefined *)(iVar2 + 7) = 0xff;
    iVar2 = FUN_8002b5a0(param_1);
    *piVar4 = iVar2;
    *(undefined2 **)(*piVar4 + 0xc4) = param_1;
  }
  iVar2 = FUN_80013ec8(0x5b,1);
  piVar4[2] = iVar2;
  *(undefined *)(piVar4 + 3) = 0;
  return;
}

