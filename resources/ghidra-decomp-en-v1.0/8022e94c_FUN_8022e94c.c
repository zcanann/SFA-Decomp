// Function: FUN_8022e94c
// Entry: 8022e94c
// Size: 536 bytes

void FUN_8022e94c(int param_1)

{
  float fVar1;
  int iVar2;
  undefined *puVar3;
  
  puVar3 = *(undefined **)(param_1 + 0xb8);
  iVar2 = FUN_8022d768();
  fVar1 = FLOAT_803e7008;
  if ((iVar2 == 0) || ((*(ushort *)(iVar2 + 0xb0) & 0x1000) == 0)) {
    if (*(float *)(puVar3 + 0x10) <= FLOAT_803e7008) {
      FUN_80035df4(param_1,0xf,puVar3[0x18],0);
      *(undefined *)(param_1 + 0x36) = 0xff;
      fVar1 = FLOAT_803e7008;
      if (FLOAT_803e7008 < *(float *)(puVar3 + 4)) {
        *(float *)(puVar3 + 4) = *(float *)(puVar3 + 4) - FLOAT_803db414;
        if (fVar1 < *(float *)(puVar3 + 4)) {
          if (*(char *)(*(int *)(param_1 + 0x54) + 0xad) != '\0') {
            if (*(short *)(param_1 + 0x46) != 0x6ae) {
              FUN_8000b4d0(param_1,0x2b3,4);
            }
            *(float *)(puVar3 + 0x10) = FLOAT_803e7028;
            *(undefined *)(param_1 + 0x36) = 0;
            FUN_80099660((double)FLOAT_803e701c,param_1,*puVar3);
            if (*(int *)(puVar3 + 0x14) != 0) {
              FUN_8001f384();
              *(undefined4 *)(puVar3 + 0x14) = 0;
            }
          }
          FUN_8002b95c((double)(*(float *)(param_1 + 0x24) * FLOAT_803db414),
                       (double)(*(float *)(param_1 + 0x28) * FLOAT_803db414),
                       (double)(*(float *)(param_1 + 0x2c) * FLOAT_803db414),param_1);
          if (*(short *)(param_1 + 0x46) == 0x80d) {
            *(short *)(param_1 + 4) = *(short *)(param_1 + 4) + *(short *)(puVar3 + 0x1a);
            *(short *)(param_1 + 2) = *(short *)(param_1 + 2) + *(short *)(puVar3 + 0x1c);
          }
          if (*(short *)(param_1 + 0x46) == 0x7e4) {
            *(float *)(param_1 + 8) = *(float *)(param_1 + 8) + FLOAT_803dc3d0;
            FUN_80035974(param_1,(int)(*(float *)(param_1 + 8) * FLOAT_803dc3d8));
            *(short *)(param_1 + 4) =
                 (short)(int)((float)((double)CONCAT44(0x43300000,
                                                       (int)*(short *)(param_1 + 4) ^ 0x80000000) -
                                     DOUBLE_803e7020) + FLOAT_803dc3d4);
          }
        }
        else {
          *(float *)(puVar3 + 4) = fVar1;
          FUN_8002cbc4(param_1);
        }
      }
    }
    else {
      *(float *)(puVar3 + 0x10) = *(float *)(puVar3 + 0x10) - FLOAT_803db414;
      if (*(float *)(puVar3 + 0x10) <= fVar1) {
        FUN_8002cbc4(param_1);
      }
    }
  }
  else {
    FUN_8002cbc4(param_1);
  }
  return;
}

