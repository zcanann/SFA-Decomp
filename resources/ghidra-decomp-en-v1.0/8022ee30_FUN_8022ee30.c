// Function: FUN_8022ee30
// Entry: 8022ee30
// Size: 696 bytes

void FUN_8022ee30(int param_1)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  float *pfVar4;
  
  pfVar4 = *(float **)(param_1 + 0xb8);
  iVar2 = FUN_8022d768();
  fVar1 = FLOAT_803e7044;
  if ((*(ushort *)(iVar2 + 0xb0) & 0x1000) == 0) {
    if (pfVar4[2] <= FLOAT_803e7044) {
      if (FLOAT_803e7044 < *pfVar4) {
        *pfVar4 = *pfVar4 - FLOAT_803db414;
        if (*pfVar4 <= fVar1) {
          pfVar4 = *(float **)(param_1 + 0xb8);
          FUN_8022d768();
          FUN_8022d4f8();
          FUN_8000bb18(param_1,0x2a5);
          pfVar4[2] = FLOAT_803e7040;
          *pfVar4 = FLOAT_803e7044;
          *(undefined *)(param_1 + 0x36) = 0;
          *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
               *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfdff;
          FUN_8009ab70((double)FLOAT_803e7048,param_1,1,0,1,1,0,1,0);
          FUN_80035974(param_1,0x280);
          FUN_80035df4(param_1,5,5,0);
          fVar1 = FLOAT_803e7044;
          *(float *)(param_1 + 0x24) = FLOAT_803e7044;
          *(float *)(param_1 + 0x28) = fVar1;
          *(float *)(param_1 + 0x2c) = fVar1;
        }
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x79e,0,1,0xffffffff,param_1 + 0x24);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x79e,0,1,0xffffffff,param_1 + 0x24);
        FUN_80035df4(param_1,0xf,0,0);
        if (((*(int *)(*(int *)(param_1 + 0x54) + 0x50) != 0) ||
            (*(char *)(*(int *)(param_1 + 0x54) + 0xad) != '\0')) ||
           (uVar3 = FUN_80014e70(0), (uVar3 & 0x200) != 0)) {
          pfVar4 = *(float **)(param_1 + 0xb8);
          FUN_8022d768();
          FUN_8022d4f8();
          FUN_8000bb18(param_1,0x2a5);
          pfVar4[2] = FLOAT_803e7040;
          *pfVar4 = FLOAT_803e7044;
          *(undefined *)(param_1 + 0x36) = 0;
          *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
               *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfdff;
          FUN_8009ab70((double)FLOAT_803e7048,param_1,1,0,1,1,0,1,0);
          FUN_80035974(param_1,0x280);
          FUN_80035df4(param_1,5,5,0);
          fVar1 = FLOAT_803e7044;
          *(float *)(param_1 + 0x24) = FLOAT_803e7044;
          *(float *)(param_1 + 0x28) = fVar1;
          *(float *)(param_1 + 0x2c) = fVar1;
        }
        FUN_8002b95c((double)(*(float *)(param_1 + 0x24) * FLOAT_803db414),
                     (double)(*(float *)(param_1 + 0x28) * FLOAT_803db414),
                     (double)(*(float *)(param_1 + 0x2c) * FLOAT_803db414),param_1);
      }
    }
    else {
      pfVar4[2] = pfVar4[2] - FLOAT_803db414;
      if (pfVar4[2] <= fVar1) {
        FUN_8002cbc4(param_1);
      }
    }
  }
  else {
    FUN_8022d4f8();
    FUN_8002cbc4(param_1);
  }
  return;
}

