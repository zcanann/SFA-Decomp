// Function: FUN_8022f4f4
// Entry: 8022f4f4
// Size: 696 bytes

void FUN_8022f4f4(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  float *pfVar4;
  undefined8 uVar5;
  double dVar6;
  double dVar7;
  
  pfVar4 = *(float **)(param_9 + 0xb8);
  iVar2 = FUN_8022de2c();
  if ((*(ushort *)(iVar2 + 0xb0) & 0x1000) == 0) {
    dVar6 = (double)pfVar4[2];
    dVar7 = (double)FLOAT_803e7cdc;
    if (dVar6 <= dVar7) {
      if (dVar7 < (double)*pfVar4) {
        *pfVar4 = (float)((double)*pfVar4 - (double)FLOAT_803dc074);
        if ((double)*pfVar4 <= dVar7) {
          pfVar4 = *(float **)(param_9 + 0xb8);
          iVar2 = FUN_8022de2c();
          FUN_8022dbbc(iVar2);
          FUN_8000bb38(param_9,0x2a5);
          pfVar4[2] = FLOAT_803e7cd8;
          *pfVar4 = FLOAT_803e7cdc;
          *(undefined *)(param_9 + 0x36) = 0;
          *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) =
               *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) & 0xfdff;
          FUN_8009adfc((double)FLOAT_803e7ce0,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,
                       param_9,1,0,1,1,0,1,0);
          FUN_80035a6c(param_9,0x280);
          FUN_80035eec(param_9,5,5,0);
          fVar1 = FLOAT_803e7cdc;
          *(float *)(param_9 + 0x24) = FLOAT_803e7cdc;
          *(float *)(param_9 + 0x28) = fVar1;
          *(float *)(param_9 + 0x2c) = fVar1;
        }
        (**(code **)(*DAT_803dd708 + 8))(param_9,0x79e,0,1,0xffffffff,param_9 + 0x24);
        (**(code **)(*DAT_803dd708 + 8))(param_9,0x79e,0,1,0xffffffff,param_9 + 0x24);
        FUN_80035eec(param_9,0xf,0,0);
        if (((*(int *)(*(int *)(param_9 + 0x54) + 0x50) != 0) ||
            (*(char *)(*(int *)(param_9 + 0x54) + 0xad) != '\0')) ||
           (uVar3 = FUN_80014e9c(0), (uVar3 & 0x200) != 0)) {
          pfVar4 = *(float **)(param_9 + 0xb8);
          iVar2 = FUN_8022de2c();
          FUN_8022dbbc(iVar2);
          FUN_8000bb38(param_9,0x2a5);
          pfVar4[2] = FLOAT_803e7cd8;
          *pfVar4 = FLOAT_803e7cdc;
          *(undefined *)(param_9 + 0x36) = 0;
          *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) =
               *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) & 0xfdff;
          FUN_8009adfc((double)FLOAT_803e7ce0,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,
                       param_9,1,0,1,1,0,1,0);
          FUN_80035a6c(param_9,0x280);
          FUN_80035eec(param_9,5,5,0);
          fVar1 = FLOAT_803e7cdc;
          *(float *)(param_9 + 0x24) = FLOAT_803e7cdc;
          *(float *)(param_9 + 0x28) = fVar1;
          *(float *)(param_9 + 0x2c) = fVar1;
        }
        FUN_8002ba34((double)(*(float *)(param_9 + 0x24) * FLOAT_803dc074),
                     (double)(*(float *)(param_9 + 0x28) * FLOAT_803dc074),
                     (double)(*(float *)(param_9 + 0x2c) * FLOAT_803dc074),param_9);
      }
    }
    else {
      pfVar4[2] = (float)(dVar6 - (double)FLOAT_803dc074);
      if ((double)pfVar4[2] <= dVar7) {
        FUN_8002cc9c(dVar6,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
      }
    }
  }
  else {
    uVar5 = FUN_8022dbbc(iVar2);
    FUN_8002cc9c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  return;
}

