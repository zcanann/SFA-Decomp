// Function: FUN_801a14f4
// Entry: 801a14f4
// Size: 928 bytes

void FUN_801a14f4(int param_1)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  double dVar7;
  double dVar8;
  undefined4 local_18;
  int local_14 [3];
  
  iVar6 = *(int *)(param_1 + 0xb8);
  if ((*(byte *)(iVar6 + 0x4a) >> 5 & 1) == 0) {
    iVar4 = FUN_8005b2fc((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                         (double)*(float *)(param_1 + 0x14));
    if (iVar4 == -1) {
      if ((*(byte *)(iVar6 + 0x49) & 2) != 0) {
        *(undefined *)(iVar6 + 0x16) = 4;
      }
    }
    else {
      if ((*(char *)(iVar6 + 0x16) == '\0') &&
         (((*(byte *)(iVar6 + 0x49) & 2) != 0 || (FLOAT_803e430c < *(float *)(iVar6 + 0x24))))) {
        FUN_80035df4(param_1,0xe,1,0);
        FUN_80035f20(param_1);
      }
      if (-1 < *(char *)(iVar6 + 0x4a)) {
        *(float *)(iVar6 + 0x24) = -(FLOAT_803e4310 * FLOAT_803db414 - *(float *)(iVar6 + 0x24));
      }
      fVar2 = *(float *)(iVar6 + 0x20);
      fVar3 = FLOAT_803e4314;
      if ((FLOAT_803e4314 <= fVar2) && (fVar3 = fVar2, FLOAT_803e4318 < fVar2)) {
        fVar3 = FLOAT_803e4318;
      }
      *(float *)(iVar6 + 0x20) = fVar3;
      fVar2 = *(float *)(iVar6 + 0x24);
      fVar3 = FLOAT_803e4314;
      if ((FLOAT_803e4314 <= fVar2) && (fVar3 = fVar2, FLOAT_803e4318 < fVar2)) {
        fVar3 = FLOAT_803e4318;
      }
      *(float *)(iVar6 + 0x24) = fVar3;
      fVar2 = *(float *)(iVar6 + 0x28);
      fVar3 = FLOAT_803e4314;
      if ((FLOAT_803e4314 <= fVar2) && (fVar3 = fVar2, FLOAT_803e4318 < fVar2)) {
        fVar3 = FLOAT_803e4318;
      }
      *(float *)(iVar6 + 0x28) = fVar3;
      *(undefined4 *)(param_1 + 0x24) = *(undefined4 *)(iVar6 + 0x20);
      *(undefined4 *)(param_1 + 0x28) = *(undefined4 *)(iVar6 + 0x24);
      *(undefined4 *)(param_1 + 0x2c) = *(undefined4 *)(iVar6 + 0x28);
      FUN_8002b95c((double)(*(float *)(param_1 + 0x24) * FLOAT_803db414),
                   (double)(*(float *)(param_1 + 0x28) * FLOAT_803db414),
                   (double)(*(float *)(param_1 + 0x2c) * FLOAT_803db414),param_1);
      *(byte *)(iVar6 + 0x4a) = *(byte *)(iVar6 + 0x4a) & 0xef;
      if ((*(byte *)(iVar6 + 0x49) & 2) == 0) {
        dVar7 = (double)*(float *)(param_1 + 0x84);
        dVar8 = (double)*(float *)(param_1 + 0x10);
        if (dVar7 < dVar8) {
          dVar8 = (double)(float)(dVar8 + (double)FLOAT_803e4318);
        }
        else {
          dVar7 = (double)(float)(dVar7 + (double)FLOAT_803e4318);
        }
        iVar4 = FUN_80062d60((double)*(float *)(param_1 + 0xc),dVar7,
                             (double)*(float *)(param_1 + 0x14),dVar8,param_1,&local_18,local_14);
        if (iVar4 != 0) {
          if (iVar4 == 2) {
            *(undefined *)(iVar6 + 0x16) = 4;
          }
          else {
            bVar1 = *(byte *)(iVar6 + 0x4a);
            if ((bVar1 >> 3 & 1) == 0) {
              if ((bVar1 >> 2 & 1) == 0) {
                *(byte *)(iVar6 + 0x4a) = bVar1 & 0xfb | 4;
              }
              else {
                FUN_8000bb18(param_1,0xd2);
              }
            }
            *(byte *)(iVar6 + 0x4a) = *(byte *)(iVar6 + 0x4a) & 0xef | 0x10;
            *(undefined4 *)(param_1 + 0x10) = local_18;
          }
        }
      }
      fVar2 = FLOAT_803e42c0;
      if ((*(byte *)(iVar6 + 0x4a) >> 4 & 1) == 0) {
        if (*(float *)(iVar6 + 0x24) < FLOAT_803e4320) {
          FUN_801a0f58(param_1,(int)*(short *)(iVar6 + 0x44),(int)*(short *)(iVar6 + 0x46));
        }
        if ((((*(byte *)(iVar6 + 0x4a) >> 5 & 1) == 0) && (-1 < (char)*(byte *)(iVar6 + 0x4a))) &&
           (*(float *)(iVar6 + 0x38) = *(float *)(iVar6 + 0x38) + *(float *)(param_1 + 0x28),
           *(float *)(iVar6 + 0x38) < -FLOAT_803dbe88)) {
          *(undefined *)(iVar6 + 0x16) = 4;
        }
      }
      else {
        *(float *)(param_1 + 0x24) = FLOAT_803e42c0;
        *(float *)(param_1 + 0x28) = fVar2;
        *(float *)(param_1 + 0x2c) = fVar2;
        *(float *)(iVar6 + 0x20) = fVar2;
        *(float *)(iVar6 + 0x24) = fVar2;
        *(float *)(iVar6 + 0x28) = fVar2;
        if (local_14[0] != 0) {
          FUN_80036708(local_14[0],param_1);
          uVar5 = *(uint *)(*(int *)(local_14[0] + 0x50) + 0x44);
          if (((uVar5 & 0x40) == 0) || ((uVar5 & 0x8000) != 0)) {
            if (*(float *)(iVar6 + 0x38) < FLOAT_803e431c) {
              *(undefined *)(iVar6 + 0x16) = 4;
            }
          }
          else {
            *(int *)(iVar6 + 0xc) = local_14[0];
          }
        }
        if (*(char *)(iVar6 + 0x4a) < '\0') {
          FUN_801a0e04(param_1,0);
        }
        *(float *)(iVar6 + 0x38) = FLOAT_803e42c0;
      }
      *(byte *)(iVar6 + 0x4a) =
           (byte)((*(byte *)(iVar6 + 0x4a) >> 4 & 1) << 3) | *(byte *)(iVar6 + 0x4a) & 0xf7;
    }
  }
  return;
}

