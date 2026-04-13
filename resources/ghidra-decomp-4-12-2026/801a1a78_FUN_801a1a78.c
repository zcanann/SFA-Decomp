// Function: FUN_801a1a78
// Entry: 801a1a78
// Size: 976 bytes

void FUN_801a1a78(uint param_1)

{
  float fVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  float local_18;
  int local_14 [3];
  
  iVar5 = *(int *)(param_1 + 0xb8);
  if ((*(byte *)(iVar5 + 0x4a) >> 5 & 1) == 0) {
    iVar3 = FUN_8005b478((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
    if (iVar3 == -1) {
      if ((*(byte *)(iVar5 + 0x49) & 2) != 0) {
        *(undefined *)(iVar5 + 0x16) = 4;
      }
    }
    else {
      if ((*(char *)(iVar5 + 0x16) == '\0') &&
         (((*(byte *)(iVar5 + 0x49) & 2) != 0 || (FLOAT_803e4fa4 < *(float *)(iVar5 + 0x24))))) {
        FUN_80035eec(param_1,0xe,1,0);
        FUN_80036018(param_1);
      }
      if (-1 < *(char *)(iVar5 + 0x4a)) {
        *(float *)(iVar5 + 0x24) = -(FLOAT_803e4fa8 * FLOAT_803dc074 - *(float *)(iVar5 + 0x24));
      }
      fVar1 = *(float *)(iVar5 + 0x20);
      fVar2 = FLOAT_803e4fac;
      if ((FLOAT_803e4fac <= fVar1) && (fVar2 = fVar1, FLOAT_803e4fb0 < fVar1)) {
        fVar2 = FLOAT_803e4fb0;
      }
      *(float *)(iVar5 + 0x20) = fVar2;
      fVar1 = *(float *)(iVar5 + 0x24);
      fVar2 = FLOAT_803e4fac;
      if ((FLOAT_803e4fac <= fVar1) && (fVar2 = fVar1, FLOAT_803e4fb0 < fVar1)) {
        fVar2 = FLOAT_803e4fb0;
      }
      *(float *)(iVar5 + 0x24) = fVar2;
      fVar1 = *(float *)(iVar5 + 0x28);
      fVar2 = FLOAT_803e4fac;
      if ((FLOAT_803e4fac <= fVar1) && (fVar2 = fVar1, FLOAT_803e4fb0 < fVar1)) {
        fVar2 = FLOAT_803e4fb0;
      }
      *(float *)(iVar5 + 0x28) = fVar2;
      *(undefined4 *)(param_1 + 0x24) = *(undefined4 *)(iVar5 + 0x20);
      *(undefined4 *)(param_1 + 0x28) = *(undefined4 *)(iVar5 + 0x24);
      *(undefined4 *)(param_1 + 0x2c) = *(undefined4 *)(iVar5 + 0x28);
      FUN_8002ba34((double)(*(float *)(param_1 + 0x24) * FLOAT_803dc074),
                   (double)(*(float *)(param_1 + 0x28) * FLOAT_803dc074),
                   (double)(*(float *)(param_1 + 0x2c) * FLOAT_803dc074),param_1);
      *(byte *)(iVar5 + 0x4a) = *(byte *)(iVar5 + 0x4a) & 0xef;
      if ((*(byte *)(iVar5 + 0x49) & 2) == 0) {
        dVar6 = (double)*(float *)(param_1 + 0x84);
        dVar7 = (double)*(float *)(param_1 + 0x10);
        if (dVar6 < dVar7) {
          dVar7 = (double)(float)(dVar7 + (double)FLOAT_803e4fb0);
        }
        else {
          dVar6 = (double)(float)(dVar6 + (double)FLOAT_803e4fb0);
        }
        iVar3 = FUN_80062edc((double)*(float *)(param_1 + 0xc),dVar6,
                             (double)*(float *)(param_1 + 0x14),dVar7,param_1,&local_18,local_14);
        if (iVar3 != 0) {
          if (iVar3 == 2) {
            *(undefined *)(iVar5 + 0x16) = 4;
          }
          else {
            if (*(char *)(iVar5 + 0x58) == '\0') {
              if ((*(byte *)(iVar5 + 0x4a) >> 3 & 1) == 0) {
                *(byte *)(iVar5 + 0x4a) = *(byte *)(iVar5 + 0x4a) & 0xf7 | 8;
              }
              else {
                FUN_8000bb38(param_1,0xd2);
              }
            }
            *(byte *)(iVar5 + 0x4a) = *(byte *)(iVar5 + 0x4a) & 0xef | 0x10;
            *(float *)(param_1 + 0x10) = local_18;
          }
        }
      }
      fVar1 = FLOAT_803e4f58;
      if ((*(byte *)(iVar5 + 0x4a) >> 4 & 1) == 0) {
        if (*(float *)(iVar5 + 0x24) < FLOAT_803e4fb8) {
          FUN_801a14d4(param_1,(int)*(short *)(iVar5 + 0x44),*(short *)(iVar5 + 0x46));
        }
        if ((((*(byte *)(iVar5 + 0x4a) >> 5 & 1) == 0) && (-1 < (char)*(byte *)(iVar5 + 0x4a))) &&
           (*(float *)(iVar5 + 0x38) = *(float *)(iVar5 + 0x38) + *(float *)(param_1 + 0x28),
           *(float *)(iVar5 + 0x38) < -FLOAT_803dcaf0)) {
          *(undefined *)(iVar5 + 0x16) = 4;
        }
      }
      else {
        *(float *)(param_1 + 0x24) = FLOAT_803e4f58;
        *(float *)(param_1 + 0x28) = fVar1;
        *(float *)(param_1 + 0x2c) = fVar1;
        *(float *)(iVar5 + 0x20) = fVar1;
        *(float *)(iVar5 + 0x24) = fVar1;
        *(float *)(iVar5 + 0x28) = fVar1;
        if (local_14[0] != 0) {
          FUN_80036800(local_14[0],param_1);
          uVar4 = *(uint *)(*(int *)(local_14[0] + 0x50) + 0x44);
          if (((uVar4 & 0x40) == 0) || ((uVar4 & 0x8000) != 0)) {
            if (*(float *)(iVar5 + 0x38) < FLOAT_803e4fb4) {
              *(undefined *)(iVar5 + 0x16) = 4;
            }
          }
          else {
            *(int *)(iVar5 + 0xc) = local_14[0];
          }
        }
        if (*(char *)(iVar5 + 0x4a) < '\0') {
          FUN_801a1380(param_1,'\0');
        }
        *(float *)(iVar5 + 0x38) = FLOAT_803e4f58;
      }
      if ((*(byte *)(iVar5 + 0x4a) >> 4 & 1) == 0) {
        iVar3 = *(char *)(iVar5 + 0x58) + -1;
        if (iVar3 < 0) {
          iVar3 = 0;
        }
        *(char *)(iVar5 + 0x58) = (char)iVar3;
      }
      else {
        *(undefined *)(iVar5 + 0x58) = 3;
      }
    }
  }
  return;
}

