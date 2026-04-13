// Function: FUN_801ef65c
// Entry: 801ef65c
// Size: 652 bytes

void FUN_801ef65c(ushort *param_1,undefined4 param_2,int param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  char cVar1;
  double dVar2;
  float fVar3;
  char cVar5;
  undefined4 *puVar4;
  int iVar6;
  int iVar7;
  int local_38 [2];
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  longlong local_20;
  
  iVar7 = *(int *)(param_1 + 0x5c);
  if ((*(char *)(iVar7 + 0x6e) == '\0') && (*(char *)(param_1 + 0x56) != '\v')) {
    FUN_8011f6d0(6);
    cVar5 = FUN_80014cec(0);
    *(int *)(iVar7 + 0x70) = (int)cVar5;
    cVar5 = FUN_80014c98(0);
    *(int *)(iVar7 + 0x74) = (int)cVar5;
    if (*(int *)(iVar7 + 0x10) == 0) {
      puVar4 = FUN_80037048(3,local_38);
      for (iVar6 = 0; iVar6 < local_38[0]; iVar6 = iVar6 + 1) {
        param_3 = puVar4[iVar6];
        if (*(short *)(param_3 + 0x46) == 0x8e) {
          *(int *)(iVar7 + 0x10) = param_3;
          iVar6 = local_38[0];
        }
      }
    }
    param_1[0x7a] = 0;
    param_1[0x7b] = 0;
    cVar5 = *(char *)(iVar7 + 0x65);
    *(byte *)(iVar7 + 100) = *(char *)(iVar7 + 100) - DAT_803dc070;
    if (*(char *)(iVar7 + 100) < '\0') {
      *(undefined *)(iVar7 + 100) = 0;
    }
    cVar1 = *(char *)(iVar7 + 0x65);
    if (cVar1 == '\x01') {
      FUN_801ee9ec((short *)param_1,iVar7,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    else if (cVar1 < '\x01') {
      if (-1 < cVar1) {
        FUN_801eeca0(param_1,iVar7,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_801ef188((uint)param_1,iVar7);
      }
    }
    else if (cVar1 < '\x04') {
      param_1[0x7a] = 0;
      param_1[0x7b] = 1;
    }
    fVar3 = FLOAT_803e6954;
    dVar2 = DOUBLE_803e6938;
    uStack_2c = (int)(short)param_1[2] ^ 0x80000000;
    local_30 = 0x43300000;
    *(float *)(iVar7 + 0x5c) =
         *(float *)(iVar7 + 0x5c) +
         ((float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e6938) * FLOAT_803dc074) /
         FLOAT_803e6954;
    uStack_24 = (int)(short)param_1[1] ^ 0x80000000;
    local_28 = 0x43300000;
    *(float *)(iVar7 + 0x58) =
         *(float *)(iVar7 + 0x58) +
         ((float)((double)CONCAT44(0x43300000,uStack_24) - dVar2) * FLOAT_803dc074) / fVar3;
    fVar3 = FLOAT_803e6958;
    *(float *)(iVar7 + 0x5c) =
         -(FLOAT_803dc074 * *(float *)(iVar7 + 0x5c) * FLOAT_803e6958 - *(float *)(iVar7 + 0x5c));
    *(float *)(iVar7 + 0x58) =
         -(FLOAT_803dc074 * *(float *)(iVar7 + 0x58) * fVar3 - *(float *)(iVar7 + 0x58));
    fVar3 = FLOAT_803e6950;
    iVar6 = (int)(FLOAT_803e6950 * *(float *)(iVar7 + 0x58));
    local_20 = (longlong)iVar6;
    param_1[1] = param_1[1] - (short)iVar6;
    *(float *)(param_1 + 8) = fVar3 * *(float *)(iVar7 + 0x58) + *(float *)(iVar7 + 0x50);
    *(float *)(param_1 + 10) = fVar3 * *(float *)(iVar7 + 0x5c) + *(float *)(iVar7 + 0x54);
    *(ushort *)(iVar7 + 0x6c) = *(short *)(iVar7 + 0x6c) + (ushort)DAT_803dc070;
    if (*(char *)(iVar7 + 0x65) != cVar5) {
      *(undefined2 *)(iVar7 + 0x6c) = 0;
    }
    FUN_801ee880(param_1,iVar7);
  }
  else {
    param_1[3] = param_1[3] | 0x4000;
  }
  return;
}

