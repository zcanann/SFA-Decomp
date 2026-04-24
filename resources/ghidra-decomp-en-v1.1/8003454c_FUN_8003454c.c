// Function: FUN_8003454c
// Entry: 8003454c
// Size: 1116 bytes

void FUN_8003454c(undefined4 param_1,undefined4 param_2,int *param_3)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int in_r10;
  int *piVar8;
  int iVar9;
  double dVar10;
  double dVar11;
  undefined8 uVar12;
  int local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar12 = FUN_80286840();
  iVar5 = (int)((ulonglong)uVar12 >> 0x20);
  iVar7 = (int)uVar12;
  iVar9 = *(int *)(iVar7 + 0x54);
  if ((((*(char *)(*(int *)(iVar5 + 0x54) + 0xaf) == '\0') && (*(char *)(iVar9 + 0xaf) == '\0')) &&
      (*(char *)(iVar9 + 0xae) == '\0')) && (*(char *)(*(int *)(iVar5 + 0x54) + 0xae) == '\0')) {
    piVar8 = *(int **)(*(int *)(iVar5 + 0x7c) + *(char *)(iVar5 + 0xad) * 4);
    bVar1 = *(byte *)(iVar9 + 0x62);
    if ((bVar1 & 1) == 0) {
      if ((bVar1 & 2) == 0) {
        if (((bVar1 & 0x20) != 0) && (in_r10 < 1)) {
          FUN_8003454c(iVar7,iVar5,param_3);
        }
      }
      else {
        local_60 = *(float *)(iVar7 + 0x18) - FLOAT_803dda58;
        local_5c = *(float *)(iVar7 + 0x1c);
        local_58 = *(float *)(iVar7 + 0x20) - FLOAT_803dda5c;
        uStack_2c = (int)*(short *)(iVar9 + 0x5a) ^ 0x80000000;
        local_30 = 0x43300000;
        uStack_24 = (int)*(short *)(iVar9 + 0x5e) ^ 0x80000000;
        local_28 = 0x43300000;
        uStack_1c = (int)*(short *)(iVar9 + 0x5c) ^ 0x80000000;
        local_20 = 0x43300000;
        local_3c = local_60;
        local_38 = local_5c;
        local_34 = local_58;
        iVar6 = FUN_80030780((double)(float)((double)CONCAT44(0x43300000,uStack_2c) -
                                            DOUBLE_803df5c0),
                             (double)(local_5c +
                                     (float)((double)CONCAT44(0x43300000,uStack_24) -
                                            DOUBLE_803df5c0)),
                             (double)(local_5c +
                                     (float)((double)CONCAT44(0x43300000,uStack_1c) -
                                            DOUBLE_803df5c0)),&local_60,piVar8[5],piVar8,param_3,
                             &local_68,&local_64);
        if (iVar6 != 0) {
          dVar11 = (double)((*(float *)(iVar7 + 0xa8) * *(float *)(iVar7 + 8)) /
                           (*(float *)(iVar5 + 0xa8) * *(float *)(iVar7 + 8)));
          uStack_1c = (int)*(short *)(iVar9 + 0x5a) ^ 0x80000000;
          local_20 = 0x43300000;
          dVar10 = (double)FLOAT_803df590;
          if ((dVar10 <= dVar11) && (dVar10 = dVar11, (double)FLOAT_803df598 < dVar11)) {
            dVar10 = (double)FLOAT_803df598;
          }
          FUN_80030fc0((double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803df5c0),
                       dVar10,(double)local_64,&local_3c,iVar7,(int)param_3,piVar8[5],*piVar8,
                       local_68,&local_48);
          fVar2 = FLOAT_803df5d8;
          if ((FLOAT_803df5d8 <= local_48) && (fVar2 = local_48, FLOAT_803df5dc < local_48)) {
            fVar2 = FLOAT_803df5dc;
          }
          fVar3 = FLOAT_803df5d8;
          if ((FLOAT_803df5d8 <= local_44) && (fVar3 = local_44, FLOAT_803df5dc < local_44)) {
            fVar3 = FLOAT_803df5dc;
          }
          fVar4 = FLOAT_803df5d8;
          if ((FLOAT_803df5d8 <= local_40) && (fVar4 = local_40, FLOAT_803df5dc < local_40)) {
            fVar4 = FLOAT_803df5dc;
          }
          local_48 = fVar2;
          local_44 = fVar3;
          local_40 = fVar4;
          FUN_80033a8c((double)fVar2,(double)fVar3,(double)fVar4,iVar5,iVar7,0);
        }
      }
    }
    else {
      local_54 = *(float *)(iVar7 + 0x18) - FLOAT_803dda58;
      local_50 = *(float *)(iVar7 + 0x1c);
      local_4c = *(float *)(iVar7 + 0x20) - FLOAT_803dda5c;
      uStack_2c = (int)*(short *)(iVar9 + 0x5a) ^ 0x80000000;
      local_30 = 0x43300000;
      local_3c = local_54;
      local_38 = local_50;
      local_34 = local_4c;
      iVar6 = FUN_80030be4(&local_54,piVar8[5],piVar8,param_3,&local_68,&local_64);
      if (iVar6 != 0) {
        dVar11 = (double)((*(float *)(iVar7 + 0xa8) * *(float *)(iVar7 + 8)) /
                         (*(float *)(iVar5 + 0xa8) * *(float *)(iVar5 + 8)));
        uStack_2c = (int)*(short *)(iVar9 + 0x5a) ^ 0x80000000;
        local_30 = 0x43300000;
        dVar10 = (double)FLOAT_803df590;
        if ((dVar10 <= dVar11) && (dVar10 = dVar11, (double)FLOAT_803df598 < dVar11)) {
          dVar10 = (double)FLOAT_803df598;
        }
        FUN_800314a0((double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df5c0),
                     dVar10,(double)local_64,&local_3c,iVar7,(int)param_3,piVar8[5],*piVar8,local_68
                     ,&local_48);
        fVar2 = FLOAT_803df5d8;
        if ((FLOAT_803df5d8 <= local_48) && (fVar2 = local_48, FLOAT_803df5dc < local_48)) {
          fVar2 = FLOAT_803df5dc;
        }
        fVar3 = FLOAT_803df5d8;
        if ((FLOAT_803df5d8 <= local_44) && (fVar3 = local_44, FLOAT_803df5dc < local_44)) {
          fVar3 = FLOAT_803df5dc;
        }
        fVar4 = FLOAT_803df5d8;
        if ((FLOAT_803df5d8 <= local_40) && (fVar4 = local_40, FLOAT_803df5dc < local_40)) {
          fVar4 = FLOAT_803df5dc;
        }
        local_48 = fVar2;
        local_44 = fVar3;
        local_40 = fVar4;
        FUN_80033a8c((double)fVar2,(double)fVar3,(double)fVar4,iVar5,iVar7,0);
      }
    }
  }
  FUN_8028688c();
  return;
}

