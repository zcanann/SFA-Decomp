// Function: FUN_80034454
// Entry: 80034454
// Size: 1116 bytes

void FUN_80034454(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int in_r10;
  undefined4 *puVar8;
  int iVar9;
  double dVar10;
  double dVar11;
  undefined8 uVar12;
  undefined4 local_68;
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
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  
  uVar12 = FUN_802860dc();
  iVar5 = (int)((ulonglong)uVar12 >> 0x20);
  iVar7 = (int)uVar12;
  iVar9 = *(int *)(iVar7 + 0x54);
  if ((((*(char *)(*(int *)(iVar5 + 0x54) + 0xaf) == '\0') && (*(char *)(iVar9 + 0xaf) == '\0')) &&
      (*(char *)(iVar9 + 0xae) == '\0')) && (*(char *)(*(int *)(iVar5 + 0x54) + 0xae) == '\0')) {
    puVar8 = *(undefined4 **)(*(int *)(iVar5 + 0x7c) + *(char *)(iVar5 + 0xad) * 4);
    bVar1 = *(byte *)(iVar9 + 0x62);
    if ((bVar1 & 1) == 0) {
      if ((bVar1 & 2) == 0) {
        if (((bVar1 & 0x20) != 0) && (in_r10 < 1)) {
          FUN_80034454(iVar7,iVar5);
        }
      }
      else {
        local_60 = *(float *)(iVar7 + 0x18) - FLOAT_803dcdd8;
        local_5c = *(float *)(iVar7 + 0x1c);
        local_58 = *(float *)(iVar7 + 0x20) - FLOAT_803dcddc;
        uStack44 = (int)*(short *)(iVar9 + 0x5a) ^ 0x80000000;
        local_30 = 0x43300000;
        uStack36 = (int)*(short *)(iVar9 + 0x5e) ^ 0x80000000;
        local_28 = 0x43300000;
        uStack28 = (int)*(short *)(iVar9 + 0x5c) ^ 0x80000000;
        local_20 = 0x43300000;
        local_3c = local_60;
        local_38 = local_5c;
        local_34 = local_58;
        iVar6 = FUN_80030688((double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803de940
                                            ),
                             (double)(local_5c +
                                     (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803de940
                                            )),
                             (double)(local_5c +
                                     (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803de940
                                            )),&local_60,puVar8[5],puVar8,param_3,&local_68,
                             &local_64);
        if (iVar6 != 0) {
          dVar11 = (double)((*(float *)(iVar7 + 0xa8) * *(float *)(iVar7 + 8)) /
                           (*(float *)(iVar5 + 0xa8) * *(float *)(iVar7 + 8)));
          uStack28 = (int)*(short *)(iVar9 + 0x5a) ^ 0x80000000;
          local_20 = 0x43300000;
          dVar10 = (double)FLOAT_803de910;
          if ((dVar10 <= dVar11) && (dVar10 = dVar11, (double)FLOAT_803de918 < dVar11)) {
            dVar10 = (double)FLOAT_803de918;
          }
          FUN_80030ec8((double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803de940),
                       dVar10,(double)local_64,&local_3c,iVar7,param_3,puVar8[5],*puVar8,local_68,
                       &local_48);
          fVar2 = FLOAT_803de958;
          if ((FLOAT_803de958 <= local_48) && (fVar2 = local_48, FLOAT_803de95c < local_48)) {
            fVar2 = FLOAT_803de95c;
          }
          fVar3 = FLOAT_803de958;
          if ((FLOAT_803de958 <= local_44) && (fVar3 = local_44, FLOAT_803de95c < local_44)) {
            fVar3 = FLOAT_803de95c;
          }
          fVar4 = FLOAT_803de958;
          if ((FLOAT_803de958 <= local_40) && (fVar4 = local_40, FLOAT_803de95c < local_40)) {
            fVar4 = FLOAT_803de95c;
          }
          local_48 = fVar2;
          local_44 = fVar3;
          local_40 = fVar4;
          FUN_80033994((double)fVar2,(double)fVar3,(double)fVar4,iVar5,iVar7,0);
        }
      }
    }
    else {
      local_54 = *(float *)(iVar7 + 0x18) - FLOAT_803dcdd8;
      local_50 = *(float *)(iVar7 + 0x1c);
      local_4c = *(float *)(iVar7 + 0x20) - FLOAT_803dcddc;
      uStack44 = (int)*(short *)(iVar9 + 0x5a) ^ 0x80000000;
      local_30 = 0x43300000;
      local_3c = local_54;
      local_38 = local_50;
      local_34 = local_4c;
      iVar6 = FUN_80030aec((double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803de940),
                           &local_54,puVar8[5],puVar8,param_3,&local_68,&local_64);
      if (iVar6 != 0) {
        dVar11 = (double)((*(float *)(iVar7 + 0xa8) * *(float *)(iVar7 + 8)) /
                         (*(float *)(iVar5 + 0xa8) * *(float *)(iVar5 + 8)));
        uStack44 = (int)*(short *)(iVar9 + 0x5a) ^ 0x80000000;
        local_30 = 0x43300000;
        dVar10 = (double)FLOAT_803de910;
        if ((dVar10 <= dVar11) && (dVar10 = dVar11, (double)FLOAT_803de918 < dVar11)) {
          dVar10 = (double)FLOAT_803de918;
        }
        FUN_800313a8((double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803de940),dVar10
                     ,(double)local_64,&local_3c,iVar7,param_3,puVar8[5],*puVar8,local_68,&local_48)
        ;
        fVar2 = FLOAT_803de958;
        if ((FLOAT_803de958 <= local_48) && (fVar2 = local_48, FLOAT_803de95c < local_48)) {
          fVar2 = FLOAT_803de95c;
        }
        fVar3 = FLOAT_803de958;
        if ((FLOAT_803de958 <= local_44) && (fVar3 = local_44, FLOAT_803de95c < local_44)) {
          fVar3 = FLOAT_803de95c;
        }
        fVar4 = FLOAT_803de958;
        if ((FLOAT_803de958 <= local_40) && (fVar4 = local_40, FLOAT_803de95c < local_40)) {
          fVar4 = FLOAT_803de95c;
        }
        local_48 = fVar2;
        local_44 = fVar3;
        local_40 = fVar4;
        FUN_80033994((double)fVar2,(double)fVar3,(double)fVar4,iVar5,iVar7,0);
      }
    }
  }
  FUN_80286128();
  return;
}

