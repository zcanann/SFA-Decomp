// Function: FUN_802994d0
// Entry: 802994d0
// Size: 1760 bytes

/* WARNING: Removing unreachable block (ram,0x80299b88) */

undefined4 FUN_802994d0(double param_1,int param_2,uint *param_3)

{
  float fVar1;
  short sVar4;
  int iVar2;
  undefined4 uVar3;
  ushort uVar5;
  int iVar6;
  undefined4 uVar7;
  double dVar8;
  undefined8 in_f31;
  short local_b0 [2];
  undefined2 local_ac;
  undefined local_aa;
  undefined local_a9;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  undefined auStack144 [60];
  float local_54;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar6 = *(int *)(param_2 + 0xb8);
  if (*(char *)((int)param_3 + 0x27a) != '\0') {
    FUN_80035e8c();
  }
  sVar4 = FUN_8011f3a8(local_b0);
  if ((sVar4 == 1) && (local_b0[0] == 0x957)) {
    uVar5 = 0x900;
  }
  else {
    uVar5 = 0x100;
  }
  *param_3 = *param_3 | 0x200000;
  fVar1 = FLOAT_803e7ea4;
  sVar4 = *(short *)(param_2 + 0xa0);
  if (sVar4 == 0x7f) {
    *(float *)(param_2 + 0x28) =
         (float)((double)FLOAT_803e7efc * param_1 + (double)*(float *)(param_2 + 0x28));
    if (FLOAT_803e7f10 < *(float *)(param_2 + 0x28)) {
      *(float *)(param_2 + 0x28) = FLOAT_803e7f10;
    }
    if (FLOAT_803de490 < *(float *)(param_2 + 0x10)) {
      FUN_80030334((double)FLOAT_803e7ea4,param_2,0x80,0);
      param_3[0xa8] = (uint)FLOAT_803e7f84;
    }
  }
  else if (sVar4 < 0x7f) {
    if (sVar4 == 0x43) {
      if ((*(ushort *)(iVar6 + 0x6e0) & uVar5) == 0) {
        if ((*(ushort *)(iVar6 + 0x6e2) & 0x200) != 0) {
          FUN_80014b3c(0,0x200);
          FUN_80030334((double)FLOAT_803e7ea4,param_2,0x44,0);
          param_3[0xa8] = (uint)FLOAT_803e7f80;
        }
      }
      else {
        FUN_8000bb18(param_2,0x216);
        FUN_80030334((double)FLOAT_803e7ea4,param_2,0x87,0);
        param_3[0xa8] = (uint)FLOAT_803e7ef8;
      }
    }
    else if (sVar4 < 0x43) {
      if (sVar4 == 4) {
        if ((DAT_803de48d == '\0') && (FLOAT_803e7f74 < *(float *)(param_2 + 0x98))) {
          FUN_8000bb18(param_2,0x215);
          DAT_803de48d = '\x01';
        }
        if (*(char *)((int)param_3 + 0x346) != '\0') {
          if ((*(ushort *)(iVar6 + 0x6e0) & uVar5) == 0) {
            FUN_80030334((double)FLOAT_803e7ea4,param_2,0x43,0);
            param_3[0xa8] = (uint)FLOAT_803e7f78;
          }
          else {
            FUN_8000bb18(param_2,0x216);
            FUN_80030334((double)FLOAT_803e7ea4,param_2,0x87,0);
            param_3[0xa8] = (uint)FLOAT_803e7ef8;
          }
        }
      }
      else {
LAB_80299964:
        param_3[0xa5] = (uint)FLOAT_803e7ea4;
        param_3[0xa1] = (uint)fVar1;
        param_3[0xa0] = (uint)fVar1;
        *(float *)(param_2 + 0x24) = fVar1;
        *(float *)(param_2 + 0x28) = fVar1;
        *(float *)(param_2 + 0x2c) = fVar1;
        FUN_80030334(param_2,4,0);
        param_3[0xa8] = (uint)FLOAT_803e7f84;
        FLOAT_803de494 = *(float *)(param_2 + 0x10);
        *(undefined2 *)(iVar6 + 0x478) = *DAT_803de434;
        *(undefined2 *)(iVar6 + 0x484) = *(undefined2 *)(iVar6 + 0x478);
        FUN_80189f5c(DAT_803de434,param_2 + 0xc,param_2 + 0x14);
        FUN_802ab5a4(param_2,iVar6,7);
        param_3[1] = param_3[1] | 0x8000000;
        local_9c = *(float *)(param_2 + 0xc);
        local_98 = FLOAT_803e7ed8 + *(float *)(param_2 + 0x10);
        local_94 = *(float *)(param_2 + 0x14);
        uStack52 = (int)*(short *)(iVar6 + 0x478) ^ 0x80000000;
        local_38 = 0x43300000;
        dVar8 = (double)FUN_80293e80((double)((FLOAT_803e7f94 *
                                              (float)((double)CONCAT44(0x43300000,uStack52) -
                                                     DOUBLE_803e7ec0)) / FLOAT_803e7f98));
        local_a8 = -(float)((double)FLOAT_803e7f5c * dVar8 - (double)local_9c);
        local_a4 = local_98;
        uStack44 = (int)*(short *)(iVar6 + 0x478) ^ 0x80000000;
        local_30 = 0x43300000;
        dVar8 = (double)FUN_80294204((double)((FLOAT_803e7f94 *
                                              (float)((double)CONCAT44(0x43300000,uStack44) -
                                                     DOUBLE_803e7ec0)) / FLOAT_803e7f98));
        local_a0 = -(float)((double)FLOAT_803e7f5c * dVar8 - (double)local_94);
        iVar2 = FUN_800640cc((double)FLOAT_803e7ea4,&local_9c,&local_a8,3,auStack144,param_2,1,1,
                             0xff,0);
        if (iVar2 == 0) {
          FLOAT_803de490 = FLOAT_803e7f5c + *(float *)(param_2 + 0x10);
        }
        else {
          FLOAT_803de490 = local_54 - FLOAT_803e7f30;
        }
        DAT_803de48d = '\0';
        if ((DAT_803de44c != 0) && ((*(byte *)(iVar6 + 0x3f4) >> 6 & 1) != 0)) {
          *(undefined *)(iVar6 + 0x8b4) = 4;
          *(byte *)(iVar6 + 0x3f4) = *(byte *)(iVar6 + 0x3f4) & 0xf7 | 8;
        }
        *(float *)(iVar6 + 0x7d4) = FLOAT_803e7ea4;
        if ((*(char *)(iVar6 + 0x8c8) != 'H') && (*(char *)(iVar6 + 0x8c8) != 'G')) {
          local_ac = 0;
          local_aa = 0;
          local_a9 = 1;
          (**(code **)(*DAT_803dca50 + 0x1c))(0x43,1,0,4,&local_ac,0,0xff);
        }
      }
    }
    else {
      if (0x44 < sVar4) goto LAB_80299964;
      if (*(char *)((int)param_3 + 0x346) != '\0') {
        *(uint *)(iVar6 + 0x360) = *(uint *)(iVar6 + 0x360) | 0x800000;
        *(float *)(param_2 + 0x28) = FLOAT_803e7ea4;
        *(undefined2 *)(iVar6 + 0x80a) = 0xffff;
        param_3[0xc2] = (uint)FUN_802a514c;
        uVar3 = 2;
        goto LAB_80299b88;
      }
    }
  }
  else if (sVar4 == 0x87) {
    if ((*(ushort *)(iVar6 + 0x6e0) & uVar5) != 0) {
      uStack52 = (int)*(short *)(*(int *)(*(int *)(param_2 + 0xb8) + 0x35c) + 4) ^ 0x80000000;
      local_38 = 0x43300000;
      if (*(float *)(iVar6 + 0x7d4) <=
          (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e7ec0)) {
        param_3[0xa8] =
             (uint)(float)((double)FLOAT_803e7f20 * param_1 + (double)(float)param_3[0xa8]);
        if (FLOAT_803e7f6c < (float)param_3[0xa8]) {
          param_3[0xa8] = (uint)FLOAT_803e7f6c;
        }
        *(float *)(iVar6 + 0x7d4) =
             (float)((double)FLOAT_803e7f7c * param_1 + (double)*(float *)(iVar6 + 0x7d4));
        *(float *)(iVar6 + 0x7d4) =
             (float)((double)FLOAT_803e7e98 * param_1 + (double)*(float *)(iVar6 + 0x7d4));
        if (FLOAT_803e7ed8 <= *(float *)(iVar6 + 0x7d4)) {
          *(float *)(iVar6 + 0x7d4) = FLOAT_803e7ea4;
          iVar2 = *(int *)(*(int *)(param_2 + 0xb8) + 0x35c);
          iVar6 = *(short *)(iVar2 + 4) + -10;
          if (iVar6 < 0) {
            iVar6 = 0;
          }
          else if (*(short *)(iVar2 + 6) < iVar6) {
            iVar6 = (int)*(short *)(iVar2 + 6);
          }
          *(short *)(iVar2 + 4) = (short)iVar6;
          FUN_8000bb18(param_2,0x217);
          FUN_80030334((double)FLOAT_803e7ea4,param_2,0x88,0);
          param_3[0xa8] = (uint)FLOAT_803e7f6c;
        }
        goto LAB_80299b84;
      }
    }
    FUN_80030334((double)FLOAT_803e7ea4,param_2,0x43,0);
    param_3[0xa8] = (uint)FLOAT_803e7f78;
  }
  else if (sVar4 < 0x87) {
    if (0x80 < sVar4) goto LAB_80299964;
    *(float *)(param_2 + 0x28) =
         (float)-(DOUBLE_803e7f88 * param_1 - (double)*(float *)(param_2 + 0x28));
    dVar8 = (double)FUN_80292b44((double)FLOAT_803e7f90,param_1);
    *(float *)(param_2 + 0x28) = (float)((double)*(float *)(param_2 + 0x28) * dVar8);
    (**(code **)(*DAT_803dca8c + 0x20))(param_1,param_2,param_3,1);
    if (*(char *)((int)param_3 + 0x346) != '\0') {
      *(uint *)(iVar6 + 0x360) = *(uint *)(iVar6 + 0x360) | 0x800000;
      *(float *)(param_2 + 0x28) = FLOAT_803e7ea4;
      *(undefined2 *)(iVar6 + 0x80a) = 0xffff;
      param_3[0xc2] = (uint)FUN_802a514c;
      uVar3 = 2;
      goto LAB_80299b88;
    }
  }
  else {
    if (0x88 < sVar4) goto LAB_80299964;
    *(float *)(param_2 + 0x28) =
         (float)((double)FLOAT_803e7f6c * param_1 + (double)*(float *)(param_2 + 0x28));
    if (*(char *)((int)param_3 + 0x346) != '\0') {
      iVar6 = FUN_8002b9ac();
      if (iVar6 != 0) {
        FUN_80138ef8();
      }
      FUN_80030334((double)FLOAT_803e7ea4,param_2,0x7f,0);
      param_3[0xa8] = (uint)FLOAT_803e7eb4;
    }
  }
LAB_80299b84:
  uVar3 = 0;
LAB_80299b88:
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  return uVar3;
}

