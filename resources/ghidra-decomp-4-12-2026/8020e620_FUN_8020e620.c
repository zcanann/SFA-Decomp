// Function: FUN_8020e620
// Entry: 8020e620
// Size: 3392 bytes

/* WARNING: Removing unreachable block (ram,0x8020f338) */
/* WARNING: Removing unreachable block (ram,0x8020f330) */
/* WARNING: Removing unreachable block (ram,0x8020f328) */
/* WARNING: Removing unreachable block (ram,0x8020f0c8) */
/* WARNING: Removing unreachable block (ram,0x8020eba8) */
/* WARNING: Removing unreachable block (ram,0x8020e640) */
/* WARNING: Removing unreachable block (ram,0x8020e638) */
/* WARNING: Removing unreachable block (ram,0x8020e630) */
/* WARNING: Removing unreachable block (ram,0x8020f068) */

void FUN_8020e620(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined2 *puVar4;
  ushort uVar6;
  int *piVar5;
  short *psVar7;
  short sVar8;
  byte bVar9;
  uint *puVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  ushort local_a8 [4];
  float local_a0;
  float local_9c;
  float local_98;
  undefined4 local_78;
  uint uStack_74;
  undefined8 local_70;
  longlong local_68;
  undefined4 local_60;
  uint uStack_5c;
  undefined8 local_58;
  undefined4 local_50;
  uint uStack_4c;
  
  puVar10 = *(uint **)(param_9 + 0x5c);
  psVar7 = *(short **)(param_9 + 0x26);
  sVar8 = *psVar7;
  if (sVar8 < 0x5ed) {
    if (sVar8 != 0x5dd) {
      if (sVar8 < 0x5dd) {
        if (sVar8 == 0x5da) {
          *param_9 = *param_9 + (short)*(char *)(puVar10 + 0xa0);
          param_9[1] = param_9[1] + (short)*(char *)((int)puVar10 + 0x27f);
          param_9[2] = param_9[2] + (short)*(char *)((int)puVar10 + 0x27e);
          *(char *)(puVar10 + 0x9f) = *(char *)(puVar10 + 0x9f) + '\x02';
          uStack_4c = (int)(short)((ushort)*(byte *)(puVar10 + 0x9f) << 8) ^ 0x80000000;
          local_50 = 0x43300000;
          dVar11 = (double)FUN_80294964();
          *(float *)(param_9 + 4) =
               FLOAT_803e7334 * (float)((double)FLOAT_803e7310 + dVar11) + FLOAT_803e7330;
          return;
        }
        if (0x5d9 < sVar8) {
          if (sVar8 < 0x5dc) {
            *param_9 = 0x21a8;
            *(float *)(param_9 + 4) = FLOAT_803e7338;
            return;
          }
          if (*(int *)(param_9 + 0x7a) == 0) {
            iVar3 = FUN_8002e1ac(0x431dc);
            *(int *)(param_9 + 0x7a) = iVar3;
            FUN_80037e24((int)param_9,*(int *)(param_9 + 0x7a),0);
          }
          if (*(int *)(param_9 + 0x7c) == 0) {
            iVar3 = FUN_8002e1ac(0x4325b);
            *(int *)(param_9 + 0x7c) = iVar3;
            FUN_80037e24((int)param_9,*(int *)(param_9 + 0x7c),0);
          }
          iVar3 = FUN_800395a4((int)param_9,0);
          if (iVar3 == 0) {
            return;
          }
          sVar8 = -*(short *)(iVar3 + 8) + -2;
          if (sVar8 < 0) {
            sVar8 = -*(short *)(iVar3 + 8) + 0x270e;
          }
          *(short *)(iVar3 + 8) = -sVar8;
          return;
        }
        if (0x5d8 < sVar8) {
          return;
        }
        if (sVar8 < 0x5d5) {
          return;
        }
      }
      else {
        if (sVar8 == 0x5e2) {
          bVar9 = *(byte *)((int)psVar7 + 0x1b);
          if (bVar9 == 1) {
            param_9[1] = param_9[1] + 100;
            return;
          }
          if (bVar9 == 0) {
            *param_9 = *param_9 + 100;
            return;
          }
          if (2 < bVar9) {
            return;
          }
          param_9[2] = param_9[2] + 100;
          return;
        }
        if (0x5e1 < sVar8) {
          if (0x5e3 < sVar8) {
            return;
          }
          if ((uint)*(byte *)(puVar10 + 0x9f) != (int)*(char *)((int)param_9 + 0xad)) {
            FUN_8002b95c((int)param_9,(uint)*(byte *)(puVar10 + 0x9f));
          }
          if ((int)*(char *)((int)puVar10 + 0x27e) != (-DAT_803dd4e8 | DAT_803dd4e8) >> 0x1f) {
            if (DAT_803dd4e8 == 0) {
              FUN_8003042c((double)FLOAT_803e72f4,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,param_9,0,0,param_12,param_13,param_14,param_15,param_16);
            }
            else {
              FUN_8003042c((double)FLOAT_803e72f4,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,param_9,1,0,param_12,param_13,param_14,param_15,param_16);
            }
          }
          *(byte *)((int)puVar10 + 0x27e) =
               (byte)((byte)(-DAT_803dd4e8 >> 0x18) | (byte)(DAT_803dd4e8 >> 0x18)) >> 7;
          FUN_8002fb40((double)*(float *)(&DAT_8032ae58 + (uint)*(byte *)(puVar10 + 0x9f) * 4),
                       (double)FLOAT_803dc074);
          if (*(char *)((int)puVar10 + 0x27d) != '\0') {
            return;
          }
          if (*puVar10 == 0) {
            return;
          }
          FUN_8001f448(*puVar10);
          *puVar10 = 0;
          return;
        }
        if (sVar8 != 0x5df) {
          return;
        }
        FUN_8020e05c((int)param_9);
      }
      if ((*(int *)(param_9 + 0x7c) == 0) && (iVar3 = FUN_8002e1ac(puVar10[0x9e]), iVar3 != 0)) {
        *(float *)(iVar3 + 8) = *(float *)(iVar3 + 8) * FLOAT_803e7300;
        *(undefined *)(iVar3 + 0x36) = 0x96;
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
        FUN_80037e24((int)param_9,iVar3,0);
        param_9[0x7c] = 0;
        param_9[0x7d] = 1;
      }
      if ((*(int *)(param_9 + 0x7a) != 0) && (puVar10[0x9d] != 0)) {
        puVar4 = FUN_8000facc();
        dVar14 = (double)(*(float *)(puVar4 + 6) - *(float *)(param_9 + 6));
        dVar12 = (double)(*(float *)(puVar4 + 8) - *(float *)(param_9 + 8));
        dVar13 = (double)(*(float *)(puVar4 + 10) - *(float *)(param_9 + 10));
        dVar11 = FUN_80293900((double)(float)(dVar13 * dVar13 +
                                             (double)(float)(dVar14 * dVar14 +
                                                            (double)(float)(dVar12 * dVar12))));
        if ((double)FLOAT_803e72f4 < dVar11) {
          dVar14 = (double)(float)(dVar14 / dVar11);
          dVar12 = (double)(float)(dVar12 / dVar11);
          dVar13 = (double)(float)(dVar13 / dVar11);
        }
        dVar11 = (double)FLOAT_803e7340;
        *(float *)(puVar10[0x9d] + 0xc) = (float)(dVar11 * dVar14 + (double)*(float *)(param_9 + 6))
        ;
        *(float *)(puVar10[0x9d] + 0x10) =
             (float)(dVar11 * dVar12 + (double)*(float *)(param_9 + 8));
        *(float *)(puVar10[0x9d] + 0x14) =
             (float)(dVar11 * dVar13 + (double)*(float *)(param_9 + 10));
      }
      if (*(char *)((int)puVar10 + 0x27d) != '\0') {
        uVar6 = FUN_8012e0e8();
        if ((((uVar6 & 0xff) == 0) && (iVar3 = (**(code **)(*DAT_803dd6cc + 0x14))(), iVar3 != 0))
           && (DAT_803de9b4 == 0)) {
          if (*puVar10 == 0) {
            piVar5 = FUN_8001f58c((int)param_9,'\x01');
            *puVar10 = (uint)piVar5;
            if (*puVar10 != 0) {
              FUN_8001dbf0(*puVar10,2);
              FUN_8001de4c((double)FLOAT_803e72f4,(double)FLOAT_803e7344,(double)FLOAT_803e72f4,
                           (int *)*puVar10);
              FUN_8001dbb4(*puVar10,0xff,0,0,0xff);
              FUN_8001db7c(*puVar10,0,0,0,0xff);
              FUN_8001dc30((double)FLOAT_803e72f4,*puVar10,'\x01');
              FUN_8001dcfc((double)FLOAT_803e7348,(double)FLOAT_803e734c,*puVar10);
              FUN_8001d6e4(*puVar10,2,0x3c);
              FUN_8001dd54((double)FLOAT_803e72f4,(double)FLOAT_803e72dc,(double)FLOAT_803e72f4,
                           (int *)*puVar10);
            }
          }
        }
        else if (*puVar10 != 0) {
          FUN_8001f448(*puVar10);
          *puVar10 = 0;
        }
        *(undefined *)(*(int *)(DAT_803de9b0 + 0xb8) + 0x27d) = 1;
        *(undefined4 *)(DAT_803de9b0 + 0xc) = *(undefined4 *)(param_9 + 6);
        *(float *)(DAT_803de9b0 + 0x10) = FLOAT_803e7350 + *(float *)(param_9 + 8);
        *(undefined4 *)(DAT_803de9b0 + 0x14) = *(undefined4 *)(param_9 + 10);
        iVar3 = FUN_8002e1ac(0x4300c);
        if ((iVar3 != 0) && ((*(ushort *)(iVar3 + 6) & 0x4000) != 0)) {
          FUN_8002b95c(DAT_803de9b0,1);
          return;
        }
        FUN_8002b95c(DAT_803de9b0,0);
        return;
      }
      if (*puVar10 == 0) {
        return;
      }
      FUN_8001f448(*puVar10);
      *puVar10 = 0;
      return;
    }
  }
  else {
    if (sVar8 == 0x61e) {
      param_9[1] = 0x3448;
      *param_9 = 0x4000;
      bVar9 = *(byte *)((int)psVar7 + 0x1b);
      if (bVar9 == 1) {
        param_9[2] = param_9[2] + -0x10;
      }
      else if (bVar9 == 0) {
        param_9[2] = param_9[2] + -0xe;
      }
      else if (bVar9 < 3) {
        param_9[2] = param_9[2] + -0x13;
      }
      if (*(char *)(puVar10 + 0x9f) != '\0') {
        return;
      }
      bVar9 = *(byte *)((int)psVar7 + 0x1b);
      if (bVar9 == 1) {
        FUN_8020e23c(param_9,0xa5,0xbe,0xfffffff8,8,0x4b,0x6f3);
        FUN_8020e23c(param_9,0xa5,0xbe,0xfffffff6,10,0x4b,0x6f4);
        FUN_8020e23c(param_9,0xa5,0xbe,0xfffffff8,8,0x4b,0x6f5);
        FUN_8020e23c(param_9,0xa5,0xbe,0xfffffff6,10,0x32,0x6f6);
        FUN_8020e23c(param_9,0xa5,0xbe,0xfffffff8,8,0x4b,0x6f7);
        FUN_8020e23c(param_9,0xa5,0xbe,0xfffffff6,10,0x32,0x6f8);
      }
      else if (bVar9 == 0) {
        FUN_8020e23c(param_9,0xfa,0x113,0xfffffffb,5,0x4b,0x6f3);
        FUN_8020e23c(param_9,0xfa,0x113,0xfffffff9,7,0x4b,0x6f4);
        FUN_8020e23c(param_9,0xfa,0x113,0xfffffffb,5,0x4b,0x6f5);
        FUN_8020e23c(param_9,0xfa,0x113,0xfffffff9,7,0x32,0x6f6);
        FUN_8020e23c(param_9,0xfa,0x113,0xfffffffb,5,0x4b,0x6f7);
        FUN_8020e23c(param_9,0xfa,0x113,0xfffffff9,7,0x32,0x6f8);
      }
      else if (bVar9 < 3) {
        FUN_8020e23c(param_9,0x78,0x91,0xfffffffb,5,0x32,0x6f3);
        FUN_8020e23c(param_9,0x78,0x91,0xfffffff9,7,0x32,0x6f4);
        FUN_8020e23c(param_9,0x78,0x91,0xfffffffb,5,0x32,0x6f5);
        FUN_8020e23c(param_9,0x78,0x91,0xfffffff9,7,0x19,0x6f6);
        FUN_8020e23c(param_9,0x78,0x91,0xfffffffb,5,0x32,0x6f7);
        FUN_8020e23c(param_9,0x78,0x91,0xfffffff9,7,0x19,0x6f8);
      }
      *(undefined *)(puVar10 + 0x9f) = 1;
      return;
    }
    if (0x61d < sVar8) {
      if (sVar8 != 0x80f) {
        if (0x80e < sVar8) {
          return;
        }
        if (sVar8 != 0x740) {
          return;
        }
        FUN_8002fb40((double)FLOAT_803e732c,(double)FLOAT_803dc074);
        *param_9 = (short)(int)(FLOAT_803e7324 * FLOAT_803dc074 +
                               (float)((double)CONCAT44(0x43300000,(int)*param_9 ^ 0x80000000) -
                                      DOUBLE_803e7308));
        return;
      }
      if (((int)puVar10[0x9c] < 0x8001) && (-1 < (int)puVar10[0x9c])) {
        iVar3 = FUN_8002e1ac(0x42fe7);
        iVar2 = FUN_8002e1ac(0x4305a);
        if ((iVar3 != 0) && (iVar2 != 0)) {
          local_70 = (double)CONCAT44(0x43300000,(int)*(char *)(puVar10 + 0xa0) ^ 0x80000000);
          uStack_74 = puVar10[0x9c] ^ 0x80000000;
          local_78 = 0x43300000;
          uVar1 = (uint)((float)(local_70 - DOUBLE_803e7308) * FLOAT_803dc074 +
                        (float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803e7308));
          local_68 = (longlong)(int)uVar1;
          puVar10[0x9c] = uVar1;
          uStack_5c = puVar10[0x9c] ^ 0x80000000;
          local_60 = 0x43300000;
          dVar11 = (double)FUN_80294964();
          local_a0 = (float)((double)(float)puVar10[0x98] * dVar11);
          local_9c = FLOAT_803e72f4;
          local_58 = CONCAT44(0x43300000,puVar10[0x9c] ^ 0x80000000);
          dVar11 = (double)FUN_802945e0();
          local_98 = (float)((double)(float)puVar10[0x97] * dVar11);
          dVar12 = (double)(*(float *)(iVar2 + 0xc) - *(float *)(iVar3 + 0xc));
          dVar11 = (double)(*(float *)(iVar2 + 0x14) - *(float *)(iVar3 + 0x14));
          iVar2 = FUN_80021884();
          local_a8[0] = (ushort)iVar2;
          local_a8[1] = 0;
          local_a8[2] = 0;
          FUN_80021b8c(local_a8,&local_a0);
          *(float *)(param_9 + 6) = local_a0 + (float)((double)*(float *)(iVar3 + 0xc) - dVar12);
          uStack_4c = puVar10[0x9c] ^ 0x80000000;
          local_50 = 0x43300000;
          *(float *)(param_9 + 8) =
               (float)puVar10[0x99] +
               ((float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e7308) *
               ((float)puVar10[0x9a] - (float)puVar10[0x99])) / FLOAT_803e7320;
          *(float *)(param_9 + 10) = local_98 + (float)((double)*(float *)(iVar3 + 0x14) - dVar11);
        }
        *(float *)(param_9 + 0x12) =
             FLOAT_803dc078 * (*(float *)(param_9 + 6) - *(float *)(param_9 + 0x40));
        *(float *)(param_9 + 0x16) =
             FLOAT_803dc078 * (*(float *)(param_9 + 10) - *(float *)(param_9 + 0x44));
        local_a0 = *(float *)(param_9 + 0x12);
        local_9c = FLOAT_803e72f4;
        local_98 = *(float *)(param_9 + 0x16);
        FUN_80098bb4((double)(FLOAT_803e7300 * (float)puVar10[0x9b]),param_9,2,0xdf,8,&local_a0);
        dVar11 = DOUBLE_803e7308;
        uStack_4c = (int)*param_9 ^ 0x80000000;
        local_50 = 0x43300000;
        iVar3 = (int)(FLOAT_803e7324 * FLOAT_803dc074 +
                     (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e7308));
        local_58 = (longlong)iVar3;
        *param_9 = (short)iVar3;
        uStack_5c = (int)param_9[1] ^ 0x80000000;
        local_60 = 0x43300000;
        iVar3 = (int)(FLOAT_803e7328 * FLOAT_803dc074 +
                     (float)((double)CONCAT44(0x43300000,uStack_5c) - dVar11));
        local_68 = (longlong)iVar3;
        param_9[1] = (short)iVar3;
        if (*puVar10 == 0) {
          return;
        }
        iVar3 = FUN_8001dc28(*puVar10);
        if (iVar3 == 0) {
          return;
        }
        FUN_8001d774(*puVar10);
        return;
      }
      if (*puVar10 != 0) {
        FUN_8001dc30((double)FLOAT_803e7310,*puVar10,'\0');
      }
      dVar11 = DOUBLE_803e7358;
      dVar13 = (double)FLOAT_803e7314;
      dVar12 = (double)FLOAT_803dc074;
      uStack_74 = (uint)*(byte *)(param_9 + 0x1b);
      local_78 = 0x43300000;
      iVar3 = (int)-(float)(dVar13 * dVar12 -
                           (double)(float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803e7358)
                           );
      local_70 = (double)(longlong)iVar3;
      if (iVar3 < 0) {
        iVar3 = 0;
      }
      *(char *)(param_9 + 0x1b) = (char)iVar3;
      if (*(char *)(param_9 + 0x1b) != '\0') {
        return;
      }
      FUN_8002cc9c(dVar11,dVar12,dVar13,param_4,param_5,param_6,param_7,param_8,(int)param_9);
      return;
    }
    if (sVar8 == 0x5f5) {
      *param_9 = *param_9 + 1;
      return;
    }
    if (0x5f4 < sVar8) {
      if (sVar8 != 0x602) {
        return;
      }
      FUN_8002fb40((double)FLOAT_803e733c,(double)FLOAT_803dc074);
      return;
    }
    if (0x5f3 < sVar8) {
      return;
    }
  }
  if (*(char *)((int)puVar10 + 0x27d) == '\x02') {
    for (bVar9 = 0; bVar9 < 0x16; bVar9 = bVar9 + 1) {
      uVar1 = (uint)bVar9;
      FUN_80038524(param_9,uVar1,(float *)(puVar10 + uVar1 * 6 + 4),puVar10 + uVar1 * 6 + 5,
                   (float *)(puVar10 + uVar1 * 6 + 6),0);
    }
  }
  return;
}

