// Function: FUN_80230598
// Entry: 80230598
// Size: 2032 bytes

/* WARNING: Removing unreachable block (ram,0x80230d68) */
/* WARNING: Removing unreachable block (ram,0x80230d60) */
/* WARNING: Removing unreachable block (ram,0x80230d58) */
/* WARNING: Removing unreachable block (ram,0x80230d50) */
/* WARNING: Removing unreachable block (ram,0x80230d48) */
/* WARNING: Removing unreachable block (ram,0x80230614) */
/* WARNING: Removing unreachable block (ram,0x802305c8) */
/* WARNING: Removing unreachable block (ram,0x802305c0) */
/* WARNING: Removing unreachable block (ram,0x802305b8) */
/* WARNING: Removing unreachable block (ram,0x802305b0) */
/* WARNING: Removing unreachable block (ram,0x802305a8) */

void FUN_80230598(void)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  ushort *puVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  byte *pbVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double in_f27;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  int local_f8;
  int local_f4;
  float local_f0;
  float local_ec;
  float local_e8;
  undefined auStack_e4 [12];
  float local_d8;
  float local_d4;
  float local_d0;
  float afStack_cc [13];
  undefined8 local_98;
  undefined8 local_90;
  longlong local_88;
  undefined4 local_80;
  uint uStack_7c;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  puVar4 = (ushort *)FUN_80286838();
  pbVar8 = *(byte **)(puVar4 + 0x5c);
  uVar5 = FUN_8022de2c();
  iVar7 = *(int *)(puVar4 + 0x26);
  if (uVar5 == 0) {
    uVar5 = FUN_8002bac4();
  }
  dVar9 = DOUBLE_803e7d30;
  bVar1 = pbVar8[0x15];
  if (bVar1 == 2) {
    if (*(float *)(pbVar8 + 0x18) <= FLOAT_803e7d38) {
      *(float *)(pbVar8 + 0x18) = FLOAT_803e7d58;
    }
    else {
      if (uVar5 != 0) {
        *(float *)(puVar4 + 0x12) =
             FLOAT_803dc078 * (*(float *)(uVar5 + 0xc) - *(float *)(puVar4 + 6));
        *(float *)(puVar4 + 0x14) =
             FLOAT_803dc078 *
             (*(float *)(pbVar8 + 0x10) + (*(float *)(uVar5 + 0x10) - *(float *)(puVar4 + 8)));
        *(float *)(puVar4 + 0x16) =
             FLOAT_803dc078 * (*(float *)(uVar5 + 0x14) - *(float *)(puVar4 + 10));
        FUN_8002ba34((double)(*(float *)(puVar4 + 0x12) * FLOAT_803dc074),
                     (double)(*(float *)(puVar4 + 0x14) * FLOAT_803dc074),
                     (double)(*(float *)(puVar4 + 0x16) * FLOAT_803dc074),(int)puVar4);
      }
      fVar2 = FLOAT_803e7d54;
      if (*(float *)(pbVar8 + 0x18) <= FLOAT_803e7d54) {
        if ((pbVar8[0x14] >> 6 & 1) != 0) {
          for (iVar3 = 0; iVar3 < *(int *)(&DAT_8032c384 + (uint)*pbVar8 * 0x18); iVar3 = iVar3 + 1)
          {
            (**(code **)(*DAT_803dd708 + 8))
                      (puVar4,*(undefined4 *)(&DAT_8032c37c + (uint)*pbVar8 * 0x18),0,2,0xffffffff,0
                      );
          }
        }
        pbVar8[0x14] = pbVar8[0x14] & 0xbf;
        *(undefined *)(puVar4 + 0x1b) = 0;
      }
      else {
        *puVar4 = *puVar4 + (short)*(undefined4 *)(&DAT_8032c388 + (uint)*pbVar8 * 0x18);
        *(float *)(puVar4 + 4) =
             ((*(float *)(pbVar8 + 0x18) - fVar2) / fVar2) * *(float *)(*(int *)(puVar4 + 0x28) + 4)
        ;
        if (FLOAT_803e7d58 != *(float *)(pbVar8 + 0x18)) {
          FUN_8002b554(puVar4,afStack_cc,'\0');
          dVar10 = (double)FLOAT_803e7d5c;
          dVar9 = (double)FLOAT_803e7d38;
          for (iVar3 = -0x7fff; iVar3 < 0x7fff;
              iVar3 = iVar3 + *(int *)(&DAT_8032c380 + (uint)*pbVar8 * 0x18)) {
            local_90 = (double)(longlong)
                               (int)(*(float *)(pbVar8 + 0x18) *
                                    *(float *)(&DAT_8032c38c + (uint)*pbVar8 * 0x18));
            local_98 = (double)CONCAT44(0x43300000,
                                        iVar3 + (int)(*(float *)(pbVar8 + 0x18) *
                                                     *(float *)(&DAT_8032c38c + (uint)*pbVar8 * 0x18
                                                               )) ^ 0x80000000);
            dVar11 = (double)FUN_80294964();
            local_f0 = (float)(dVar10 * dVar11);
            local_88 = (longlong)
                       (int)(*(float *)(pbVar8 + 0x18) *
                            *(float *)(&DAT_8032c38c + (uint)*pbVar8 * 0x18));
            uStack_7c = iVar3 + (int)(*(float *)(pbVar8 + 0x18) *
                                     *(float *)(&DAT_8032c38c + (uint)*pbVar8 * 0x18)) ^ 0x80000000;
            local_80 = 0x43300000;
            dVar11 = (double)FUN_802945e0();
            local_ec = (float)(dVar10 * dVar11);
            local_e8 = (float)dVar9;
            FUN_80247cd8(afStack_cc,&local_f0,&local_f0);
            local_d8 = local_f0 + *(float *)(puVar4 + 6);
            local_d4 = local_ec + *(float *)(puVar4 + 8);
            local_d0 = local_e8 + *(float *)(puVar4 + 10);
            (**(code **)(*DAT_803dd708 + 8))
                      (puVar4,*(undefined4 *)(&DAT_8032c378 + (uint)*pbVar8 * 0x18),auStack_e4,
                       0x200001,0xffffffff,puVar4 + 0x12);
            (**(code **)(*DAT_803dd708 + 8))
                      (puVar4,*(undefined4 *)(&DAT_8032c378 + (uint)*pbVar8 * 0x18),auStack_e4,
                       0x200001,0xffffffff,puVar4 + 0x12);
            (**(code **)(*DAT_803dd708 + 8))
                      (puVar4,*(undefined4 *)(&DAT_8032c378 + (uint)*pbVar8 * 0x18),auStack_e4,
                       0x200001,0xffffffff,puVar4 + 0x12);
          }
        }
        pbVar8[0x14] = pbVar8[0x14] & 0xbf | 0x40;
      }
      *(float *)(pbVar8 + 0x18) = *(float *)(pbVar8 + 0x18) - FLOAT_803dc074;
      fVar2 = FLOAT_803e7d38;
      if (*(float *)(pbVar8 + 0x18) <= FLOAT_803e7d38) {
        *(float *)(pbVar8 + 0x18) = FLOAT_803e7d38;
        *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(iVar7 + 8);
        *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(iVar7 + 0xc);
        *(undefined4 *)(puVar4 + 10) = *(undefined4 *)(iVar7 + 0x10);
        *puVar4 = 0;
        *(undefined *)(puVar4 + 0x1b) = 0xff;
        *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(*(int *)(puVar4 + 0x28) + 4);
        *(float *)(puVar4 + 0x12) = fVar2;
        *(float *)(puVar4 + 0x14) = fVar2;
        *(float *)(puVar4 + 0x16) = fVar2;
        pbVar8[0x15] = 3;
        puVar4[3] = puVar4[3] | 0x4000;
      }
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      local_98 = (double)CONCAT44(0x43300000,(uint)*(byte *)(puVar4 + 0x1b));
      iVar3 = (int)-(FLOAT_803e7d4c * FLOAT_803dc074 - (float)(local_98 - DOUBLE_803e7d30));
      local_90 = (double)(longlong)iVar3;
      if (iVar3 < 0) {
        iVar3 = 0;
        puVar4[3] = puVar4[3] | 0x4000;
      }
      *(char *)(puVar4 + 0x1b) = (char)iVar3;
      if (*(short *)(iVar7 + 0x20) < 0) {
        iVar7 = FUN_8022de2c();
        if (iVar7 != 0) {
          puVar4[3] = puVar4[3] & 0xbfff;
          pbVar8[0x15] = 1;
        }
      }
      else {
        uVar5 = FUN_80020078((int)*(short *)(iVar7 + 0x20));
        if (uVar5 != 0) {
          puVar4[3] = puVar4[3] & 0xbfff;
          pbVar8[0x15] = 1;
        }
      }
      goto LAB_80230d48;
    }
    dVar11 = (double)FLOAT_803e7d4c;
    dVar10 = (double)FLOAT_803dc074;
    local_90 = (double)CONCAT44(0x43300000,(uint)*(byte *)(puVar4 + 0x1b));
    iVar3 = (int)(dVar11 * dVar10 + (double)(float)(local_90 - DOUBLE_803e7d30));
    local_98 = (double)(longlong)iVar3;
    if (0xff < iVar3) {
      iVar3 = 0xff;
    }
    *(char *)(puVar4 + 0x1b) = (char)iVar3;
    if ((-1 < *(short *)(iVar7 + 0x20)) &&
       (uVar6 = FUN_80020078((int)*(short *)(iVar7 + 0x20)), uVar6 == 0)) {
      pbVar8[0x15] = 1;
    }
    bVar1 = pbVar8[1];
    if (bVar1 == 3) {
LAB_8023076c:
      iVar7 = FUN_80036974((int)puVar4,&local_f4,(int *)0x0,(uint *)0x0);
      if (((iVar7 != 0) && (local_f4 != 0)) &&
         ((*(short *)(local_f4 + 0x46) == 0x604 || (*(short *)(local_f4 + 0x46) == 0x605)))) {
        iVar7 = FUN_8022de2c();
        FUN_8022dbe4(iVar7,0xf);
        *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(*(int *)(puVar4 + 0x28) + 4);
        FUN_8002b95c((int)puVar4,0);
        FUN_80035ff8((int)puVar4);
        pbVar8[0x14] = pbVar8[0x14] & 0x7f | 0x80;
        if (*(uint *)(pbVar8 + 0x20) != 0) {
          FUN_8001f448(*(uint *)(pbVar8 + 0x20));
          pbVar8[0x20] = 0;
          pbVar8[0x21] = 0;
          pbVar8[0x22] = 0;
          pbVar8[0x23] = 0;
        }
      }
      dVar9 = (double)FUN_802300c4((int)puVar4,(int)pbVar8);
    }
    else if (bVar1 < 3) {
      if (bVar1 == 1) {
LAB_802308a0:
        dVar9 = (double)FUN_802300c4((int)puVar4,(int)pbVar8);
      }
      else if ((((bVar1 != 0) &&
                (iVar7 = FUN_80036974((int)puVar4,&local_f8,(int *)0x0,(uint *)0x0), iVar7 != 0)) &&
               (local_f8 != 0)) &&
              ((*(short *)(local_f8 + 0x46) == 0x604 || (*(short *)(local_f8 + 0x46) == 0x605)))) {
        iVar7 = FUN_8022de2c();
        FUN_8022dbe4(iVar7,0xf);
        *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(*(int *)(puVar4 + 0x28) + 4);
        FUN_8002b95c((int)puVar4,0);
        dVar9 = (double)FUN_80035ff8((int)puVar4);
        pbVar8[0x14] = pbVar8[0x14] & 0x7f | 0x80;
        if (*(uint *)(pbVar8 + 0x20) != 0) {
          dVar9 = (double)FUN_8001f448(*(uint *)(pbVar8 + 0x20));
          pbVar8[0x20] = 0;
          pbVar8[0x21] = 0;
          pbVar8[0x22] = 0;
          pbVar8[0x23] = 0;
        }
      }
    }
    else {
      if (bVar1 == 5) goto LAB_8023076c;
      if (bVar1 < 5) goto LAB_802308a0;
    }
    if ((((char)pbVar8[0x14] < '\0') && (uVar6 = FUN_8022de14(uVar5), uVar6 == 0)) &&
       ((iVar7 = FUN_8022ddd4(uVar5), iVar7 == 0 &&
        (iVar7 = FUN_8023039c(dVar9,dVar10,dVar11,in_f4,in_f5,in_f6,in_f7,in_f8,(int)puVar4,
                              (char *)pbVar8,uVar5), iVar7 != 0)))) {
      FUN_80230220(dVar9,dVar10,dVar11,in_f4,in_f5,in_f6,in_f7,in_f8,(int)puVar4,(char *)pbVar8,
                   uVar5);
    }
    local_90 = (double)CONCAT44(0x43300000,(int)(short)*puVar4 ^ 0x80000000);
    iVar7 = (int)(FLOAT_803e7d50 * FLOAT_803dc074 + (float)(local_90 - DOUBLE_803e7d68));
    local_98 = (double)(longlong)iVar7;
    *puVar4 = (ushort)iVar7;
  }
  if ((*(int *)(pbVar8 + 0x20) != 0) && (iVar7 = FUN_8001dc28(*(int *)(pbVar8 + 0x20)), iVar7 != 0))
  {
    FUN_8001d774(*(int *)(pbVar8 + 0x20));
  }
LAB_80230d48:
  FUN_80286884();
  return;
}

