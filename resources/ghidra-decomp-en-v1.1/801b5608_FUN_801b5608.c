// Function: FUN_801b5608
// Entry: 801b5608
// Size: 1532 bytes

/* WARNING: Removing unreachable block (ram,0x801b5be4) */
/* WARNING: Removing unreachable block (ram,0x801b5618) */

void FUN_801b5608(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  double dVar10;
  double in_f31;
  double dVar11;
  double in_ps31_1;
  undefined8 uVar12;
  float local_b8;
  float local_b4;
  float local_b0;
  float afStack_ac [12];
  float afStack_7c [13];
  undefined8 local_48;
  undefined4 local_40;
  uint uStack_3c;
  undefined8 local_38;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar12 = FUN_8028683c();
  iVar3 = (int)((ulonglong)uVar12 >> 0x20);
  iVar2 = (int)uVar12;
  iVar8 = *(int *)(iVar3 + 0xb8);
  *(undefined *)(iVar8 + 0xa58) = 0;
  if ((int)*(short *)(iVar2 + 0x1a) == 0) {
    dVar11 = (double)FLOAT_803e5640;
  }
  else {
    local_48 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar2 + 0x1a) ^ 0x80000000);
    dVar11 = (double)((float)(local_48 - DOUBLE_803e55e0) * FLOAT_803e560c);
    if ((double)FLOAT_803e5640 < dVar11) {
      dVar11 = (double)FLOAT_803e5640;
    }
  }
  FUN_801b4398((double)(float)((double)FLOAT_803e5644 * dVar11),(double)*(float *)(iVar3 + 0xc),
               (double)*(float *)(iVar3 + 0x10),(double)*(float *)(iVar3 + 0x14));
  *(ushort *)(iVar3 + 0xb0) = *(ushort *)(iVar3 + 0xb0) | 0x2000;
  *(byte *)(iVar8 + 0xa5d) = (byte)*(undefined2 *)(iVar2 + 0x1c) & 3;
  FUN_8002b95c(iVar3,(uint)*(byte *)(iVar8 + 0xa5d));
  if ((*(ushort *)(iVar2 + 0x1c) & 4) == 0) {
    *(float *)(iVar8 + 0xa3c) = FLOAT_803e55f8;
  }
  else {
    *(float *)(iVar8 + 0xa3c) = FLOAT_803e563c;
  }
  *(undefined *)(iVar8 + 0xa5c) = 0;
  iVar4 = FUN_80065a20((double)*(float *)(iVar3 + 0xc),
                       (double)(FLOAT_803e5648 + *(float *)(iVar3 + 0x10)),
                       (double)*(float *)(iVar3 + 0x14),iVar3,(float *)(iVar8 + 0x960),0);
  if (iVar4 == 0) {
    if (*(float *)(iVar8 + 0x960) < FLOAT_803e564c) {
      *(undefined *)(iVar8 + 0xa5c) = 1;
    }
    *(float *)(iVar8 + 0x960) = *(float *)(iVar3 + 0x10) - *(float *)(iVar8 + 0x960);
  }
  else {
    *(undefined4 *)(iVar8 + 0x960) = *(undefined4 *)(iVar3 + 0x10);
  }
  if ((*(ushort *)(iVar2 + 0x1c) & 0x10) == 0) {
    *(undefined *)(iVar8 + 0xa5a) = 0;
  }
  else {
    iVar4 = (int)((float)((double)FLOAT_803e5650 * dVar11) / FLOAT_803e5640);
    local_48 = (double)(longlong)iVar4;
    iVar9 = iVar8;
    for (iVar7 = 0; iVar7 < iVar4; iVar7 = iVar7 + 1) {
      if (*(char *)(iVar8 + 0xa5c) == '\0') {
        uVar6 = FUN_80022264(0x14,0x28);
        local_38 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        local_b0 = FLOAT_803e5654 * FLOAT_803e5658 * (float)(local_38 - DOUBLE_803e55e0) +
                   FLOAT_803e5654;
        iVar1 = iVar7 >> 0x1f;
        uVar6 = (iVar1 * 4 | (uint)(iVar7 * 0x40000000 + iVar1) >> 0x1e) - iVar1 & 0xff;
        local_b8 = local_b0 * (float)(&DAT_80326168)[uVar6 * 3];
        local_b4 = local_b0 * (float)(&DAT_8032616c)[uVar6 * 3];
        local_b0 = local_b0 * (float)(&DAT_80326170)[uVar6 * 3];
        uStack_3c = FUN_80022264(0,0x8000);
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        FUN_8024782c((double)(float)(DOUBLE_803e5600 *
                                    (double)(((float)((double)CONCAT44(0x43300000,uStack_3c) -
                                                     DOUBLE_803e55e0) - FLOAT_803e5660) /
                                            FLOAT_803e565c)),afStack_7c,0x7a);
        uVar6 = FUN_80022264(0,0x8000);
        local_48 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        FUN_8024782c((double)(float)(DOUBLE_803e5600 *
                                    (double)(((float)(local_48 - DOUBLE_803e55e0) - FLOAT_803e5660)
                                            / FLOAT_803e565c)),afStack_ac,0x78);
        FUN_80247618(afStack_ac,afStack_7c,afStack_7c);
        FUN_80247cd8(afStack_7c,&local_b8,&local_b8);
      }
      else {
        uVar6 = FUN_80022264(0x14,0x28);
        local_48 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        local_b8 = FLOAT_803e5654 * FLOAT_803e5658 * (float)(local_48 - DOUBLE_803e55e0) +
                   FLOAT_803e5654;
        local_b4 = FLOAT_803e55f8;
        local_b0 = FLOAT_803e55f8;
        uStack_3c = FUN_80022264(0x2000,0x6000);
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        FUN_8024782c((double)(float)(DOUBLE_803e5600 *
                                    (double)((float)((double)CONCAT44(0x43300000,uStack_3c) -
                                                    DOUBLE_803e55e0) / FLOAT_803e565c)),afStack_7c,
                     0x7a);
        uVar6 = FUN_80022264(0,0xffff);
        local_38 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        FUN_8024782c((double)(float)(DOUBLE_803e5600 *
                                    (double)((float)(local_38 - DOUBLE_803e55e0) / FLOAT_803e5608)),
                     afStack_ac,0x79);
        FUN_80247618(afStack_ac,afStack_7c,afStack_7c);
        FUN_80247cd8(afStack_7c,&local_b8,&local_b8);
      }
      *(undefined4 *)(iVar9 + 0x964) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(iVar9 + 0x968) = *(undefined4 *)(iVar3 + 0x10);
      *(undefined4 *)(iVar9 + 0x96c) = *(undefined4 *)(iVar3 + 0x14);
      *(float *)(iVar9 + 0x970) = local_b8;
      *(float *)(iVar9 + 0x974) = local_b4;
      *(float *)(iVar9 + 0x978) = local_b0;
      *(undefined4 *)(iVar9 + 0x97c) = 0;
      uVar6 = FUN_80022264(0x28,0x32);
      *(uint *)(iVar9 + 0x980) = uVar6;
      *(undefined *)(iVar9 + 0x984) = 1;
      iVar9 = iVar9 + 0x24;
    }
    *(char *)(iVar8 + 0xa5a) = (char)iVar7;
  }
  *(undefined4 *)(iVar8 + 0xa40) = 0;
  if ((*(ushort *)(iVar2 + 0x1c) & 0x20) != 0) {
    piVar5 = FUN_8001f58c(0,'\x01');
    *(int **)(iVar8 + 0xa40) = piVar5;
    if (*(int *)(iVar8 + 0xa40) != 0) {
      FUN_8001dbf0(*(int *)(iVar8 + 0xa40),2);
      FUN_8001de4c((double)*(float *)(iVar3 + 0x18),(double)*(float *)(iVar3 + 0x1c),
                   (double)*(float *)(iVar3 + 0x20),*(int **)(iVar8 + 0xa40));
      FUN_8001de04(*(int *)(iVar8 + 0xa40),1);
      FUN_8001dc30((double)FLOAT_803e55f8,*(int *)(iVar8 + 0xa40),'\x01');
      FUN_8001dcfc((double)(float)((double)FLOAT_803e5664 * dVar11),
                   (double)(float)((double)FLOAT_803e55f0 * dVar11),*(int *)(iVar8 + 0xa40));
      FUN_8001dbb4(*(int *)(iVar8 + 0xa40),0xff,0xeb,0xa0,0xff);
    }
  }
  *(undefined *)(iVar3 + 0x36) = 0xff;
  if ((*(ushort *)(iVar2 + 0x1c) & 8) == 0) {
    *(undefined *)(iVar8 + 0xa59) = 0;
  }
  else if (*(char *)(iVar8 + 0xa5c) == '\0') {
    *(undefined *)(iVar8 + 0xa59) = 2;
    uVar6 = FUN_80022264(0,0x4000);
    *(short *)(iVar8 + 0xa44) = (short)uVar6;
    uVar6 = FUN_80022264(0,0x8000);
    *(short *)(iVar8 + 0xa46) = (short)uVar6;
    *(short *)(iVar8 + 0xa48) = *(short *)(iVar8 + 0xa44) + 0x4000;
    *(undefined2 *)(iVar8 + 0xa4a) = *(undefined2 *)(iVar8 + 0xa46);
  }
  else {
    *(undefined *)(iVar8 + 0xa59) = 1;
    *(undefined2 *)(iVar8 + 0xa44) = 0;
    *(undefined2 *)(iVar8 + 0xa46) = 0;
  }
  *(undefined *)(iVar8 + 0xa5b) = 0;
  *(undefined4 *)(iVar8 + 0xa4c) = 0;
  dVar10 = FUN_80293900(dVar11);
  local_38 = (double)(longlong)(int)((double)FLOAT_803e55c8 * dVar10);
  *(int *)(iVar8 + 0xa50) = (int)((double)FLOAT_803e55c8 * dVar10);
  iVar2 = *(int *)(iVar8 + 0xa50);
  if (iVar2 < 0) {
    iVar2 = 0;
  }
  else if (0x3c < iVar2) {
    iVar2 = 0x3c;
  }
  *(int *)(iVar8 + 0xa50) = iVar2;
  *(float *)(iVar8 + 0xa54) = (float)dVar11;
  *(float *)(iVar3 + 8) = FLOAT_803e55f8;
  FUN_80286888();
  return;
}

