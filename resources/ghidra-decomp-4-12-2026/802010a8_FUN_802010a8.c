// Function: FUN_802010a8
// Entry: 802010a8
// Size: 980 bytes

/* WARNING: Removing unreachable block (ram,0x8020145c) */
/* WARNING: Removing unreachable block (ram,0x80201454) */
/* WARNING: Removing unreachable block (ram,0x8020144c) */
/* WARNING: Removing unreachable block (ram,0x802010c8) */
/* WARNING: Removing unreachable block (ram,0x802010c0) */
/* WARNING: Removing unreachable block (ram,0x802010b8) */
/* WARNING: Type propagation algorithm not settling */

void FUN_802010a8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  short sVar1;
  float fVar2;
  float fVar3;
  ushort *puVar4;
  uint uVar5;
  int iVar6;
  int *piVar7;
  int iVar8;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short *psVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  ushort *puVar13;
  double extraout_f1;
  double dVar14;
  double dVar15;
  double in_f29;
  double dVar16;
  double in_f30;
  double in_f31;
  double dVar17;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar18;
  int local_98 [3];
  ushort *local_8c;
  undefined4 local_88;
  undefined4 local_84;
  int local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_60;
  uint uStack_5c;
  longlong local_58;
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
  uVar18 = FUN_80286834();
  puVar4 = (ushort *)((ulonglong)uVar18 >> 0x20);
  iVar8 = (int)uVar18;
  iVar12 = *(int *)(puVar4 + 0x5c);
  iVar11 = *(int *)(iVar12 + 0x40c);
  iVar10 = *(int *)(iVar11 + 0x30);
  *(byte *)(iVar11 + 0x15) = *(byte *)(iVar11 + 0x15) & 0xfb;
  *(byte *)(iVar11 + 0x14) = *(byte *)(iVar11 + 0x14) | 2;
  dVar17 = extraout_f1;
  FUN_80137cd0();
  if (*(int *)(iVar11 + 0x3c) == 0) {
    local_68 = FUN_8002bac4();
    psVar9 = *(short **)(iVar11 + 0x24);
    local_70 = 0xf;
    local_6c = 1;
    uVar5 = FUN_800138e4(psVar9);
    if (uVar5 == 0) {
      FUN_80013978(psVar9,(uint)&local_70);
    }
    *(undefined *)(iVar11 + 0x34) = 1;
  }
  else {
    if (*(char *)(iVar8 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   puVar4,0x11,0,in_r6,in_r7,in_r8,in_r9,in_r10);
      *(undefined *)(iVar8 + 0x346) = 0;
    }
    *(float *)(iVar8 + 0x2a0) = FLOAT_803e6f98;
    uStack_5c = (uint)*(byte *)(iVar12 + 0x406);
    local_60 = 0x43300000;
    dVar16 = (double)((float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e6f78) /
                     FLOAT_803e6f50);
    if ((*(int *)(iVar11 + 0x18) == 0) && (sVar1 = *(short *)(iVar11 + 0x1c), sVar1 != -1)) {
      local_74 = *(undefined4 *)(iVar11 + 0x30);
      local_78 = *(undefined4 *)(iVar11 + 0x2c);
      psVar9 = *(short **)(iVar11 + 0x24);
      local_7c = *(undefined4 *)(iVar11 + 0x28);
      uVar5 = FUN_800138e4(psVar9);
      if (uVar5 == 0) {
        FUN_80013978(psVar9,(uint)&local_7c);
      }
      psVar9 = *(short **)(iVar11 + 0x24);
      local_88 = 9;
      local_84 = 0;
      local_80 = (int)sVar1;
      uVar5 = FUN_800138e4(psVar9);
      if (uVar5 == 0) {
        FUN_80013978(psVar9,(uint)&local_88);
      }
      *(undefined *)(iVar11 + 0x34) = 1;
      *(undefined2 *)(iVar11 + 0x1c) = 0xffff;
    }
    if ((*(byte *)(iVar11 + 0x44) >> 5 & 1) != 0) {
      FUN_80203064(puVar4,&DAT_8032a33c,(float *)&DAT_8032a34c,4);
    }
    iVar6 = FUN_8002bac4();
    dVar14 = (double)FUN_80021754((float *)(puVar4 + 0xc),(float *)(iVar6 + 0x18));
    uStack_5c = (uint)*(byte *)(iVar12 + 0x406);
    local_60 = 0x43300000;
    fVar2 = (float)(dVar14 - (double)FLOAT_803e6f9c) /
            (FLOAT_803e6fa0 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e6f78));
    fVar3 = FLOAT_803e6f40;
    if ((FLOAT_803e6f40 <= fVar2) && (fVar3 = fVar2, FLOAT_803e6f48 < fVar2)) {
      fVar3 = FLOAT_803e6f48;
    }
    local_58 = (longlong)(int)fVar3;
    FUN_80137cd0();
    iVar12 = FUN_8002bac4();
    puVar13 = (ushort *)0x0;
    dVar14 = (double)FLOAT_803e6f40;
    piVar7 = FUN_80037048(iVar10,local_98);
    for (iVar10 = 0; iVar10 < local_98[0]; iVar10 = iVar10 + 1) {
      if ((*piVar7 != iVar12) &&
         (dVar15 = FUN_80021794((float *)(iVar12 + 0x18),(float *)(*piVar7 + 0x18)), dVar14 < dVar15
         )) {
        puVar13 = (ushort *)*piVar7;
        dVar14 = dVar15;
      }
      piVar7 = piVar7 + 1;
    }
    if (((puVar13 != (ushort *)0x0) && (FUN_80293900(dVar14), puVar13 != puVar4)) &&
       (puVar13[0x23] == 0x539)) {
      *(ushort **)(iVar8 + 0x2d0) = puVar13;
      uVar5 = FUN_80022264(0,(int)fVar3);
      if (uVar5 == 0) {
        iVar8 = (**(code **)(**(int **)(puVar13 + 0x34) + 0x24))
                          (puVar13,0x82,*(undefined4 *)(iVar11 + 0x18));
        if (iVar8 != 0) {
          *(undefined4 *)(iVar11 + 0x3c) = 0;
          psVar9 = *(short **)(iVar11 + 0x24);
          local_98[1] = 10;
          local_98[2] = 1;
          local_8c = puVar13;
          uVar5 = FUN_800138e4(psVar9);
          if (uVar5 == 0) {
            FUN_80013978(psVar9,(uint)(local_98 + 1));
          }
          *(undefined *)(iVar11 + 0x34) = 1;
        }
      }
      else {
        FUN_802032b0((double)FLOAT_803e6fa4,dVar16,(double)FLOAT_803e6f64,dVar17,puVar4,(int)puVar13
                    );
      }
    }
  }
  FUN_80286880();
  return;
}

