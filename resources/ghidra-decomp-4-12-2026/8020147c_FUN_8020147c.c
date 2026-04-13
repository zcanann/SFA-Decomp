// Function: FUN_8020147c
// Entry: 8020147c
// Size: 1300 bytes

/* WARNING: Removing unreachable block (ram,0x80201970) */
/* WARNING: Removing unreachable block (ram,0x80201968) */
/* WARNING: Removing unreachable block (ram,0x80201494) */
/* WARNING: Removing unreachable block (ram,0x8020148c) */
/* WARNING: Type propagation algorithm not settling */

void FUN_8020147c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  ushort *puVar2;
  uint uVar3;
  int *piVar4;
  int iVar5;
  ushort *puVar6;
  uint *puVar7;
  undefined2 *puVar8;
  undefined4 uVar9;
  int iVar10;
  int in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short *psVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  double extraout_f1;
  double in_f30;
  double dVar17;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar18;
  float local_d8;
  int local_d4;
  int local_d0 [5];
  undefined4 local_bc;
  undefined4 local_b8;
  undefined4 local_b4;
  undefined4 local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  int local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_50;
  uint uStack_4c;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar18 = FUN_80286830();
  puVar2 = (ushort *)((ulonglong)uVar18 >> 0x20);
  iVar10 = (int)uVar18;
  iVar15 = *(int *)(puVar2 + 0x5c);
  iVar16 = *(int *)(iVar15 + 0x40c);
  iVar14 = *(int *)(iVar16 + 0x30);
  *(byte *)(iVar16 + 0x14) = *(byte *)(iVar16 + 0x14) | 2;
  *(byte *)(iVar16 + 0x15) = *(byte *)(iVar16 + 0x15) & 0xfb;
  dVar17 = extraout_f1;
  uVar3 = FUN_80036d04(*(int *)(iVar10 + 0x2d0),iVar14);
  if ((uVar3 == 0) && (FUN_80037048(iVar14,local_d0), local_d0[0] == 0)) {
    local_58 = FUN_8002bac4();
    psVar11 = *(short **)(iVar16 + 0x24);
    local_60 = 0xf;
    local_5c = 1;
    uVar3 = FUN_800138e4(psVar11);
    if (uVar3 == 0) {
      FUN_80013978(psVar11,(uint)&local_60);
    }
    *(undefined *)(iVar16 + 0x34) = 1;
  }
  else {
    iVar12 = *(int *)(iVar10 + 0x2d0);
    bVar1 = false;
    piVar4 = FUN_80037048(3,&local_d4);
    for (iVar13 = 0; iVar13 < local_d4; iVar13 = iVar13 + 1) {
      iVar5 = *piVar4;
      if (*(short *)(iVar5 + 0x46) == 0x539) {
        in_r6 = **(int **)(iVar5 + 0x68);
        iVar5 = (**(code **)(in_r6 + 0x24))(iVar5,0x83,0);
        if (iVar5 == iVar12) {
          bVar1 = true;
        }
      }
      piVar4 = piVar4 + 1;
    }
    if ((bVar1) ||
       (puVar6 = (ushort *)FUN_80036f50(3,*(undefined4 *)(iVar10 + 0x2d0),(float *)0x0),
       puVar2 != puVar6)) {
      iVar16 = *(int *)(iVar15 + 0x40c);
      *(undefined *)(iVar10 + 0x34d) = 0x1f;
      if (*(char *)(iVar10 + 0x27a) != '\0') {
        FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     puVar2,0xf,0,in_r6,in_r7,in_r8,in_r9,in_r10);
        *(undefined *)(iVar10 + 0x346) = 0;
      }
      if ((*(int *)(iVar16 + 0x3c) == 0) ||
         (uVar3 = FUN_80036d04(*(int *)(iVar10 + 0x2d0),iVar14), uVar3 == 0)) {
        uStack_4c = (uint)*(byte *)(iVar15 + 0x406);
        local_50 = 0x43300000;
        FUN_802032b0((double)FLOAT_803e6f4c,
                     (double)((float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e6f78) /
                             FLOAT_803e6f5c),(double)FLOAT_803e6f64,dVar17,puVar2,
                     *(int *)(iVar10 + 0x2d0));
        if ((*(byte *)(iVar16 + 0x44) >> 5 & 1) != 0) {
          FUN_80203064(puVar2,&DAT_8032a35c,(float *)&DAT_8032a36c,4);
        }
        iVar14 = FUN_8002bac4();
        iVar14 = FUN_800386e0(puVar2,iVar14,&local_d8);
        bVar1 = false;
        iVar14 = (int)(short)iVar14;
        if (iVar14 < 0) {
          iVar14 = -iVar14;
        }
        if ((iVar14 < 0x1c71) && (local_d8 < FLOAT_803e6f68)) {
          bVar1 = true;
        }
        if (bVar1) {
          puVar7 = FUN_80039598();
          iVar14 = 1;
          do {
            puVar7 = puVar7 + 1;
            puVar8 = (undefined2 *)FUN_800396d0((int)puVar2,*puVar7);
            if (puVar8 != (undefined2 *)0x0) {
              puVar8[2] = 0;
              *puVar8 = 0;
            }
            iVar14 = iVar14 + 1;
          } while (iVar14 < 9);
          uVar9 = FUN_8002bac4();
          *(undefined4 *)(iVar10 + 0x2d0) = uVar9;
          local_b8 = *(undefined4 *)(iVar16 + 0x30);
          local_bc = *(undefined4 *)(iVar16 + 0x2c);
          psVar11 = *(short **)(iVar16 + 0x24);
          local_d0[4] = *(undefined4 *)(iVar16 + 0x28);
          uVar3 = FUN_800138e4(psVar11);
          if (uVar3 == 0) {
            FUN_80013978(psVar11,(uint)(local_d0 + 4));
          }
          psVar11 = *(short **)(iVar16 + 0x24);
          local_d0[1] = 2;
          local_d0[2] = 0;
          local_d0[3] = 0;
          uVar3 = FUN_800138e4(psVar11);
          if (uVar3 == 0) {
            FUN_80013978(psVar11,(uint)(local_d0 + 1));
          }
          *(undefined *)(iVar16 + 0x34) = 1;
        }
      }
      else {
        local_94 = *(undefined4 *)(iVar16 + 0x30);
        local_98 = *(undefined4 *)(iVar16 + 0x2c);
        psVar11 = *(short **)(iVar16 + 0x24);
        local_9c = *(undefined4 *)(iVar16 + 0x28);
        uVar3 = FUN_800138e4(psVar11);
        if (uVar3 == 0) {
          FUN_80013978(psVar11,(uint)&local_9c);
        }
        psVar11 = *(short **)(iVar16 + 0x24);
        local_a8 = 0xc;
        local_a4 = 0;
        local_a0 = 3;
        uVar3 = FUN_800138e4(psVar11);
        if (uVar3 == 0) {
          FUN_80013978(psVar11,(uint)&local_a8);
        }
        *(undefined *)(iVar16 + 0x34) = 1;
        local_ac = *(undefined4 *)(iVar16 + 0x3c);
        psVar11 = *(short **)(iVar16 + 0x24);
        local_b4 = 0xd;
        local_b0 = 1;
        uVar3 = FUN_800138e4(psVar11);
        if (uVar3 == 0) {
          FUN_80013978(psVar11,(uint)&local_b4);
        }
        *(undefined *)(iVar16 + 0x34) = 1;
      }
    }
    else {
      *(undefined4 *)(iVar16 + 0x3c) = *(undefined4 *)(iVar10 + 0x2d0);
      local_64 = *(undefined4 *)(iVar16 + 0x30);
      local_68 = *(undefined4 *)(iVar16 + 0x2c);
      psVar11 = *(short **)(iVar16 + 0x24);
      local_6c = *(undefined4 *)(iVar16 + 0x28);
      uVar3 = FUN_800138e4(psVar11);
      if (uVar3 == 0) {
        FUN_80013978(psVar11,(uint)&local_6c);
      }
      psVar11 = *(short **)(iVar16 + 0x24);
      local_78 = 0xc;
      local_74 = 0;
      local_70 = 3;
      uVar3 = FUN_800138e4(psVar11);
      if (uVar3 == 0) {
        FUN_80013978(psVar11,(uint)&local_78);
      }
      *(undefined *)(iVar16 + 0x34) = 1;
      psVar11 = *(short **)(iVar16 + 0x24);
      local_84 = 9;
      local_80 = 0;
      local_7c = iVar14;
      uVar3 = FUN_800138e4(psVar11);
      if (uVar3 == 0) {
        FUN_80013978(psVar11,(uint)&local_84);
      }
      *(undefined *)(iVar16 + 0x34) = 1;
      local_88 = *(undefined4 *)(iVar16 + 0x3c);
      psVar11 = *(short **)(iVar16 + 0x24);
      local_90 = 7;
      local_8c = 1;
      uVar3 = FUN_800138e4(psVar11);
      if (uVar3 == 0) {
        FUN_80013978(psVar11,(uint)&local_90);
      }
      *(undefined *)(iVar16 + 0x34) = 1;
    }
  }
  FUN_8028687c();
  return;
}

