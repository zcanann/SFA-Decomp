// Function: FUN_80201ddc
// Entry: 80201ddc
// Size: 1076 bytes

/* WARNING: Removing unreachable block (ram,0x802021f0) */
/* WARNING: Removing unreachable block (ram,0x802021e8) */
/* WARNING: Removing unreachable block (ram,0x80201df4) */
/* WARNING: Removing unreachable block (ram,0x80201dec) */
/* WARNING: Type propagation algorithm not settling */

void FUN_80201ddc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  short sVar2;
  ushort *puVar3;
  uint uVar4;
  undefined4 uVar5;
  uint *puVar6;
  undefined2 *puVar7;
  short sVar8;
  int iVar9;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar10;
  short *psVar11;
  int iVar12;
  double extraout_f1;
  double in_f30;
  double dVar13;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar14;
  float local_88 [5];
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  int local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined8 local_50;
  longlong local_48;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar14 = FUN_8028683c();
  puVar3 = (ushort *)((ulonglong)uVar14 >> 0x20);
  iVar9 = (int)uVar14;
  iVar10 = *(int *)(puVar3 + 0x5c);
  iVar12 = *(int *)(iVar10 + 0x40c);
  *(byte *)(iVar12 + 0x14) = *(byte *)(iVar12 + 0x14) | 2;
  *(byte *)(iVar12 + 0x15) = *(byte *)(iVar12 + 0x15) & 0xfb;
  dVar13 = extraout_f1;
  if (*(char *)(iVar9 + 0x27a) != '\0') {
    FUN_80036018((int)puVar3);
    FUN_80035ea4((int)puVar3);
  }
  *(float *)(iVar9 + 0x2a0) = FLOAT_803e6f8c;
  if (*(int *)(iVar12 + 0x18) == 0) {
    sVar2 = *(short *)(iVar12 + 0x1c);
    if (sVar2 != -1) {
      local_58 = *(undefined4 *)(iVar12 + 0x30);
      local_5c = *(undefined4 *)(iVar12 + 0x2c);
      psVar11 = *(short **)(iVar12 + 0x24);
      local_60 = *(undefined4 *)(iVar12 + 0x28);
      uVar4 = FUN_800138e4(psVar11);
      if (uVar4 == 0) {
        FUN_80013978(psVar11,(uint)&local_60);
      }
      psVar11 = *(short **)(iVar12 + 0x24);
      local_6c = 9;
      local_68 = 0;
      local_64 = (int)sVar2;
      uVar4 = FUN_800138e4(psVar11);
      if (uVar4 == 0) {
        FUN_80013978(psVar11,(uint)&local_6c);
      }
      *(undefined *)(iVar12 + 0x34) = 1;
      *(undefined2 *)(iVar12 + 0x1c) = 0xffff;
    }
  }
  else {
    if (*(char *)(iVar9 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   puVar3,0x11,0,in_r6,in_r7,in_r8,in_r9,in_r10);
      *(undefined *)(iVar9 + 0x346) = 0;
    }
    *(float *)(iVar9 + 0x2a0) = FLOAT_803e6f98;
    local_50 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar10 + 0x406));
    in_f31 = (double)((float)(local_50 - DOUBLE_803e6f78) / FLOAT_803e6fbc);
  }
  *(undefined *)(iVar9 + 0x34d) = 0x1f;
  iVar10 = FUN_802032b0((double)FLOAT_803e6f4c,in_f31,(double)FLOAT_803e6f64,dVar13,puVar3,
                        *(int *)(iVar9 + 0x2d0));
  if (iVar10 != 0) {
    *(undefined *)(iVar12 + 0x34) = 1;
  }
  if ((*(byte *)(iVar12 + 0x44) >> 5 & 1) == 0) {
    if (*(int *)(iVar12 + 0x18) == 0) {
      iVar10 = FUN_8002bac4();
      iVar10 = FUN_800386e0(puVar3,iVar10,local_88);
      bVar1 = false;
      iVar10 = (int)(short)iVar10;
      if (iVar10 < 0) {
        iVar10 = -iVar10;
      }
      if ((iVar10 < 0x1c71) && (local_88[0] < FLOAT_803e6f68)) {
        bVar1 = true;
      }
      if (bVar1) {
        puVar6 = FUN_80039598();
        iVar10 = 1;
        do {
          puVar6 = puVar6 + 1;
          puVar7 = (undefined2 *)FUN_800396d0((int)puVar3,*puVar6);
          if (puVar7 != (undefined2 *)0x0) {
            puVar7[2] = 0;
            *puVar7 = 0;
          }
          iVar10 = iVar10 + 1;
        } while (iVar10 < 9);
        uVar5 = FUN_8002bac4();
        *(undefined4 *)(iVar9 + 0x2d0) = uVar5;
        local_70 = *(undefined4 *)(iVar12 + 0x30);
        local_74 = *(undefined4 *)(iVar12 + 0x2c);
        psVar11 = *(short **)(iVar12 + 0x24);
        local_88[4] = *(float *)(iVar12 + 0x28);
        uVar4 = FUN_800138e4(psVar11);
        if (uVar4 == 0) {
          FUN_80013978(psVar11,(uint)(local_88 + 4));
        }
        psVar11 = *(short **)(iVar12 + 0x24);
        local_88[1] = 2.8026e-45;
        local_88[2] = 0.0;
        local_88[3] = 0.0;
        uVar4 = FUN_800138e4(psVar11);
        if (uVar4 == 0) {
          FUN_80013978(psVar11,(uint)(local_88 + 1));
        }
        *(undefined *)(iVar12 + 0x34) = 1;
      }
    }
  }
  else {
    FUN_80203064(puVar3,&DAT_8032a33c,(float *)&DAT_8032a34c,4);
  }
  if ((*(byte *)(iVar12 + 0x44) >> 6 & 1) == 0) {
    if (*(int *)(iVar12 + 0x18) == 0) {
      iVar10 = (int)-(FLOAT_803e6fc0 * *(float *)(iVar9 + 0x280));
      local_50 = (double)(longlong)iVar10;
      iVar12 = (int)-(FLOAT_803e6fc0 * *(float *)(iVar9 + 0x284));
      local_48 = (longlong)iVar12;
      sVar2 = (short)iVar10;
      if (sVar2 < -0x500) {
        sVar2 = -0x500;
      }
      else if (0x500 < sVar2) {
        sVar2 = 0x500;
      }
      sVar8 = (short)iVar12;
      if (sVar8 < -0x500) {
        sVar8 = -0x500;
      }
      else if (0x500 < sVar8) {
        sVar8 = 0x500;
      }
      puVar6 = FUN_80039598();
      iVar10 = 1;
      do {
        puVar6 = puVar6 + 1;
        psVar11 = (short *)FUN_800396d0((int)puVar3,*puVar6);
        if (psVar11 != (short *)0x0) {
          psVar11[2] = sVar8;
          *psVar11 = sVar2;
        }
        iVar10 = iVar10 + 1;
      } while (iVar10 < 9);
    }
  }
  else {
    puVar6 = FUN_80039598();
    iVar10 = 1;
    do {
      puVar6 = puVar6 + 1;
      puVar7 = (undefined2 *)FUN_800396d0((int)puVar3,*puVar6);
      if (puVar7 != (undefined2 *)0x0) {
        puVar7[2] = 0;
        *puVar7 = 0;
      }
      iVar10 = iVar10 + 1;
    } while (iVar10 < 9);
  }
  FUN_8002f6cc((double)*(float *)(iVar9 + 0x280),(int)puVar3,(float *)(iVar9 + 0x2a0));
  FUN_80286888();
  return;
}

