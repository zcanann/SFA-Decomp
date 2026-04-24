// Function: FUN_801574b0
// Entry: 801574b0
// Size: 1364 bytes

/* WARNING: Removing unreachable block (ram,0x801579e4) */
/* WARNING: Removing unreachable block (ram,0x801574c0) */

void FUN_801574b0(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  bool bVar2;
  ushort *puVar3;
  uint uVar4;
  uint uVar5;
  undefined4 uVar6;
  int iVar7;
  short sVar8;
  char cVar9;
  int iVar10;
  undefined4 in_r8;
  uint uVar11;
  undefined4 in_r9;
  undefined4 uVar12;
  undefined4 in_r10;
  undefined4 uVar13;
  double dVar14;
  double in_f31;
  double dVar15;
  double in_ps31_1;
  undefined8 uVar16;
  float local_130;
  float local_12c;
  float local_128;
  float local_124;
  float local_120;
  undefined4 local_11c;
  undefined4 local_118;
  undefined4 local_114;
  float local_110;
  float local_10c;
  float local_108;
  undefined4 local_104;
  undefined4 local_100;
  undefined4 local_fc;
  float local_f8;
  float local_f4;
  float local_f0;
  int aiStack_ec [21];
  int aiStack_98 [22];
  undefined8 local_40;
  undefined4 local_38;
  uint uStack_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar16 = FUN_80286840();
  dVar14 = DOUBLE_803e37f0;
  puVar3 = (ushort *)((ulonglong)uVar16 >> 0x20);
  iVar10 = (int)uVar16;
  uStack_34 = (uint)*(byte *)(*(int *)(puVar3 + 0x26) + 0x2f);
  local_40 = (double)CONCAT44(0x43300000,uStack_34);
  local_38 = 0x43300000;
  fVar1 = (float)(local_40 - DOUBLE_803e37f0);
  if (FLOAT_803e37b0 == (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e37f0)) {
    fVar1 = FLOAT_803e37d0;
  }
  dVar15 = (double)(fVar1 / FLOAT_803e37d0);
  *(float *)(iVar10 + 0x324) = *(float *)(iVar10 + 0x324) - FLOAT_803dc074;
  if (*(float *)(iVar10 + 0x324) <= FLOAT_803e37b0) {
    uStack_34 = FUN_80022264(0x3c,0x78);
    uStack_34 = uStack_34 ^ 0x80000000;
    *(float *)(iVar10 + 0x324) = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e37b8);
  }
  local_38 = 0x43300000;
  if (FLOAT_803e37b0 == *(float *)(iVar10 + 0x328)) {
    bVar2 = false;
  }
  else {
    FUN_80035ff8((int)puVar3);
    if (puVar3[0x50] == 5) {
      if ((*(uint *)(iVar10 + 0x2dc) & 0x40000000) != 0) {
        FUN_80036018((int)puVar3);
        *(float *)(iVar10 + 0x328) = FLOAT_803e37b0;
      }
    }
    else {
      FUN_8014d504((double)FLOAT_803dc954,dVar14,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)puVar3,iVar10,5,0,0,in_r8,in_r9,in_r10);
    }
    *(undefined *)(puVar3 + 0x1b) = 0xff;
    bVar2 = true;
  }
  if (!bVar2) {
    *puVar3 = *puVar3 + *(short *)(iVar10 + 0x338);
    local_104 = *(undefined4 *)(puVar3 + 6);
    local_100 = *(undefined4 *)(puVar3 + 8);
    local_fc = *(undefined4 *)(puVar3 + 10);
    FUN_80293580((uint)*puVar3,&local_128,&local_124);
    local_f8 = -(FLOAT_803e37d0 * local_128 - *(float *)(puVar3 + 6));
    local_f4 = FLOAT_803e37d4 + *(float *)(puVar3 + 8);
    local_f0 = -(FLOAT_803e37d0 * local_124 - *(float *)(puVar3 + 10));
    uVar11 = (uint)*(byte *)(iVar10 + 0x261);
    uVar12 = 0xffffffff;
    uVar13 = 0xff;
    uVar4 = FUN_80064248(&local_104,&local_f8,(float *)0x3,aiStack_98,(int *)puVar3,uVar11,
                         0xffffffff,0xff,0);
    uVar4 = countLeadingZeros(uVar4 & 0xff);
    uVar4 = uVar4 >> 5 & 0xff;
    dVar14 = (double)(*(float *)(puVar3 + 10) - *(float *)(*(int *)(iVar10 + 0x29c) + 0x14));
    uVar5 = FUN_80021884();
    uStack_34 = (uVar5 & 0xffff) - (uint)*puVar3 ^ 0x80000000;
    local_38 = 0x43300000;
    fVar1 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e37b8);
    if (FLOAT_803e37c4 < fVar1) {
      fVar1 = FLOAT_803e37c0 + fVar1;
    }
    if (fVar1 < FLOAT_803e37cc) {
      fVar1 = FLOAT_803e37c8 + fVar1;
    }
    local_40 = (double)(longlong)(int)fVar1;
    sVar8 = (short)(int)fVar1;
    uVar5 = (uint)sVar8;
    if ((int)uVar5 < 0) {
      uVar5 = -uVar5;
    }
    uVar5 = uVar5 & 0xffff;
    uVar6 = FUN_8002bac4();
    iVar7 = FUN_802963e8(uVar6);
    if (iVar7 != 0) {
      local_120 = FLOAT_803e37e0;
      iVar7 = FUN_80036f50(0x30,puVar3,&local_120);
      if (iVar7 != 0) {
        iVar7 = FUN_800386e0(puVar3,iVar7,&local_120);
        sVar8 = (short)iVar7;
        if (sVar8 < -300) {
          sVar8 = -300;
        }
        else if (300 < sVar8) {
          sVar8 = 300;
        }
        iVar7 = (int)sVar8;
        *(short *)(iVar10 + 0x338) = sVar8;
        if (iVar7 < 0) {
          iVar7 = -iVar7;
        }
        if (iVar7 < 0x4000) {
          *puVar3 = -*puVar3;
          local_11c = *(undefined4 *)(puVar3 + 6);
          local_118 = *(undefined4 *)(puVar3 + 8);
          local_114 = *(undefined4 *)(puVar3 + 10);
          FUN_80293580((uint)*puVar3,&local_130,&local_12c);
          dVar14 = (double)FLOAT_803e37d0;
          local_110 = -(float)(dVar14 * (double)local_130 - (double)*(float *)(puVar3 + 6));
          local_10c = FLOAT_803e37d4 + *(float *)(puVar3 + 8);
          local_108 = -(float)(dVar14 * (double)local_12c - (double)*(float *)(puVar3 + 10));
          uVar4 = (uint)*(byte *)(iVar10 + 0x261);
          uVar12 = 0xffffffff;
          uVar13 = 0xff;
          cVar9 = FUN_80064248(&local_11c,&local_110,(float *)0x3,aiStack_ec,(int *)puVar3,uVar4,
                               0xffffffff,0xff,0);
          if (cVar9 == '\0') {
            if ((*(uint *)(iVar10 + 0x2dc) & 0x40000000) != 0) {
              FUN_8014d504((double)(FLOAT_803e37d8 / (float)((double)FLOAT_803e37e4 * dVar15)),
                           dVar14,param_3,param_4,param_5,param_6,param_7,param_8,(int)puVar3,iVar10
                           ,7,0,1,uVar4,uVar12,uVar13);
            }
            puVar3[1] = *(ushort *)(iVar10 + 0x19c);
            puVar3[2] = *(ushort *)(iVar10 + 0x19e);
          }
          *puVar3 = -*puVar3;
        }
        goto LAB_801579e4;
      }
    }
    if ((*(int *)(iVar10 + 0x29c) != 0) &&
       (FLOAT_803e37e8 < *(float *)(*(int *)(iVar10 + 0x29c) + 0xa8))) {
      *(float *)(iVar10 + 0x2ac) = FLOAT_803dc950;
    }
    if ((((*(uint *)(iVar10 + 0x2dc) & 0x40000000) != 0) || (uVar4 == 0)) ||
       ((uVar5 < 3000 && ((uVar4 != 0 && (puVar3[0x50] != 0)))))) {
      if ((uVar4 == 0) || (2999 < uVar5)) {
        FUN_8014d504((double)(float)((double)FLOAT_803e37dc / dVar15),dVar14,param_3,param_4,param_5
                     ,param_6,param_7,param_8,(int)puVar3,iVar10,1,0,0,uVar11,uVar12,uVar13);
        fVar1 = FLOAT_803e37b0;
        *(float *)(puVar3 + 0x12) = FLOAT_803e37b0;
        *(float *)(puVar3 + 0x14) = fVar1;
        *(float *)(puVar3 + 0x16) = fVar1;
        if (uVar5 < 3000) {
          uVar4 = FUN_80022264(0,1);
          *(short *)(iVar10 + 0x338) = ((short)uVar4 + -1) * 300;
        }
        else if (sVar8 < 0) {
          *(undefined2 *)(iVar10 + 0x338) = 0xfed4;
        }
        else {
          *(undefined2 *)(iVar10 + 0x338) = 300;
        }
      }
      else {
        *(undefined2 *)(iVar10 + 0x338) = 0;
        FUN_8014d504((double)(float)((double)FLOAT_803e37d8 / dVar15),dVar14,param_3,param_4,param_5
                     ,param_6,param_7,param_8,(int)puVar3,iVar10,0,0,1,uVar11,uVar12,uVar13);
      }
    }
    puVar3[1] = *(ushort *)(iVar10 + 0x19c);
    puVar3[2] = *(ushort *)(iVar10 + 0x19e);
  }
LAB_801579e4:
  FUN_8028688c();
  return;
}

