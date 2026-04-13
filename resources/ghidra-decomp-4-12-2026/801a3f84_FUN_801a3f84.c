// Function: FUN_801a3f84
// Entry: 801a3f84
// Size: 1128 bytes

/* WARNING: Removing unreachable block (ram,0x801a43cc) */
/* WARNING: Removing unreachable block (ram,0x801a43c4) */
/* WARNING: Removing unreachable block (ram,0x801a43bc) */
/* WARNING: Removing unreachable block (ram,0x801a43b4) */
/* WARNING: Removing unreachable block (ram,0x801a43ac) */
/* WARNING: Removing unreachable block (ram,0x801a43a4) */
/* WARNING: Removing unreachable block (ram,0x801a439c) */
/* WARNING: Removing unreachable block (ram,0x801a4394) */
/* WARNING: Removing unreachable block (ram,0x801a3fcc) */
/* WARNING: Removing unreachable block (ram,0x801a3fc4) */
/* WARNING: Removing unreachable block (ram,0x801a3fbc) */
/* WARNING: Removing unreachable block (ram,0x801a3fb4) */
/* WARNING: Removing unreachable block (ram,0x801a3fac) */
/* WARNING: Removing unreachable block (ram,0x801a3fa4) */
/* WARNING: Removing unreachable block (ram,0x801a3f9c) */
/* WARNING: Removing unreachable block (ram,0x801a3f94) */

void FUN_801a3f84(void)

{
  int iVar1;
  char cVar2;
  float fVar3;
  ushort *puVar4;
  uint uVar5;
  int iVar6;
  byte *pbVar7;
  int iVar8;
  int iVar9;
  undefined4 *puVar10;
  double dVar11;
  double in_f24;
  double dVar12;
  double in_f25;
  double dVar13;
  double in_f26;
  double dVar14;
  double in_f27;
  double dVar15;
  double in_f28;
  double in_f29;
  double dVar16;
  double in_f30;
  double in_f31;
  double dVar17;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float local_138;
  float local_134;
  float local_130;
  undefined auStack_12c [12];
  float local_120;
  float local_11c;
  float local_118;
  float afStack_114 [13];
  undefined8 local_e0;
  undefined8 local_d8;
  undefined4 local_d0;
  uint uStack_cc;
  undefined8 local_c8;
  undefined8 local_c0;
  undefined4 local_b8;
  uint uStack_b4;
  float local_78;
  float fStack_74;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
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
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  puVar4 = (ushort *)FUN_80286830();
  fVar3 = FLOAT_803e5028;
  iVar8 = *(int *)(puVar4 + 0x26);
  pbVar7 = *(byte **)(puVar4 + 0x5c);
  *(float *)(puVar4 + 0x16) = FLOAT_803e5028;
  *(float *)(puVar4 + 0x14) = fVar3;
  *(float *)(puVar4 + 0x12) = fVar3;
  uVar5 = FUN_80020078((int)*(short *)(iVar8 + 0x1e));
  if (uVar5 != 0) {
    if ((char)*pbVar7 < '\0') {
      uVar5 = FUN_80020078((int)*(short *)(iVar8 + 0x20));
      *pbVar7 = (byte)((uVar5 & 0xff) << 7) | *pbVar7 & 0x7f;
    }
    else {
      cVar2 = *(char *)(iVar8 + 0x19);
      uVar5 = countLeadingZeros(((uint)(byte)((*(float *)(pbVar7 + 4) == FLOAT_803e5028) << 1) <<
                                0x1c) >> 0x1d ^ 1);
      fVar3 = FLOAT_803e502c;
      if (uVar5 >> 5 == 0) {
        fVar3 = FLOAT_803e5030 * *(float *)(pbVar7 + 4);
      }
      dVar14 = (double)fVar3;
      FUN_8002b554(puVar4,afStack_114,'\0');
      dVar15 = DOUBLE_803e5048;
      local_e0 = (double)CONCAT44(0x43300000,(int)(short)puVar4[2] ^ 0x80000000);
      iVar6 = (int)(FLOAT_803e5034 * FLOAT_803dc074 + (float)(local_e0 - DOUBLE_803e5048));
      local_d8 = (double)(longlong)iVar6;
      puVar4[2] = (ushort)iVar6;
      iVar6 = ((int)cVar2 % 3) * 0x18;
      puVar10 = (undefined4 *)(&DAT_80323b28 + iVar6);
      dVar16 = (double)FLOAT_803e5040;
      dVar17 = (double)FLOAT_803e5038;
      dVar13 = (double)FLOAT_803e5028;
      for (iVar9 = -0x7fff; iVar9 < 0x7fff; iVar9 = iVar9 + *(int *)(&DAT_80323b30 + iVar6)) {
        uVar5 = FUN_80022264(-DAT_803dcafc,DAT_803dcafc);
        local_d8 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        dVar12 = (double)(float)(local_d8 - dVar15);
        iVar1 = (int)(dVar16 * (double)*(float *)(&DAT_80323b3c + iVar6));
        local_e0 = (double)(longlong)iVar1;
        uStack_cc = iVar9 + iVar1 ^ 0x80000000;
        local_d0 = 0x43300000;
        dVar11 = (double)FUN_80294964();
        local_138 = (float)((double)(float)(dVar17 * (double)(float)(dVar14 * (double)FLOAT_803dcaf8
                                                                    )) * dVar11 + dVar12);
        uVar5 = FUN_80022264(-DAT_803dcafc,DAT_803dcafc);
        local_c8 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        dVar12 = (double)(float)(local_c8 - dVar15);
        iVar1 = (int)(dVar16 * (double)*(float *)(&DAT_80323b3c + iVar6));
        local_c0 = (double)(longlong)iVar1;
        uStack_b4 = iVar9 + iVar1 ^ 0x80000000;
        local_b8 = 0x43300000;
        dVar11 = (double)FUN_802945e0();
        local_134 = (float)((double)(float)(dVar17 * (double)(float)(dVar14 * (double)FLOAT_803dcaf8
                                                                    )) * dVar11 + dVar12);
        local_130 = (float)dVar13;
        FUN_80247cd8(afStack_114,&local_138,&local_138);
        local_120 = local_138 + *(float *)(puVar4 + 6);
        local_11c = local_134 + *(float *)(puVar4 + 8);
        local_118 = local_130 + *(float *)(puVar4 + 10);
        (**(code **)(*DAT_803dd708 + 8))
                  (puVar4,*puVar10,auStack_12c,0x200001,0xffffffff,puVar4 + 0x12);
        (**(code **)(*DAT_803dd708 + 8))
                  (puVar4,*puVar10,auStack_12c,0x200001,0xffffffff,puVar4 + 0x12);
        (**(code **)(*DAT_803dd708 + 8))
                  (puVar4,*puVar10,auStack_12c,0x200001,0xffffffff,puVar4 + 0x12);
      }
      uVar5 = FUN_800803dc((float *)(pbVar7 + 4));
      if (uVar5 == 0) {
        uVar5 = FUN_80020078((int)*(short *)(iVar8 + 0x20));
        if (uVar5 != 0) {
          FUN_80080404((float *)(pbVar7 + 4),0x3c);
          FUN_8000bb38((uint)puVar4,0x366);
          if (*(int *)(*(int *)(puVar4 + 0x26) + 0x14) != 0x47f5e) {
            FUN_8000bb38((uint)puVar4,0x409);
          }
        }
      }
      else {
        uStack_b4 = DAT_803dcb00 ^ 0x80000000;
        local_b8 = 0x43300000;
        local_c0 = (double)CONCAT44(0x43300000,(int)(short)puVar4[1] ^ 0x80000000);
        iVar8 = (int)((float)((double)CONCAT44(0x43300000,uStack_b4) - DOUBLE_803e5048) *
                      FLOAT_803dc074 + (float)(local_c0 - DOUBLE_803e5048));
        local_c8 = (double)(longlong)iVar8;
        puVar4[1] = (ushort)iVar8;
        iVar8 = FUN_80080434((float *)(pbVar7 + 4));
        if (iVar8 != 0) {
          *pbVar7 = *pbVar7 & 0x7f | 0x80;
          puVar4[1] = 0;
        }
      }
    }
  }
  FUN_8028687c();
  return;
}

