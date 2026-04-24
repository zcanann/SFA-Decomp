// Function: FUN_80185b74
// Entry: 80185b74
// Size: 1880 bytes

/* WARNING: Removing unreachable block (ram,0x801862ac) */

void FUN_80185b74(void)

{
  char cVar1;
  float fVar2;
  int iVar3;
  undefined2 *puVar4;
  int iVar5;
  uint uVar6;
  undefined uVar7;
  int iVar8;
  int *piVar9;
  int iVar10;
  undefined4 uVar11;
  undefined8 uVar12;
  double dVar13;
  undefined8 in_f31;
  undefined auStack152 [4];
  float local_94;
  undefined auStack144 [8];
  undefined4 local_88;
  undefined auStack120 [8];
  undefined4 local_70;
  undefined auStack96 [8];
  undefined4 local_58;
  undefined2 local_48;
  undefined2 local_46;
  undefined2 local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  double local_30;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar3 = FUN_802860dc();
  iVar10 = *(int *)(iVar3 + 0x4c);
  local_94 = FLOAT_803e3a5c;
  (**(code **)(*DAT_803dca58 + 0x18))(&local_94);
  piVar9 = *(int **)(iVar3 + 0xb8);
  puVar4 = (undefined2 *)FUN_8002b9ec();
  iVar8 = *(int *)(puVar4 + 0x5c);
  uVar12 = FUN_80021704(puVar4 + 0xc,iVar3 + 0x18);
  if (*(short *)((int)piVar9 + 0x1a) < 1) {
    *(undefined2 *)(piVar9 + 4) = 1;
    *(undefined *)((int)piVar9 + 0x23) = 0;
    *(byte *)(iVar3 + 0xaf) = *(byte *)(iVar3 + 0xaf) | 8;
    fVar2 = FLOAT_803e3a58;
    *(float *)(iVar3 + 0x24) = FLOAT_803e3a58;
    *(float *)(iVar3 + 0x2c) = fVar2;
  }
  if (*(short *)((int)piVar9 + 0x1e) != 0) {
    FUN_8000bb18(iVar3,0x70);
    *(ushort *)((int)piVar9 + 0x1e) = *(short *)((int)piVar9 + 0x1e) - (ushort)DAT_803db410;
    iVar5 = FUN_800221a0(0,2);
    if (iVar5 == 2) {
      (**(code **)(*DAT_803dca88 + 8))(iVar3,0x51c,0,1,0xffffffff,0);
    }
    if (*(short *)((int)piVar9 + 0x1e) < 1) {
      FUN_80185868(uVar12,iVar3);
      goto LAB_801862ac;
    }
  }
  if (*piVar9 != 0) {
    local_30 = (double)(longlong)(int)(FLOAT_803db414 * local_94);
    *piVar9 = *piVar9 - (int)(short)(int)(FLOAT_803db414 * local_94);
    if (*piVar9 < 1) {
      *piVar9 = 0;
      *(undefined2 *)(piVar9 + 4) = 0;
      FUN_80035f20(iVar3);
      *(byte *)(iVar3 + 0xaf) = *(byte *)(iVar3 + 0xaf) & 0xf7;
      *(undefined4 *)(iVar3 + 0xf4) = 0;
    }
    goto LAB_801862ac;
  }
  if (*(short *)(piVar9 + 4) != 0) {
    FUN_8000b7bc(iVar3,0x40);
    *(ushort *)(piVar9 + 4) = *(short *)(piVar9 + 4) - (ushort)DAT_803db410;
    if (*(short *)(piVar9 + 4) < 1) {
      if (piVar9[1] == 0) {
        *piVar9 = 1;
      }
      else {
        *piVar9 = piVar9[1];
      }
    }
    if (*(short *)(piVar9 + 4) < 0x33) goto LAB_801862ac;
  }
  if (*(char *)((int)piVar9 + 0x23) == '\0') {
    if (*(char *)((int)piVar9 + 0x21) == '\0') {
      iVar8 = (**(code **)(*DAT_803dca50 + 0x3c))();
      uVar7 = 0;
      if (((iVar8 != iVar3) && ((*(byte *)(iVar3 + 0xaf) & 1) != 0)) &&
         (*(int *)(iVar3 + 0xf8) == 0)) {
        FUN_80014b3c(0,0x100);
        FUN_800385e8(iVar3,puVar4,auStack152);
        *(undefined2 *)(piVar9 + 3) = 0x8000;
        *(undefined2 *)((int)piVar9 + 0xe) = 0;
        uVar7 = 1;
      }
      *(undefined *)((int)piVar9 + 0x21) = uVar7;
      if (*(char *)((int)piVar9 + 0x21) != '\0') {
        *(undefined *)((int)piVar9 + 0x22) = 1;
        *(undefined2 *)((int)piVar9 + 0x1e) = 600;
      }
      if (*(int *)(iVar3 + 0xf8) == 0) {
        FUN_80035f20(iVar3);
        *(byte *)(iVar3 + 0xaf) = *(byte *)(iVar3 + 0xaf) & 0xf7;
      }
      *(undefined4 *)(iVar3 + 0x80) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(iVar3 + 0x84) = *(undefined4 *)(iVar3 + 0x14);
      *(undefined4 *)(iVar3 + 0x88) = *(undefined4 *)(iVar3 + 0x14);
    }
    else {
      FUN_80035f00(iVar3);
      *(undefined4 *)(*(int *)(iVar3 + 0x54) + 0x10) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(*(int *)(iVar3 + 0x54) + 0x14) = *(undefined4 *)(iVar3 + 0x10);
      *(undefined4 *)(*(int *)(iVar3 + 0x54) + 0x18) = *(undefined4 *)(iVar3 + 0x14);
      *(byte *)(iVar3 + 0xaf) = *(byte *)(iVar3 + 0xaf) | 8;
      uVar6 = FUN_80014e70(0);
      if ((uVar6 & 0x100) != 0) {
        *(undefined *)((int)piVar9 + 0x22) = 0;
      }
      if (*(char *)((int)piVar9 + 0x22) != '\0') {
        *(undefined2 *)(piVar9 + 4) = 0;
        *piVar9 = 0;
        FUN_800378c4(puVar4,0x100010,iVar3,
                     (int)*(short *)((int)piVar9 + 0xe) << 0x10 |
                     (int)*(short *)(piVar9 + 3) & 0xffffU);
      }
      if (*(int *)(iVar3 + 0xf8) == 1) {
        *(undefined *)((int)piVar9 + 0x21) = 2;
      }
      if (((*(char *)((int)piVar9 + 0x21) == '\x02') && (*(int *)(iVar3 + 0xf8) == 0)) &&
         (puVar4[0x50] != 0x447)) {
        *(undefined *)((int)piVar9 + 0x21) = 0;
        *(undefined *)((int)piVar9 + 0x23) = 1;
        local_3c = FLOAT_803e3a58;
        *(float *)(iVar3 + 0x24) = FLOAT_803e3a58;
        *(float *)(iVar3 + 0x28) = FLOAT_803e3a64 * *(float *)(iVar8 + 0x298) + FLOAT_803e3a60;
        *(float *)(iVar3 + 0x2c) = FLOAT_803e3a6c * *(float *)(iVar8 + 0x298) + FLOAT_803e3a68;
        local_38 = local_3c;
        local_34 = local_3c;
        local_40 = FLOAT_803e3a5c;
        local_44 = 0;
        local_46 = 0;
        local_48 = *puVar4;
        FUN_80021ac8(&local_48,iVar3 + 0x24);
        FUN_8000bb18(iVar3,0x6a);
      }
      else if ((*(char *)((int)piVar9 + 0x21) == '\x02') && (*(int *)(iVar3 + 0xf8) == 0)) {
        *(undefined *)((int)piVar9 + 0x21) = 0;
        *(undefined *)((int)piVar9 + 0x23) = 2;
        fVar2 = FLOAT_803e3a58;
        *(float *)(iVar3 + 0x24) = FLOAT_803e3a58;
        *(float *)(iVar3 + 0x28) = fVar2;
        *(float *)(iVar3 + 0x2c) = fVar2;
        FUN_8000bb18(iVar3,0x6a);
      }
    }
  }
  if ((*(char *)((int)piVar9 + 0x23) == '\0') && (*(char *)((int)piVar9 + 0x21) == '\0')) {
    iVar8 = FUN_8003687c(iVar3,0,0,0);
    if (iVar8 != 0) {
      iVar8 = *(int *)(iVar3 + 0xb8);
      local_58 = *(undefined4 *)(iVar8 + 8);
      (**(code **)(*DAT_803ddad4 + 4))(iVar3,0,auStack96,2,0xffffffff,0);
      *(undefined2 *)(iVar8 + 0x1e) = 1;
      goto LAB_801862ac;
    }
  }
  else if (*(char *)((int)piVar9 + 0x23) != '\0') {
    *(ushort *)((int)piVar9 + 0x1a) = *(short *)((int)piVar9 + 0x1a) - (ushort)DAT_803db410;
    if (*(char *)((int)piVar9 + 0x23) == '\x01') {
      FUN_80035df4(iVar3,0xe,3,0);
      if (FLOAT_803e3a70 < *(float *)(iVar3 + 0x28)) {
        *(float *)(iVar3 + 0x28) = FLOAT_803e3a74 * FLOAT_803db414 + *(float *)(iVar3 + 0x28);
      }
      FUN_80035f20(iVar3);
    }
    cVar1 = *(char *)(*(int *)(iVar3 + 0x54) + 0xad);
    if ((cVar1 != '\0') && (*(char *)((int)piVar9 + 0x23) == '\x01')) {
      *(float *)(iVar3 + 0x28) = FLOAT_803e3a58;
      *(undefined *)((int)piVar9 + 0x23) = 0;
      iVar8 = *(int *)(iVar3 + 0xb8);
      local_70 = *(undefined4 *)(iVar8 + 8);
      (**(code **)(*DAT_803ddad4 + 4))(iVar3,0,auStack120,2,0xffffffff,0);
      *(undefined2 *)(iVar8 + 0x1e) = 1;
      goto LAB_801862ac;
    }
    if ((cVar1 != '\0') && (*(char *)((int)piVar9 + 0x23) == '\x02')) {
      *(undefined *)((int)piVar9 + 0x23) = 0;
      iVar8 = *(int *)(iVar3 + 0xb8);
      local_88 = *(undefined4 *)(iVar8 + 8);
      (**(code **)(*DAT_803ddad4 + 4))(iVar3,0,auStack144,2,0xffffffff,0);
      *(undefined2 *)(iVar8 + 0x1e) = 1;
      *(float *)(iVar3 + 0x28) = FLOAT_803e3a58;
      goto LAB_801862ac;
    }
    *(float *)(iVar3 + 0xc) = *(float *)(iVar3 + 0x24) * FLOAT_803db414 + *(float *)(iVar3 + 0xc);
    *(float *)(iVar3 + 0x10) = *(float *)(iVar3 + 0x28) * FLOAT_803db414 + *(float *)(iVar3 + 0x10);
    *(float *)(iVar3 + 0x14) = *(float *)(iVar3 + 0x2c) * FLOAT_803db414 + *(float *)(iVar3 + 0x14);
  }
  *(undefined4 *)(iVar3 + 0x18) = *(undefined4 *)(iVar3 + 0xc);
  *(undefined4 *)(iVar3 + 0x1c) = *(undefined4 *)(iVar3 + 0x10);
  *(undefined4 *)(iVar3 + 0x20) = *(undefined4 *)(iVar3 + 0x14);
  *(ushort *)((int)piVar9 + 0x16) = *(short *)((int)piVar9 + 0x16) - (ushort)DAT_803db410;
  if (*(char *)((int)piVar9 + 0x21) != '\0') {
    dVar13 = (double)FUN_8002166c(iVar3 + 0x18,iVar10 + 8);
    fVar2 = FLOAT_803e3a58;
    local_30 = (double)CONCAT44(0x43300000,
                                (int)*(short *)((int)piVar9 + 0x12) *
                                (int)*(short *)((int)piVar9 + 0x12) ^ 0x80000000);
    if ((double)(float)(local_30 - DOUBLE_803e3a78) <= dVar13) {
      *(float *)(iVar3 + 0x24) = FLOAT_803e3a58;
      *(float *)(iVar3 + 0x2c) = fVar2;
      *(undefined2 *)(piVar9 + 4) = 500;
      *(undefined *)((int)piVar9 + 0x23) = 0;
      *(undefined4 *)(iVar3 + 0xf8) = 0;
      FUN_80035f20(iVar3);
      *(byte *)(iVar3 + 0xaf) = *(byte *)(iVar3 + 0xaf) & 0xf7;
      FUN_80035dac(iVar3);
    }
  }
LAB_801862ac:
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  FUN_80286128();
  return;
}

