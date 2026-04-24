// Function: FUN_80215a84
// Entry: 80215a84
// Size: 2424 bytes

void FUN_80215a84(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  char cVar6;
  short *psVar7;
  undefined4 uVar8;
  uint *puVar9;
  uint uVar10;
  int iVar11;
  byte bVar12;
  int iVar13;
  int iVar14;
  bool bVar15;
  float local_78;
  undefined4 local_74;
  float local_70;
  float local_6c;
  undefined4 local_68;
  float local_64;
  undefined auStack96 [48];
  double local_30;
  double local_28;
  
  psVar7 = (short *)FUN_802860d8();
  iVar14 = *(int *)(psVar7 + 0x26);
  iVar13 = *(int *)(psVar7 + 0x5c);
  local_6c = DAT_802c2560;
  local_68 = DAT_802c2564;
  local_64 = DAT_802c2568;
  local_78 = DAT_802c256c;
  local_74 = DAT_802c2570;
  local_70 = DAT_802c2574;
  *(undefined4 *)(psVar7 + 0x7c) = *(undefined4 *)(psVar7 + 0x7a);
  uVar8 = FUN_8001ffb4((int)*(short *)(iVar14 + 0x1c));
  *(undefined4 *)(psVar7 + 0x7a) = uVar8;
  puVar9 = (uint *)FUN_800394ac(psVar7,0,0);
  if (*(int *)(psVar7 + 0x7a) < 2) {
    *puVar9 = 0;
    if ((*(int *)(psVar7 + 0x7a) == 0) && (*(int *)(psVar7 + 0x7c) != 0)) {
      *(byte *)(iVar13 + 0x10) = *(byte *)(iVar13 + 0x10) | 4;
    }
    if ((*(int *)(psVar7 + 0x7a) != 0) && (*(int *)(psVar7 + 0x7c) == 0)) {
      *(byte *)(iVar13 + 0x10) = *(byte *)(iVar13 + 0x10) | 2;
      local_30 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar14 + 0x1f));
      *(float *)(psVar7 + 8) = *(float *)(iVar14 + 0xc) - (float)(local_30 - DOUBLE_803e6888);
      uVar10 = FUN_8001ffb4(0x572);
      iVar11 = *(int *)(psVar7 + 0x26);
      iVar11 = (**(code **)(*DAT_803dca9c + 0x14))
                         ((double)*(float *)(iVar11 + 8),(double)*(float *)(iVar11 + 0xc),
                          (double)*(float *)(iVar11 + 0x10),&DAT_803dc2a0,1,uVar10 >> 1);
      if ((iVar11 != -1) && (iVar11 = (**(code **)(*DAT_803dca9c + 0x1c))(), iVar11 != 0)) {
        *(undefined4 *)(psVar7 + 6) = *(undefined4 *)(iVar11 + 8);
        *(undefined4 *)(psVar7 + 10) = *(undefined4 *)(iVar11 + 0x10);
      }
    }
    if ((*(byte *)(iVar13 + 0x10) & 6) == 0) goto LAB_802163e4;
  }
  else if (*(int *)(psVar7 + 0x7c) == 0) {
    *(byte *)(iVar13 + 0x10) = *(byte *)(iVar13 + 0x10) | 2;
    local_30 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar14 + 0x1f));
    *(float *)(psVar7 + 8) = *(float *)(iVar14 + 0xc) - (float)(local_30 - DOUBLE_803e6888);
    uVar10 = FUN_8001ffb4(0x572);
    iVar11 = *(int *)(psVar7 + 0x26);
    iVar11 = (**(code **)(*DAT_803dca9c + 0x14))
                       ((double)*(float *)(iVar11 + 8),(double)*(float *)(iVar11 + 0xc),
                        (double)*(float *)(iVar11 + 0x10),&DAT_803dc2a0,1,uVar10 >> 1);
    if ((iVar11 != -1) && (iVar11 = (**(code **)(*DAT_803dca9c + 0x1c))(), iVar11 != 0)) {
      *(undefined4 *)(psVar7 + 6) = *(undefined4 *)(iVar11 + 8);
      *(undefined4 *)(psVar7 + 10) = *(undefined4 *)(iVar11 + 0x10);
    }
  }
  else {
    *puVar9 = 0x100;
    *(byte *)(iVar13 + 0x10) = *(byte *)(iVar13 + 0x10) & 0xfe;
  }
  cVar6 = *(char *)(iVar13 + 4) + -1;
  *(char *)(iVar13 + 4) = cVar6;
  if (cVar6 < '\0') {
    *(undefined *)(iVar13 + 4) = 0;
  }
  if ((('\0' < *(char *)(*(int *)(psVar7 + 0x2c) + 0x10f)) && (*(int *)(psVar7 + 0x7a) == 2)) &&
     (iVar11 = FUN_8002b9ec(), iVar11 != 0)) {
    local_30 = (double)CONCAT44(0x43300000,(int)*psVar7 ^ 0x80000000);
    FUN_802470c8((double)(float)((DOUBLE_803e6860 * (local_30 - DOUBLE_803e6890)) / DOUBLE_803e6868)
                 ,auStack96,0x79);
    FUN_80247574(auStack96,&local_6c,&local_6c);
    FUN_80247574(auStack96,&local_78,&local_78);
    fVar1 = *(float *)(psVar7 + 6);
    fVar2 = local_78 + fVar1 + local_6c;
    fVar3 = fVar2;
    if (fVar2 < fVar1) {
      fVar3 = fVar1;
      fVar1 = fVar2;
    }
    fVar2 = *(float *)(psVar7 + 10);
    fVar5 = local_70 + fVar2 + local_64;
    fVar4 = fVar5;
    if (fVar5 < fVar2) {
      fVar4 = fVar2;
      fVar2 = fVar5;
    }
    if (((fVar1 + FLOAT_803e6870 <= *(float *)(iVar11 + 0xc)) &&
        (*(float *)(iVar11 + 0xc) <= fVar3 - FLOAT_803e6870)) &&
       ((fVar2 + FLOAT_803e6870 <= *(float *)(iVar11 + 0x14) &&
        (*(float *)(iVar11 + 0x14) <= fVar4 - FLOAT_803e6870)))) {
      *(undefined *)(iVar13 + 4) = 5;
    }
  }
  bVar15 = false;
  bVar12 = *(byte *)(iVar13 + 0x10);
  if ((bVar12 & 4) == 0) {
    if ((bVar12 & 2) == 0) {
      if ((*(char *)(iVar13 + 4) == '\0') || ((bVar12 & 1) != 0)) {
        *(float *)(psVar7 + 8) = FLOAT_803e6878 * FLOAT_803db414 + *(float *)(psVar7 + 8);
        bVar15 = *(float *)(psVar7 + 8) <= *(float *)(iVar14 + 0xc);
        if (!bVar15) {
          *(float *)(psVar7 + 8) = *(float *)(iVar14 + 0xc);
        }
        if ((*(byte *)(iVar13 + 0x10) & 8) != 0) {
          if (*(float *)(iVar13 + 8) < FLOAT_803e687c) {
            *(byte *)(iVar13 + 0x10) = *(byte *)(iVar13 + 0x10) & 0xf7;
            *(byte *)(iVar13 + 0x10) = *(byte *)(iVar13 + 0x10) | 1;
            FUN_800200e8((int)*(short *)(iVar14 + 0x1a),0);
            iVar11 = FUN_8001ffb4(0x55a);
            if (iVar11 == 0) {
              FUN_800200e8(0x55a,1);
              FUN_800200e8(0x55b,0);
            }
            else {
              FUN_800200e8(0x55a,0);
              FUN_800200e8(0x55b,1);
            }
            FUN_80211d24();
          }
          *(float *)(iVar13 + 8) = *(float *)(iVar13 + 8) - FLOAT_803db414;
        }
      }
      else {
        local_30 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar14 + 0x1e));
        fVar1 = *(float *)(iVar14 + 0xc) - (float)(local_30 - DOUBLE_803e6888);
        if (fVar1 < *(float *)(psVar7 + 8)) {
          *(float *)(psVar7 + 8) = -(FLOAT_803e6878 * FLOAT_803db414 - *(float *)(psVar7 + 8));
          if (fVar1 <= *(float *)(psVar7 + 8)) {
            bVar15 = true;
          }
          else {
            *(float *)(psVar7 + 8) = fVar1;
          }
        }
        if (*(float *)(iVar13 + 8) < FLOAT_803e687c) {
          local_30 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar14 + 0x19));
          *(float *)(iVar13 + 8) = (float)(local_30 - DOUBLE_803e6888);
          bVar12 = FUN_8001ffb4((int)*(short *)(iVar14 + 0x1a));
          if (bVar12 < 0xf) {
            FUN_800200e8((int)*(short *)(iVar14 + 0x1a),bVar12 + 1);
            if ((byte)(bVar12 + 1) == '\x0f') {
              *(byte *)(iVar13 + 0x10) = *(byte *)(iVar13 + 0x10) | 8;
            }
          }
          else {
            *(byte *)(iVar13 + 0x10) = *(byte *)(iVar13 + 0x10) & 0xf7;
            *(byte *)(iVar13 + 0x10) = *(byte *)(iVar13 + 0x10) | 1;
            FUN_800200e8((int)*(short *)(iVar14 + 0x1a),0);
            iVar11 = FUN_8001ffb4(0x55a);
            if (iVar11 == 0) {
              FUN_800200e8(0x55a,1);
              FUN_800200e8(0x55b,0);
            }
            else {
              FUN_800200e8(0x55a,0);
              FUN_800200e8(0x55b,1);
            }
            FUN_80211d24();
          }
        }
        *(float *)(iVar13 + 8) = *(float *)(iVar13 + 8) - FLOAT_803db414;
      }
    }
    else if (*(float *)(psVar7 + 8) < *(float *)(iVar14 + 0xc)) {
      *(float *)(psVar7 + 8) = FLOAT_803e6874 * FLOAT_803db414 + *(float *)(psVar7 + 8);
      if (*(float *)(psVar7 + 8) < *(float *)(iVar14 + 0xc)) {
        bVar15 = true;
        (**(code **)(*DAT_803dca88 + 8))(psVar7,0x488,0,2,0xffffffff,0);
      }
      else {
        *(float *)(psVar7 + 8) = *(float *)(iVar14 + 0xc);
        *(byte *)(iVar13 + 0x10) = *(byte *)(iVar13 + 0x10) & 0xfd;
      }
    }
  }
  else {
    local_30 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar14 + 0x1f));
    fVar1 = *(float *)(iVar14 + 0xc) - (float)(local_30 - DOUBLE_803e6888);
    if (fVar1 < *(float *)(psVar7 + 8)) {
      *(float *)(psVar7 + 8) = -(FLOAT_803e6874 * FLOAT_803db414 - *(float *)(psVar7 + 8));
      if (fVar1 < *(float *)(psVar7 + 8)) {
        bVar15 = true;
        (**(code **)(*DAT_803dca88 + 8))(psVar7,0x488,0,2,0xffffffff,0);
      }
      else {
        *(float *)(psVar7 + 8) = fVar1;
        *(byte *)(iVar13 + 0x10) = *(byte *)(iVar13 + 0x10) & 0xfb;
      }
    }
  }
  if (((*(byte *)(iVar13 + 0x10) & 1) == 0) && (*(char *)(iVar13 + 5) != *(char *)(iVar13 + 4))) {
    FUN_8001ffb4((int)*(short *)(iVar14 + 0x1a));
    FUN_800200e8((int)*(short *)(iVar14 + 0x1a),0);
  }
  if ((bVar15 != false) && (DAT_803ddd60 == 0)) {
    FUN_8000bb18(psVar7,0x85);
  }
  DAT_803ddd60 = (int)bVar15;
  if (*(int *)(psVar7 + 0x7a) == 2) {
    if (*(char *)(iVar13 + 4) == '\0') {
      local_28 = (double)CONCAT44(0x43300000,*puVar9 ^ 0x80000000);
      uVar10 = (uint)(FLOAT_803db414 * *(float *)(iVar13 + 0xc) +
                     (float)(local_28 - DOUBLE_803e6890));
      local_30 = (double)(longlong)(int)uVar10;
      if ((int)uVar10 < 0x201) {
        if ((int)uVar10 < 0x100) {
          uVar10 = 0x100;
          *(float *)(iVar13 + 0xc) = FLOAT_803e687c;
        }
      }
      else {
        uVar10 = 0x200 - (uVar10 - 0x200);
        *(float *)(iVar13 + 0xc) = -*(float *)(iVar13 + 0xc);
      }
      *puVar9 = uVar10;
    }
    else {
      if (FLOAT_803e687c == *(float *)(iVar13 + 0xc)) {
        *(float *)(iVar13 + 0xc) = FLOAT_803e6880;
      }
      fVar1 = *(float *)(iVar13 + 0xc);
      local_30 = (double)CONCAT44(0x43300000,*puVar9 ^ 0x80000000);
      uVar10 = (uint)(FLOAT_803db414 * fVar1 + (float)(local_30 - DOUBLE_803e6890));
      local_28 = (double)(longlong)(int)uVar10;
      if ((int)uVar10 < 0x201) {
        if ((int)uVar10 < 0x100) {
          uVar10 = 0x200 - uVar10;
          *(float *)(iVar13 + 0xc) = -fVar1;
        }
      }
      else {
        uVar10 = 0x200 - (uVar10 - 0x200);
        *(float *)(iVar13 + 0xc) = -fVar1;
      }
      *puVar9 = uVar10;
    }
    if ((*(byte *)(iVar13 + 0x10) & 6) == 0) {
      (**(code **)(*DAT_803dca88 + 8))(psVar7,0x486,0,2,0xffffffff,0);
    }
  }
  else if (*puVar9 != 0) {
    local_28 = (double)CONCAT44(0x43300000,*puVar9 ^ 0x80000000);
    uVar10 = (uint)(FLOAT_803db414 * *(float *)(iVar13 + 0xc) + (float)(local_28 - DOUBLE_803e6890))
    ;
    local_30 = (double)(longlong)(int)uVar10;
    if ((int)uVar10 < 0x201) {
      if ((int)uVar10 < 0x100) {
        uVar10 = 0;
      }
    }
    else {
      uVar10 = 0x200 - (uVar10 - 0x200);
      *(float *)(iVar13 + 0xc) = -*(float *)(iVar13 + 0xc);
    }
    *puVar9 = uVar10;
  }
  *(undefined *)(iVar13 + 5) = *(undefined *)(iVar13 + 4);
LAB_802163e4:
  FUN_80286124();
  return;
}

