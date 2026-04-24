// Function: FUN_802160fc
// Entry: 802160fc
// Size: 2424 bytes

void FUN_802160fc(void)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  char cVar7;
  short *psVar8;
  uint uVar9;
  uint *puVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  bool bVar14;
  float local_78;
  undefined4 local_74;
  float local_70;
  float local_6c;
  undefined4 local_68;
  float local_64;
  float afStack_60 [12];
  undefined8 local_30;
  undefined8 local_28;
  
  psVar8 = (short *)FUN_8028683c();
  iVar13 = *(int *)(psVar8 + 0x26);
  iVar12 = *(int *)(psVar8 + 0x5c);
  local_6c = DAT_802c2ce0;
  local_68 = DAT_802c2ce4;
  local_64 = DAT_802c2ce8;
  local_78 = DAT_802c2cec;
  local_74 = DAT_802c2cf0;
  local_70 = DAT_802c2cf4;
  *(undefined4 *)(psVar8 + 0x7c) = *(undefined4 *)(psVar8 + 0x7a);
  uVar9 = FUN_80020078((int)*(short *)(iVar13 + 0x1c));
  *(uint *)(psVar8 + 0x7a) = uVar9;
  puVar10 = (uint *)FUN_800395a4((int)psVar8,0);
  if (*(int *)(psVar8 + 0x7a) < 2) {
    *puVar10 = 0;
    if ((*(int *)(psVar8 + 0x7a) == 0) && (*(int *)(psVar8 + 0x7c) != 0)) {
      *(byte *)(iVar12 + 0x10) = *(byte *)(iVar12 + 0x10) | 4;
    }
    if ((*(int *)(psVar8 + 0x7a) != 0) && (*(int *)(psVar8 + 0x7c) == 0)) {
      *(byte *)(iVar12 + 0x10) = *(byte *)(iVar12 + 0x10) | 2;
      local_30 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar13 + 0x1f));
      *(float *)(psVar8 + 8) = *(float *)(iVar13 + 0xc) - (float)(local_30 - DOUBLE_803e7520);
      uVar9 = FUN_80020078(0x572);
      iVar11 = *(int *)(psVar8 + 0x26);
      iVar11 = (**(code **)(*DAT_803dd71c + 0x14))
                         ((double)*(float *)(iVar11 + 8),(double)*(float *)(iVar11 + 0xc),
                          (double)*(float *)(iVar11 + 0x10),&DAT_803dcf08,1,uVar9 >> 1);
      if ((iVar11 != -1) && (iVar11 = (**(code **)(*DAT_803dd71c + 0x1c))(), iVar11 != 0)) {
        *(undefined4 *)(psVar8 + 6) = *(undefined4 *)(iVar11 + 8);
        *(undefined4 *)(psVar8 + 10) = *(undefined4 *)(iVar11 + 0x10);
      }
    }
    if ((*(byte *)(iVar12 + 0x10) & 6) == 0) goto LAB_80216a5c;
  }
  else if (*(int *)(psVar8 + 0x7c) == 0) {
    *(byte *)(iVar12 + 0x10) = *(byte *)(iVar12 + 0x10) | 2;
    local_30 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar13 + 0x1f));
    *(float *)(psVar8 + 8) = *(float *)(iVar13 + 0xc) - (float)(local_30 - DOUBLE_803e7520);
    uVar9 = FUN_80020078(0x572);
    iVar11 = *(int *)(psVar8 + 0x26);
    iVar11 = (**(code **)(*DAT_803dd71c + 0x14))
                       ((double)*(float *)(iVar11 + 8),(double)*(float *)(iVar11 + 0xc),
                        (double)*(float *)(iVar11 + 0x10),&DAT_803dcf08,1,uVar9 >> 1);
    if ((iVar11 != -1) && (iVar11 = (**(code **)(*DAT_803dd71c + 0x1c))(), iVar11 != 0)) {
      *(undefined4 *)(psVar8 + 6) = *(undefined4 *)(iVar11 + 8);
      *(undefined4 *)(psVar8 + 10) = *(undefined4 *)(iVar11 + 0x10);
    }
  }
  else {
    *puVar10 = 0x100;
    *(byte *)(iVar12 + 0x10) = *(byte *)(iVar12 + 0x10) & 0xfe;
  }
  cVar7 = *(char *)(iVar12 + 4) + -1;
  *(char *)(iVar12 + 4) = cVar7;
  if (cVar7 < '\0') {
    *(undefined *)(iVar12 + 4) = 0;
  }
  if ((('\0' < *(char *)(*(int *)(psVar8 + 0x2c) + 0x10f)) && (*(int *)(psVar8 + 0x7a) == 2)) &&
     (iVar11 = FUN_8002bac4(), iVar11 != 0)) {
    local_30 = (double)CONCAT44(0x43300000,(int)*psVar8 ^ 0x80000000);
    FUN_8024782c((double)(float)((DOUBLE_803e74f8 * (local_30 - DOUBLE_803e7528)) / DOUBLE_803e7500)
                 ,afStack_60,0x79);
    FUN_80247cd8(afStack_60,&local_6c,&local_6c);
    FUN_80247cd8(afStack_60,&local_78,&local_78);
    fVar2 = *(float *)(psVar8 + 6);
    fVar3 = local_78 + fVar2 + local_6c;
    fVar4 = fVar3;
    if (fVar3 < fVar2) {
      fVar4 = fVar2;
      fVar2 = fVar3;
    }
    fVar3 = *(float *)(psVar8 + 10);
    fVar6 = local_70 + fVar3 + local_64;
    fVar5 = fVar6;
    if (fVar6 < fVar3) {
      fVar5 = fVar3;
      fVar3 = fVar6;
    }
    if (((fVar2 + FLOAT_803e7508 <= *(float *)(iVar11 + 0xc)) &&
        (*(float *)(iVar11 + 0xc) <= fVar4 - FLOAT_803e7508)) &&
       ((fVar3 + FLOAT_803e7508 <= *(float *)(iVar11 + 0x14) &&
        (*(float *)(iVar11 + 0x14) <= fVar5 - FLOAT_803e7508)))) {
      *(undefined *)(iVar12 + 4) = 5;
    }
  }
  bVar14 = false;
  bVar1 = *(byte *)(iVar12 + 0x10);
  if ((bVar1 & 4) == 0) {
    if ((bVar1 & 2) == 0) {
      if ((*(char *)(iVar12 + 4) == '\0') || ((bVar1 & 1) != 0)) {
        *(float *)(psVar8 + 8) = FLOAT_803e7510 * FLOAT_803dc074 + *(float *)(psVar8 + 8);
        bVar14 = *(float *)(psVar8 + 8) <= *(float *)(iVar13 + 0xc);
        if (!bVar14) {
          *(float *)(psVar8 + 8) = *(float *)(iVar13 + 0xc);
        }
        if ((*(byte *)(iVar12 + 0x10) & 8) != 0) {
          if (*(float *)(iVar12 + 8) < FLOAT_803e7514) {
            *(byte *)(iVar12 + 0x10) = *(byte *)(iVar12 + 0x10) & 0xf7;
            *(byte *)(iVar12 + 0x10) = *(byte *)(iVar12 + 0x10) | 1;
            FUN_800201ac((int)*(short *)(iVar13 + 0x1a),0);
            uVar9 = FUN_80020078(0x55a);
            if (uVar9 == 0) {
              FUN_800201ac(0x55a,1);
              FUN_800201ac(0x55b,0);
            }
            else {
              FUN_800201ac(0x55a,0);
              FUN_800201ac(0x55b,1);
            }
            FUN_8021239c();
          }
          *(float *)(iVar12 + 8) = *(float *)(iVar12 + 8) - FLOAT_803dc074;
        }
      }
      else {
        local_30 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar13 + 0x1e));
        fVar2 = *(float *)(iVar13 + 0xc) - (float)(local_30 - DOUBLE_803e7520);
        if (fVar2 < *(float *)(psVar8 + 8)) {
          *(float *)(psVar8 + 8) = -(FLOAT_803e7510 * FLOAT_803dc074 - *(float *)(psVar8 + 8));
          if (fVar2 <= *(float *)(psVar8 + 8)) {
            bVar14 = true;
          }
          else {
            *(float *)(psVar8 + 8) = fVar2;
          }
        }
        if (*(float *)(iVar12 + 8) < FLOAT_803e7514) {
          local_30 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar13 + 0x19));
          *(float *)(iVar12 + 8) = (float)(local_30 - DOUBLE_803e7520);
          uVar9 = FUN_80020078((int)*(short *)(iVar13 + 0x1a));
          if ((uVar9 & 0xff) < 0xf) {
            uVar9 = (uVar9 & 0xff) + 1;
            FUN_800201ac((int)*(short *)(iVar13 + 0x1a),uVar9 & 0xff);
            if ((uVar9 & 0xff) == 0xf) {
              *(byte *)(iVar12 + 0x10) = *(byte *)(iVar12 + 0x10) | 8;
            }
          }
          else {
            *(byte *)(iVar12 + 0x10) = *(byte *)(iVar12 + 0x10) & 0xf7;
            *(byte *)(iVar12 + 0x10) = *(byte *)(iVar12 + 0x10) | 1;
            FUN_800201ac((int)*(short *)(iVar13 + 0x1a),0);
            uVar9 = FUN_80020078(0x55a);
            if (uVar9 == 0) {
              FUN_800201ac(0x55a,1);
              FUN_800201ac(0x55b,0);
            }
            else {
              FUN_800201ac(0x55a,0);
              FUN_800201ac(0x55b,1);
            }
            FUN_8021239c();
          }
        }
        *(float *)(iVar12 + 8) = *(float *)(iVar12 + 8) - FLOAT_803dc074;
      }
    }
    else if (*(float *)(psVar8 + 8) < *(float *)(iVar13 + 0xc)) {
      *(float *)(psVar8 + 8) = FLOAT_803e750c * FLOAT_803dc074 + *(float *)(psVar8 + 8);
      if (*(float *)(psVar8 + 8) < *(float *)(iVar13 + 0xc)) {
        bVar14 = true;
        (**(code **)(*DAT_803dd708 + 8))(psVar8,0x488,0,2,0xffffffff,0);
      }
      else {
        *(float *)(psVar8 + 8) = *(float *)(iVar13 + 0xc);
        *(byte *)(iVar12 + 0x10) = *(byte *)(iVar12 + 0x10) & 0xfd;
      }
    }
  }
  else {
    local_30 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar13 + 0x1f));
    fVar2 = *(float *)(iVar13 + 0xc) - (float)(local_30 - DOUBLE_803e7520);
    if (fVar2 < *(float *)(psVar8 + 8)) {
      *(float *)(psVar8 + 8) = -(FLOAT_803e750c * FLOAT_803dc074 - *(float *)(psVar8 + 8));
      if (fVar2 < *(float *)(psVar8 + 8)) {
        bVar14 = true;
        (**(code **)(*DAT_803dd708 + 8))(psVar8,0x488,0,2,0xffffffff,0);
      }
      else {
        *(float *)(psVar8 + 8) = fVar2;
        *(byte *)(iVar12 + 0x10) = *(byte *)(iVar12 + 0x10) & 0xfb;
      }
    }
  }
  if (((*(byte *)(iVar12 + 0x10) & 1) == 0) && (*(char *)(iVar12 + 5) != *(char *)(iVar12 + 4))) {
    FUN_80020078((int)*(short *)(iVar13 + 0x1a));
    FUN_800201ac((int)*(short *)(iVar13 + 0x1a),0);
  }
  if ((bVar14 != false) && (DAT_803de9e0 == 0)) {
    FUN_8000bb38((uint)psVar8,0x85);
  }
  DAT_803de9e0 = (int)bVar14;
  if (*(int *)(psVar8 + 0x7a) == 2) {
    if (*(char *)(iVar12 + 4) == '\0') {
      local_28 = (double)CONCAT44(0x43300000,*puVar10 ^ 0x80000000);
      uVar9 = (uint)(FLOAT_803dc074 * *(float *)(iVar12 + 0xc) + (float)(local_28 - DOUBLE_803e7528)
                    );
      local_30 = (double)(longlong)(int)uVar9;
      if ((int)uVar9 < 0x201) {
        if ((int)uVar9 < 0x100) {
          uVar9 = 0x100;
          *(float *)(iVar12 + 0xc) = FLOAT_803e7514;
        }
      }
      else {
        uVar9 = 0x200 - (uVar9 - 0x200);
        *(float *)(iVar12 + 0xc) = -*(float *)(iVar12 + 0xc);
      }
      *puVar10 = uVar9;
    }
    else {
      if (FLOAT_803e7514 == *(float *)(iVar12 + 0xc)) {
        *(float *)(iVar12 + 0xc) = FLOAT_803e7518;
      }
      fVar2 = *(float *)(iVar12 + 0xc);
      local_30 = (double)CONCAT44(0x43300000,*puVar10 ^ 0x80000000);
      uVar9 = (uint)(FLOAT_803dc074 * fVar2 + (float)(local_30 - DOUBLE_803e7528));
      local_28 = (double)(longlong)(int)uVar9;
      if ((int)uVar9 < 0x201) {
        if ((int)uVar9 < 0x100) {
          uVar9 = 0x200 - uVar9;
          *(float *)(iVar12 + 0xc) = -fVar2;
        }
      }
      else {
        uVar9 = 0x200 - (uVar9 - 0x200);
        *(float *)(iVar12 + 0xc) = -fVar2;
      }
      *puVar10 = uVar9;
    }
    if ((*(byte *)(iVar12 + 0x10) & 6) == 0) {
      (**(code **)(*DAT_803dd708 + 8))(psVar8,0x486,0,2,0xffffffff,0);
    }
  }
  else if (*puVar10 != 0) {
    local_28 = (double)CONCAT44(0x43300000,*puVar10 ^ 0x80000000);
    uVar9 = (uint)(FLOAT_803dc074 * *(float *)(iVar12 + 0xc) + (float)(local_28 - DOUBLE_803e7528));
    local_30 = (double)(longlong)(int)uVar9;
    if ((int)uVar9 < 0x201) {
      if ((int)uVar9 < 0x100) {
        uVar9 = 0;
      }
    }
    else {
      uVar9 = 0x200 - (uVar9 - 0x200);
      *(float *)(iVar12 + 0xc) = -*(float *)(iVar12 + 0xc);
    }
    *puVar10 = uVar9;
  }
  *(undefined *)(iVar12 + 5) = *(undefined *)(iVar12 + 4);
LAB_80216a5c:
  FUN_80286888();
  return;
}

