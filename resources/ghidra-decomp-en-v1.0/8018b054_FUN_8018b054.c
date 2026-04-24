// Function: FUN_8018b054
// Entry: 8018b054
// Size: 1684 bytes

/* WARNING: Removing unreachable block (ram,0x8018b14c) */
/* WARNING: Removing unreachable block (ram,0x8018b6c8) */

void FUN_8018b054(void)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined uVar6;
  undefined4 uVar5;
  int iVar7;
  int iVar8;
  byte *pbVar9;
  undefined4 uVar10;
  double dVar11;
  undefined8 in_f31;
  undefined auStack72 [12];
  float local_3c;
  float local_38;
  float local_34;
  double local_30;
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar3 = FUN_802860d8();
  iVar4 = FUN_8002b9ec();
  pbVar9 = *(byte **)(iVar3 + 0xb8);
  iVar8 = *(int *)(iVar3 + 0x4c);
  iVar7 = 0;
  if (iVar4 != 0) {
    iVar7 = FUN_8001ffb4(0x91e);
    if (iVar7 != 0) {
      FUN_800200e8(0x91e,0);
      (**(code **)(*DAT_803dcaac + 0x50))
                (*(undefined *)(iVar8 + 0x1f),*(undefined *)(iVar8 + 0x1a),0);
      (**(code **)(*DAT_803dca54 + 0x48))(1,iVar3,0xffffffff);
      FUN_8004350c(0,0,1);
      *pbVar9 = 3;
      goto LAB_8018b6c8;
    }
    uVar6 = FUN_800481b0(*(undefined *)(iVar8 + 0x1f));
    dVar11 = (double)FUN_800216d0(iVar4 + 0x18,iVar3 + 0x18);
    iVar7 = FUN_8001ffb4((int)*(short *)(iVar8 + 0x1c));
    bVar1 = *pbVar9;
    if (bVar1 == 2) {
      FUN_800200e8(0x1b8,(int)*(char *)(iVar8 + 0x21));
      if (*(char *)(iVar8 + 0x22) == '\0') {
        FUN_8004350c(0,0,1);
        uVar5 = FUN_800481b0((int)*(char *)(iVar3 + 0xac));
        FUN_80043560(uVar5,0);
        FUN_80043560(uVar6,1);
      }
      else {
        FUN_8004350c(0,0,1);
        FUN_80043560(*(undefined *)(iVar8 + 0x1e),0);
        FUN_80043560(*(undefined *)(iVar8 + 0x1e),1);
      }
      if (*(char *)(iVar3 + 0xac) == '\r') {
        FUN_800200e8(0xe05,0);
      }
      FUN_800552e8((int)*(char *)(iVar8 + 0x20),0);
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        iVar2 = (uint)*(byte *)(iVar8 + 0x19) * 2;
        local_30 = (double)CONCAT44(0x43300000,iVar2 * iVar2 ^ 0x80000000);
        if (dVar11 < (double)(float)(local_30 - DOUBLE_803e3c70)) {
          if (*(char *)(iVar8 + 0x22) == '\0') {
            FUN_80042f78(*(undefined *)(iVar8 + 0x1f));
          }
          *pbVar9 = 1;
        }
      }
      else {
        iVar2 = (uint)*(byte *)(iVar8 + 0x18) * 2;
        local_30 = (double)CONCAT44(0x43300000,iVar2 * iVar2 ^ 0x80000000);
        if (dVar11 <= (double)(float)(local_30 - DOUBLE_803e3c70)) {
          if ((dVar11 < (double)FLOAT_803e3c30) && (iVar7 != 0)) {
            *pbVar9 = 2;
            (**(code **)(*DAT_803dcaac + 0x50))
                      (*(undefined *)(iVar8 + 0x1f),*(undefined *)(iVar8 + 0x1a),1);
            (**(code **)(*DAT_803dcaac + 0x44))
                      (*(undefined *)(iVar8 + 0x1f),*(undefined *)(iVar8 + 0x1b));
            (**(code **)(*DAT_803dca54 + 0x48))(0,iVar3,0xffffffff);
            (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
          }
        }
        else {
          if (*(char *)(iVar8 + 0x22) == '\0') {
            FUN_800437bc(uVar6,0x20000000);
          }
          *pbVar9 = 0;
        }
      }
    }
    else if ((bVar1 < 4) && ((double)FLOAT_803e3c30 < dVar11)) {
      *pbVar9 = 1;
    }
    bVar1 = pbVar9[1];
    if ((bVar1 & 4) == 0) {
      if (dVar11 < (double)FLOAT_803e3c34) {
        if ((bVar1 & 2) == 0) {
          if ((bVar1 & 1) == 0) {
            if (dVar11 < (double)FLOAT_803e3c34) {
              FUN_80014aa0((double)FLOAT_803e3c44);
              if ((iVar4 != 0) && (iVar4 = FUN_802966cc(iVar4), iVar4 != 0)) {
                FUN_8016d9ec(iVar4,5,2);
              }
              pbVar9[1] = pbVar9[1] | 1;
              *(float *)(pbVar9 + 8) = *(float *)(pbVar9 + 8) + FLOAT_803db414;
            }
          }
          else {
            if ((double)FLOAT_803e3c3c <= dVar11) {
              if ((double)FLOAT_803e3c40 <= dVar11) {
                FUN_80014a28();
                if ((iVar4 != 0) && (iVar4 = FUN_802966cc(iVar4), iVar4 != 0)) {
                  FUN_8016d9ec(iVar4,5,0);
                }
                pbVar9[2] = 1;
              }
              else if (pbVar9[2] == 1) {
                FUN_80014a64();
                if ((iVar4 != 0) && (iVar4 = FUN_802966cc(iVar4), iVar4 != 0)) {
                  FUN_8016d9ec(iVar4,5,0);
                }
                pbVar9[2] = 0;
              }
              else {
                FUN_80014a28();
                if ((iVar4 != 0) && (iVar4 = FUN_802966cc(iVar4), iVar4 != 0)) {
                  FUN_8016d9ec(iVar4,5,0);
                }
                pbVar9[2] = 1;
              }
            }
            else {
              FUN_80014a64();
              if ((iVar4 != 0) && (iVar4 = FUN_802966cc(iVar4), iVar4 != 0)) {
                FUN_8016d9ec(iVar4,5,0);
              }
              pbVar9[2] = 0;
            }
            pbVar9[1] = pbVar9[1] & 0xfe;
            *(float *)(pbVar9 + 8) = *(float *)(pbVar9 + 8) + FLOAT_803db414;
          }
          if (FLOAT_803e3c48 < *(float *)(pbVar9 + 8)) {
            pbVar9[1] = pbVar9[1] | 2;
          }
        }
      }
      else {
        *(float *)(pbVar9 + 8) = FLOAT_803e3c38;
        pbVar9[1] = pbVar9[1] & 0xfd;
      }
    }
  }
  if (iVar7 == 0) {
    *(undefined *)(iVar3 + 0x36) = 0;
  }
  else {
    if (FLOAT_803e3c38 == *(float *)(pbVar9 + 4)) {
      FUN_8000bb18(iVar3,0x4a2);
    }
    *(float *)(pbVar9 + 4) = *(float *)(pbVar9 + 4) + FLOAT_803db414;
    if (*(float *)(pbVar9 + 4) <= FLOAT_803e3c4c) {
      iVar4 = (int)(FLOAT_803e3c50 * (*(float *)(pbVar9 + 4) / FLOAT_803e3c4c));
      local_30 = (double)(longlong)iVar4;
      *(char *)(iVar3 + 0x36) = (char)iVar4;
    }
    else {
      *(float *)(pbVar9 + 4) = FLOAT_803e3c4c;
      *(undefined *)(iVar3 + 0x36) = 0xff;
    }
  }
  if (*(char *)(iVar3 + 0x36) != '\0') {
    local_3c = FLOAT_803e3c38;
    local_38 = FLOAT_803e3c54;
    local_34 = FLOAT_803e3c38;
    if ((pbVar9[1] & 8) == 0) {
      FUN_80097734((double)FLOAT_803e3c58,(double)FLOAT_803e3c5c,(double)FLOAT_803e3c60,
                   (double)FLOAT_803e3c64,iVar3,1,2,2,0x32,auStack72,0);
      local_38 = FLOAT_803e3c68;
      dVar11 = (double)FLOAT_803e3c6c;
      FUN_80097734((double)FLOAT_803e3c58,dVar11,dVar11,dVar11,iVar3,5,2,2,0x14,auStack72,0);
    }
    else {
      FUN_80097734((double)FLOAT_803e3c58,(double)FLOAT_803e3c5c,(double)FLOAT_803e3c60,
                   (double)FLOAT_803e3c64,iVar3,1,5,2,0x32,auStack72,0);
      local_38 = FLOAT_803e3c68;
      dVar11 = (double)FLOAT_803e3c6c;
      FUN_80097734((double)FLOAT_803e3c58,dVar11,dVar11,dVar11,iVar3,5,5,2,0x14,auStack72,0);
    }
  }
LAB_8018b6c8:
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  FUN_80286124();
  return;
}

