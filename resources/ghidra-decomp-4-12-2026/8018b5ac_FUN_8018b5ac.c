// Function: FUN_8018b5ac
// Entry: 8018b5ac
// Size: 1720 bytes

/* WARNING: Removing unreachable block (ram,0x8018bc44) */
/* WARNING: Removing unreachable block (ram,0x8018b6a4) */
/* WARNING: Removing unreachable block (ram,0x8018b5bc) */

void FUN_8018b5ac(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar8;
  int iVar9;
  byte *pbVar10;
  double dVar11;
  undefined8 uVar12;
  double in_f31;
  double in_ps31_1;
  undefined auStack_48 [12];
  float local_3c;
  float local_38;
  float local_34;
  undefined8 local_30;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar3 = FUN_8028683c();
  iVar4 = FUN_8002bac4();
  pbVar10 = *(byte **)(uVar3 + 0xb8);
  iVar9 = *(int *)(uVar3 + 0x4c);
  uVar8 = 0;
  if (iVar4 != 0) {
    uVar8 = FUN_80020078(0x91e);
    if (uVar8 != 0) {
      FUN_800201ac(0x91e,0);
      (**(code **)(*DAT_803dd72c + 0x50))
                (*(undefined *)(iVar9 + 0x1f),*(undefined *)(iVar9 + 0x1a),0);
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,uVar3,0xffffffff);
      FUN_80043604(0,0,1);
      *pbVar10 = 3;
      goto LAB_8018bc44;
    }
    uVar5 = FUN_8004832c((uint)*(byte *)(iVar9 + 0x1f));
    dVar11 = FUN_80021794((float *)(iVar4 + 0x18),(float *)(uVar3 + 0x18));
    uVar8 = FUN_80020078((int)*(short *)(iVar9 + 0x1c));
    bVar1 = *pbVar10;
    if (bVar1 == 2) {
      uVar12 = FUN_800201ac(0x1b8,(int)*(char *)(iVar9 + 0x21));
      if (*(char *)(iVar9 + 0x22) == '\0') {
        uVar7 = 1;
        FUN_80043604(0,0,1);
        uVar6 = FUN_8004832c((int)*(char *)(uVar3 + 0xac));
        FUN_80043658(uVar6,0);
        FUN_80043658(uVar5 & 0xff,1);
      }
      else {
        uVar7 = 1;
        FUN_80043604(0,0,1);
        FUN_80043658((uint)*(byte *)(iVar9 + 0x1e),0);
        FUN_80043658((uint)*(byte *)(iVar9 + 0x1e),1);
      }
      if (*(char *)(uVar3 + 0xac) == '\r') {
        uVar12 = FUN_800201ac(0xe05,0);
      }
      FUN_80055464(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)*(char *)(iVar9 + 0x20),'\0',uVar7,in_r6,in_r7,in_r8,in_r9,in_r10);
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        iVar2 = (uint)*(byte *)(iVar9 + 0x19) * 2;
        local_30 = (double)CONCAT44(0x43300000,iVar2 * iVar2 ^ 0x80000000);
        if (dVar11 < (double)(float)(local_30 - DOUBLE_803e4908)) {
          if (*(char *)(iVar9 + 0x22) == '\0') {
            FUN_80043070(DOUBLE_803e4908,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (uint)*(byte *)(iVar9 + 0x1f));
          }
          *pbVar10 = 1;
        }
      }
      else {
        iVar2 = (uint)*(byte *)(iVar9 + 0x18) * 2;
        local_30 = (double)CONCAT44(0x43300000,iVar2 * iVar2 ^ 0x80000000);
        if (dVar11 <= (double)(float)(local_30 - DOUBLE_803e4908)) {
          if ((dVar11 < (double)FLOAT_803e48c8) && (uVar8 != 0)) {
            *pbVar10 = 2;
            (**(code **)(*DAT_803dd72c + 0x50))
                      (*(undefined *)(iVar9 + 0x1f),*(undefined *)(iVar9 + 0x1a),1);
            (**(code **)(*DAT_803dd72c + 0x44))
                      (*(undefined *)(iVar9 + 0x1f),*(undefined *)(iVar9 + 0x1b));
            (**(code **)(*DAT_803dd6d4 + 0x48))(0,uVar3,0xffffffff);
            (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
          }
        }
        else {
          if (*(char *)(iVar9 + 0x22) == '\0') {
            FUN_80043938(DOUBLE_803e4908,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          }
          *pbVar10 = 0;
        }
      }
    }
    else if ((bVar1 < 4) && ((double)FLOAT_803e48c8 < dVar11)) {
      *pbVar10 = 1;
    }
    bVar1 = pbVar10[1];
    if ((bVar1 & 4) == 0) {
      if (dVar11 < (double)FLOAT_803e48cc) {
        if ((bVar1 & 2) == 0) {
          if ((bVar1 & 1) == 0) {
            if (dVar11 < (double)FLOAT_803e48cc) {
              FUN_80014acc((double)FLOAT_803e48dc);
              if ((iVar4 != 0) && (iVar4 = FUN_80296e2c(iVar4), iVar4 != 0)) {
                FUN_8016de98(iVar4,5,2);
              }
              pbVar10[1] = pbVar10[1] | 1;
              *(float *)(pbVar10 + 8) = *(float *)(pbVar10 + 8) + FLOAT_803dc074;
            }
          }
          else {
            if ((double)FLOAT_803e48d4 <= dVar11) {
              if ((double)FLOAT_803e48d8 <= dVar11) {
                FUN_80014a54();
                if ((iVar4 != 0) && (iVar4 = FUN_80296e2c(iVar4), iVar4 != 0)) {
                  FUN_8016de98(iVar4,5,0);
                }
                pbVar10[2] = 1;
              }
              else if (pbVar10[2] == 1) {
                FUN_80014a90();
                if ((iVar4 != 0) && (iVar4 = FUN_80296e2c(iVar4), iVar4 != 0)) {
                  FUN_8016de98(iVar4,5,0);
                }
                pbVar10[2] = 0;
              }
              else {
                FUN_80014a54();
                if ((iVar4 != 0) && (iVar4 = FUN_80296e2c(iVar4), iVar4 != 0)) {
                  FUN_8016de98(iVar4,5,0);
                }
                pbVar10[2] = 1;
              }
            }
            else {
              FUN_80014a90();
              if ((iVar4 != 0) && (iVar4 = FUN_80296e2c(iVar4), iVar4 != 0)) {
                FUN_8016de98(iVar4,5,0);
              }
              pbVar10[2] = 0;
            }
            pbVar10[1] = pbVar10[1] & 0xfe;
            *(float *)(pbVar10 + 8) = *(float *)(pbVar10 + 8) + FLOAT_803dc074;
          }
          if (FLOAT_803e48e0 < *(float *)(pbVar10 + 8)) {
            pbVar10[1] = pbVar10[1] | 2;
          }
        }
      }
      else {
        *(float *)(pbVar10 + 8) = FLOAT_803e48d0;
        pbVar10[1] = pbVar10[1] & 0xfd;
        if ((iVar4 != 0) && (iVar4 = FUN_80296e2c(iVar4), iVar4 != 0)) {
          FUN_8016de98(iVar4,5,0);
        }
      }
    }
  }
  if (uVar8 == 0) {
    *(undefined *)(uVar3 + 0x36) = 0;
  }
  else {
    if (FLOAT_803e48d0 == *(float *)(pbVar10 + 4)) {
      FUN_8000bb38(uVar3,0x4a2);
    }
    *(float *)(pbVar10 + 4) = *(float *)(pbVar10 + 4) + FLOAT_803dc074;
    if (*(float *)(pbVar10 + 4) <= FLOAT_803e48e4) {
      iVar4 = (int)(FLOAT_803e48e8 * (*(float *)(pbVar10 + 4) / FLOAT_803e48e4));
      local_30 = (double)(longlong)iVar4;
      *(char *)(uVar3 + 0x36) = (char)iVar4;
    }
    else {
      *(float *)(pbVar10 + 4) = FLOAT_803e48e4;
      *(undefined *)(uVar3 + 0x36) = 0xff;
    }
  }
  if (*(char *)(uVar3 + 0x36) != '\0') {
    local_3c = FLOAT_803e48d0;
    local_38 = FLOAT_803e48ec;
    local_34 = FLOAT_803e48d0;
    if ((pbVar10[1] & 8) == 0) {
      FUN_800979c0((double)FLOAT_803e48f0,(double)FLOAT_803e48f4,(double)FLOAT_803e48f8,
                   (double)FLOAT_803e48fc,uVar3,1,2,2,0x32,(int)auStack_48,0);
      local_38 = FLOAT_803e4900;
      dVar11 = (double)FLOAT_803e4904;
      FUN_800979c0((double)FLOAT_803e48f0,dVar11,dVar11,dVar11,uVar3,5,2,2,0x14,(int)auStack_48,0);
    }
    else {
      FUN_800979c0((double)FLOAT_803e48f0,(double)FLOAT_803e48f4,(double)FLOAT_803e48f8,
                   (double)FLOAT_803e48fc,uVar3,1,5,2,0x32,(int)auStack_48,0);
      local_38 = FLOAT_803e4900;
      dVar11 = (double)FLOAT_803e4904;
      FUN_800979c0((double)FLOAT_803e48f0,dVar11,dVar11,dVar11,uVar3,5,5,2,0x14,(int)auStack_48,0);
    }
  }
LAB_8018bc44:
  FUN_80286888();
  return;
}

