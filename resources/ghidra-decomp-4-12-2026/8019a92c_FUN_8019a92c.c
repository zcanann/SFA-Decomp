// Function: FUN_8019a92c
// Entry: 8019a92c
// Size: 1264 bytes

/* WARNING: Removing unreachable block (ram,0x8019aabc) */
/* WARNING: Removing unreachable block (ram,0x8019aa3c) */
/* WARNING: Removing unreachable block (ram,0x8019ab50) */

void FUN_8019a92c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,float *param_11,undefined4 param_12,
                 int param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  bool bVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  byte *pbVar8;
  int unaff_r28;
  int iVar9;
  short *psVar10;
  byte *pbVar11;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  undefined8 uVar12;
  float local_28 [10];
  
  iVar4 = FUN_8028683c();
  pbVar11 = *(byte **)(iVar4 + 0xb8);
  psVar10 = *(short **)(iVar4 + 0x4c);
  local_28[0] = FLOAT_803e4d9c;
  if ((psVar10[0x1c] < 1) || (*psVar10 == 0xf4)) {
    uVar12 = extraout_f1;
    iVar5 = FUN_8002bac4();
    if (iVar5 == 0) {
      iVar5 = FUN_8022de2c();
    }
    else {
      iVar6 = FUN_80297a08(iVar5);
      if (iVar6 != 0) {
        iVar5 = iVar6;
      }
    }
    iVar6 = FUN_8002ba84();
    if ((iVar5 != 0) || (iVar6 != 0)) {
      if ((*pbVar11 & 4) == 0) {
        bVar3 = true;
        uVar7 = (uint)*(byte *)((int)psVar10 + 0x43);
        if (uVar7 < 3) {
          if (uVar7 == 1) {
            if (iVar6 == 0) {
              bVar3 = false;
            }
          }
          else if (uVar7 == 0) {
            iVar6 = iVar5;
            if (iVar5 == 0) {
              bVar3 = false;
            }
          }
          else {
            iVar6 = unaff_r28;
            if (uVar7 < 3) {
              iVar6 = (**(code **)(*DAT_803dd6d0 + 0xc))();
              uVar12 = extraout_f1_01;
            }
          }
        }
        else {
          param_11 = local_28;
          iVar6 = FUN_80036f50(uVar7 - 1,iVar4,param_11);
          uVar12 = extraout_f1_00;
          if (iVar6 == 0) {
            bVar3 = false;
          }
        }
        if (bVar3) {
          if ((*pbVar11 & 0x40) == 0) {
            *(undefined4 *)(pbVar11 + 0x1c) = *(undefined4 *)(pbVar11 + 0x28);
            *(undefined4 *)(pbVar11 + 0x20) = *(undefined4 *)(pbVar11 + 0x2c);
            *(undefined4 *)(pbVar11 + 0x24) = *(undefined4 *)(pbVar11 + 0x30);
          }
          else {
            if (*(byte *)((int)psVar10 + 0x43) == 2) {
              *(undefined4 *)(pbVar11 + 0x1c) = *(undefined4 *)(iVar6 + 0x18);
              *(undefined4 *)(pbVar11 + 0x20) = *(undefined4 *)(iVar6 + 0x1c);
              *(undefined4 *)(pbVar11 + 0x24) = *(undefined4 *)(iVar6 + 0x20);
            }
            else if (*(byte *)((int)psVar10 + 0x43) < 2) {
              *(undefined4 *)(pbVar11 + 0x1c) = *(undefined4 *)(iVar6 + 0x8c);
              *(undefined4 *)(pbVar11 + 0x20) = *(undefined4 *)(iVar6 + 0x90);
              *(undefined4 *)(pbVar11 + 0x24) = *(undefined4 *)(iVar6 + 0x94);
            }
            else {
              *(undefined4 *)(pbVar11 + 0x1c) = *(undefined4 *)(iVar6 + 0x80);
              *(undefined4 *)(pbVar11 + 0x20) = *(undefined4 *)(iVar6 + 0x84);
              *(undefined4 *)(pbVar11 + 0x24) = *(undefined4 *)(iVar6 + 0x88);
            }
            *pbVar11 = *pbVar11 & 0xbf;
          }
          if (*(byte *)((int)psVar10 + 0x43) < 3) {
            *(undefined4 *)(pbVar11 + 0x28) = *(undefined4 *)(iVar6 + 0x18);
            *(undefined4 *)(pbVar11 + 0x2c) = *(undefined4 *)(iVar6 + 0x1c);
            *(undefined4 *)(pbVar11 + 0x30) = *(undefined4 *)(iVar6 + 0x20);
          }
          else {
            *(undefined4 *)(pbVar11 + 0x28) = *(undefined4 *)(iVar6 + 0xc);
            *(undefined4 *)(pbVar11 + 0x2c) = *(undefined4 *)(iVar6 + 0x10);
            *(undefined4 *)(pbVar11 + 0x30) = *(undefined4 *)(iVar6 + 0x14);
          }
        }
        sVar1 = *psVar10;
        if (sVar1 == 0x50) {
          uVar12 = FUN_8019992c(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4
                                ,iVar5,1,0,param_13,param_14,param_15,param_16);
          iVar5 = FUN_80020380();
          if (iVar5 != 0) {
            FUN_8002cc9c(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4);
          }
        }
        else if (sVar1 < 0x50) {
          if (sVar1 == 0x4d) {
            if (bVar3) {
              iVar9 = *(int *)(iVar4 + 0xb8);
              iVar5 = FUN_801990e4(iVar4,(float *)(iVar9 + 0x28));
              iVar9 = FUN_801990e4(iVar4,(float *)(iVar9 + 0x1c));
              if (iVar5 == 0) {
                if (iVar9 == 0) {
                  FUN_8019992c(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,
                               iVar6,0xfffffffe,0,param_13,param_14,param_15,param_16);
                }
                else {
                  FUN_8019992c(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,
                               iVar6,0xffffffff,0,param_13,param_14,param_15,param_16);
                }
              }
              else if (iVar9 == 0) {
                FUN_8019992c(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,
                             iVar6,1,0,param_13,param_14,param_15,param_16);
              }
              else {
                FUN_8019992c(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,
                             iVar6,2,0,param_13,param_14,param_15,param_16);
              }
            }
          }
          else if (sVar1 < 0x4d) {
            if (sVar1 == 0x4b) {
              if (bVar3) {
                FUN_80199868(iVar4,iVar6,param_11,param_12,param_13,param_14,param_15,param_16);
              }
            }
            else if (0x4a < sVar1) {
              bVar2 = true;
              if (((int)*(short *)(pbVar11 + 0x82) != 0xffffffff) &&
                 (uVar7 = FUN_80020078((int)*(short *)(pbVar11 + 0x82)), uVar7 == 0)) {
                bVar2 = false;
              }
              if ((bVar2) && (bVar3)) {
                FUN_80199364();
              }
            }
          }
          else if ((sVar1 < 0x4f) &&
                  (*(uint *)(pbVar11 + 8) = *(int *)(pbVar11 + 8) + (uint)DAT_803dc070,
                  (uint)(ushort)psVar10[0x23] <= *(uint *)(pbVar11 + 8))) {
            FUN_8019992c(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,0,1,0,
                         param_13,param_14,param_15,param_16);
          }
        }
        else if (sVar1 == 0xf4) {
          if (bVar3) {
            FUN_80198f7c();
          }
        }
        else if (sVar1 < 0xf4) {
          if (sVar1 == 0x54) {
            bVar3 = true;
            iVar6 = 0;
            pbVar8 = pbVar11;
            while ((iVar6 < 4 && (bVar3))) {
              if (((int)*(short *)(pbVar8 + 0x82) != 0xffffffff) &&
                 (uVar7 = FUN_80020078((int)*(short *)(pbVar8 + 0x82)), uVar7 == 0)) {
                bVar3 = false;
              }
              pbVar8 = pbVar8 + 2;
              iVar6 = iVar6 + 1;
            }
            if ((bVar3) && (-1 < (char)pbVar11[0x8a])) {
              pbVar11[0x8a] = pbVar11[0x8a] & 0x7f | 0x80;
              FUN_8019992c(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,
                           iVar5,1,0,param_13,param_14,param_15,param_16);
            }
            if (!bVar3) {
              pbVar11[0x8a] = pbVar11[0x8a] & 0x7f;
            }
          }
        }
        else if ((sVar1 == 0x230) && (bVar3)) {
          FUN_80199704(iVar4,iVar6,param_11,param_12,param_13,param_14,param_15,param_16);
        }
      }
      else {
        FUN_8019992c(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,iVar5,1,0,
                     param_13,param_14,param_15,param_16);
        *pbVar11 = *pbVar11 & 0xfb;
        *pbVar11 = *pbVar11 | 1;
      }
    }
  }
  FUN_80286888();
  return;
}

