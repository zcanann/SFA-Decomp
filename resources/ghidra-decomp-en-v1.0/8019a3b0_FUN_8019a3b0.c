// Function: FUN_8019a3b0
// Entry: 8019a3b0
// Size: 1264 bytes

/* WARNING: Removing unreachable block (ram,0x8019a540) */
/* WARNING: Removing unreachable block (ram,0x8019a4c0) */
/* WARNING: Removing unreachable block (ram,0x8019a5d4) */

void FUN_8019a3b0(void)

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
  float local_28 [10];
  
  iVar4 = FUN_802860d8();
  pbVar11 = *(byte **)(iVar4 + 0xb8);
  psVar10 = *(short **)(iVar4 + 0x4c);
  local_28[0] = FLOAT_803e4104;
  if ((psVar10[0x1c] < 1) || (*psVar10 == 0xf4)) {
    iVar5 = FUN_8002b9ec();
    if (iVar5 == 0) {
      iVar5 = FUN_8022d768();
    }
    else {
      iVar6 = FUN_802972a8();
      if (iVar6 != 0) {
        iVar5 = iVar6;
      }
    }
    iVar6 = FUN_8002b9ac();
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
              iVar6 = (**(code **)(*DAT_803dca50 + 0xc))();
            }
          }
        }
        else {
          iVar6 = FUN_80036e58(uVar7 - 1,iVar4,local_28);
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
          FUN_801993b0(iVar4,iVar5,1,0);
          iVar5 = FUN_800202bc();
          if (iVar5 != 0) {
            FUN_8002cbc4(iVar4);
          }
        }
        else if (sVar1 < 0x50) {
          if (sVar1 == 0x4d) {
            if (bVar3) {
              iVar9 = *(int *)(iVar4 + 0xb8);
              iVar5 = FUN_80198b68(iVar4,iVar9 + 0x28);
              iVar9 = FUN_80198b68(iVar4,iVar9 + 0x1c);
              if (iVar5 == 0) {
                if (iVar9 == 0) {
                  FUN_801993b0(iVar4,iVar6,0xfffffffe,0);
                }
                else {
                  FUN_801993b0(iVar4,iVar6,0xffffffff,0);
                }
              }
              else if (iVar9 == 0) {
                FUN_801993b0(iVar4,iVar6,1,0);
              }
              else {
                FUN_801993b0(iVar4,iVar6,2,0);
              }
            }
          }
          else if (sVar1 < 0x4d) {
            if (sVar1 == 0x4b) {
              if (bVar3) {
                FUN_801992ec(iVar4,iVar6);
              }
            }
            else if (0x4a < sVar1) {
              bVar2 = true;
              if ((*(short *)(pbVar11 + 0x82) != -1) && (iVar5 = FUN_8001ffb4(), iVar5 == 0)) {
                bVar2 = false;
              }
              if ((bVar2) && (bVar3)) {
                FUN_80198de8(iVar4,iVar6);
              }
            }
          }
          else if ((sVar1 < 0x4f) &&
                  (*(uint *)(pbVar11 + 8) = *(int *)(pbVar11 + 8) + (uint)DAT_803db410,
                  (uint)(ushort)psVar10[0x23] <= *(uint *)(pbVar11 + 8))) {
            FUN_801993b0(iVar4,0,1,0);
          }
        }
        else if (sVar1 == 0xf4) {
          if (bVar3) {
            FUN_80198a00(iVar4,iVar6);
          }
        }
        else if (sVar1 < 0xf4) {
          if (sVar1 == 0x54) {
            bVar3 = true;
            iVar6 = 0;
            pbVar8 = pbVar11;
            while ((iVar6 < 4 && (bVar3))) {
              if ((*(short *)(pbVar8 + 0x82) != -1) && (iVar9 = FUN_8001ffb4(), iVar9 == 0)) {
                bVar3 = false;
              }
              pbVar8 = pbVar8 + 2;
              iVar6 = iVar6 + 1;
            }
            if ((bVar3) && (-1 < (char)pbVar11[0x8a])) {
              pbVar11[0x8a] = pbVar11[0x8a] & 0x7f | 0x80;
              FUN_801993b0(iVar4,iVar5,1,0);
            }
            if (!bVar3) {
              pbVar11[0x8a] = pbVar11[0x8a] & 0x7f;
            }
          }
        }
        else if ((sVar1 == 0x230) && (bVar3)) {
          FUN_80199188(iVar4,iVar6);
        }
      }
      else {
        FUN_801993b0(iVar4,iVar5,1,0);
        *pbVar11 = *pbVar11 & 0xfb;
        *pbVar11 = *pbVar11 | 1;
      }
    }
  }
  FUN_80286124();
  return;
}

