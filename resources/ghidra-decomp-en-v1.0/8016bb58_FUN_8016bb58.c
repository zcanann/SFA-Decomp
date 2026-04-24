// Function: FUN_8016bb58
// Entry: 8016bb58
// Size: 780 bytes

/* WARNING: Removing unreachable block (ram,0x8016bc90) */

void FUN_8016bb58(void)

{
  byte bVar1;
  short sVar2;
  byte bVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  char unaff_r27;
  int iVar8;
  uint uVar9;
  int iVar10;
  double dVar11;
  undefined auStack40 [4];
  uint local_24 [9];
  
  iVar4 = FUN_802860d4();
  iVar10 = *(int *)(iVar4 + 0x4c);
  if ((((*(short *)(iVar10 + 0x20) == -1) || (iVar5 = FUN_8001ffb4(), iVar5 != 0)) &&
      ((*(short *)(iVar10 + 0x1e) == -1 || (iVar5 = FUN_8001ffb4(), iVar5 == 0)))) &&
     (iVar5 = FUN_80036f50(3,local_24), 0 < (int)local_24[0])) {
    uVar9 = (int)*(short *)(iVar10 + 0x1c) << 0x10 | (int)*(short *)(iVar10 + 0x1a) & 0xffffU;
    for (uVar7 = 0; (int)(uVar7 & 0xffff) < (int)local_24[0]; uVar7 = uVar7 + 1) {
      iVar8 = (uVar7 & 0xffff) * 4;
      iVar6 = *(int *)(*(int *)(iVar5 + iVar8) + 0x4c);
      if (iVar6 == 0) {
        unaff_r27 = '\x01';
      }
      else {
        unaff_r27 = '\0';
        if ((uVar9 == *(uint *)(iVar6 + 0x14)) || (uVar9 == 0)) {
          unaff_r27 = '\x01';
        }
      }
      if (unaff_r27 != '\0') {
        unaff_r27 = '\0';
        dVar11 = (double)FUN_800216d0(iVar4 + 0x18,*(int *)(iVar5 + iVar8) + 0x18);
        if (dVar11 < (double)FLOAT_803e3224) {
          if (*(int *)(iVar4 + 0xf4) == 0) {
            iVar6 = FUN_800221a0(1,100);
            if (iVar6 <= *(char *)(iVar10 + 0x19)) {
              bVar1 = *(byte *)(iVar10 + 0x18);
              bVar3 = (char)(bVar1 & 0x30) >> 4;
              if (bVar3 == 1) {
                iVar6 = (**(code **)(*DAT_803dca58 + 0x24))(auStack40);
                if (iVar6 == 0) {
                  bVar1 = *(byte *)(iVar10 + 0x18);
                  iVar8 = *(int *)(iVar5 + iVar8);
                  if (*(short *)(iVar10 + 0x1e) != -1) {
                    FUN_800200e8((int)*(short *)(iVar10 + 0x1e),1);
                  }
                  sVar2 = *(short *)(iVar8 + 0x46);
                  if (sVar2 < 0x5b7) {
                    if ((sVar2 == 0x13a) || ((sVar2 < 0x13a && (sVar2 == 0x11)))) {
LAB_8016bd7c:
                      FUN_801504bc(iVar8,bVar1 & 0xf);
                    }
                  }
                  else if ((sVar2 == 0x5e1) || ((sVar2 < 0x5e1 && (sVar2 < 0x5ba))))
                  goto LAB_8016bd7c;
                }
              }
              else if (bVar3 == 0) {
                iVar8 = *(int *)(iVar5 + iVar8);
                if (*(short *)(iVar10 + 0x1e) != -1) {
                  FUN_800200e8((int)*(short *)(iVar10 + 0x1e),1);
                }
                sVar2 = *(short *)(iVar8 + 0x46);
                if (sVar2 < 0x5b7) {
                  if ((sVar2 == 0x13a) || ((sVar2 < 0x13a && (sVar2 == 0x11)))) {
LAB_8016bcf4:
                    FUN_801504bc(iVar8,bVar1 & 0xf);
                  }
                }
                else if ((sVar2 == 0x5e1) || ((sVar2 < 0x5e1 && (sVar2 < 0x5ba))))
                goto LAB_8016bcf4;
              }
              else if ((bVar3 < 3) &&
                      (iVar6 = (**(code **)(*DAT_803dca58 + 0x24))(auStack40), iVar6 != 0)) {
                bVar1 = *(byte *)(iVar10 + 0x18);
                iVar8 = *(int *)(iVar5 + iVar8);
                if (*(short *)(iVar10 + 0x1e) != -1) {
                  FUN_800200e8((int)*(short *)(iVar10 + 0x1e),1);
                }
                sVar2 = *(short *)(iVar8 + 0x46);
                if (sVar2 < 0x5b7) {
                  if ((sVar2 == 0x13a) || ((sVar2 < 0x13a && (sVar2 == 0x11)))) {
LAB_8016be04:
                    FUN_801504bc(iVar8,bVar1 & 0xf);
                  }
                }
                else if ((sVar2 == 0x5e1) || ((sVar2 < 0x5e1 && (sVar2 < 0x5ba))))
                goto LAB_8016be04;
              }
            }
            *(undefined4 *)(iVar4 + 0xf4) = 1;
          }
          unaff_r27 = '\x01';
        }
        uVar7 = local_24[0] & 0xffff;
      }
    }
    if (unaff_r27 == '\0') {
      *(undefined4 *)(iVar4 + 0xf4) = 0;
    }
  }
  FUN_80286120();
  return;
}

