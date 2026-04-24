// Function: FUN_8016c004
// Entry: 8016c004
// Size: 780 bytes

/* WARNING: Removing unreachable block (ram,0x8016c13c) */

void FUN_8016c004(void)

{
  byte bVar1;
  short sVar2;
  uint uVar3;
  byte bVar4;
  int iVar5;
  uint uVar6;
  undefined4 *puVar7;
  int iVar8;
  char unaff_r27;
  int iVar9;
  int iVar10;
  double dVar11;
  undefined auStack_28 [4];
  uint local_24 [9];
  
  iVar5 = FUN_80286838();
  iVar10 = *(int *)(iVar5 + 0x4c);
  if (((((int)*(short *)(iVar10 + 0x20) == 0xffffffff) ||
       (uVar6 = FUN_80020078((int)*(short *)(iVar10 + 0x20)), uVar6 != 0)) &&
      (((int)*(short *)(iVar10 + 0x1e) == 0xffffffff ||
       (uVar6 = FUN_80020078((int)*(short *)(iVar10 + 0x1e)), uVar6 == 0)))) &&
     (puVar7 = FUN_80037048(3,(int *)local_24), 0 < (int)local_24[0])) {
    iVar9 = CONCAT22(*(undefined2 *)(iVar10 + 0x1c),*(undefined2 *)(iVar10 + 0x1a));
    for (uVar6 = 0; (int)(uVar6 & 0xffff) < (int)local_24[0]; uVar6 = uVar6 + 1) {
      uVar3 = uVar6 & 0xffff;
      iVar8 = *(int *)(puVar7[uVar3] + 0x4c);
      if (iVar8 == 0) {
        unaff_r27 = '\x01';
      }
      else {
        unaff_r27 = '\0';
        if ((iVar9 == *(int *)(iVar8 + 0x14)) || (iVar9 == 0)) {
          unaff_r27 = '\x01';
        }
      }
      if (unaff_r27 != '\0') {
        unaff_r27 = '\0';
        dVar11 = FUN_80021794((float *)(iVar5 + 0x18),(float *)(puVar7[uVar3] + 0x18));
        if (dVar11 < (double)FLOAT_803e3ebc) {
          if (*(int *)(iVar5 + 0xf4) == 0) {
            uVar6 = FUN_80022264(1,100);
            if ((int)uVar6 <= (int)*(char *)(iVar10 + 0x19)) {
              bVar1 = *(byte *)(iVar10 + 0x18);
              bVar4 = (char)(bVar1 & 0x30) >> 4;
              if (bVar4 == 1) {
                iVar8 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_28);
                if (iVar8 == 0) {
                  bVar1 = *(byte *)(iVar10 + 0x18);
                  iVar8 = puVar7[uVar3];
                  if ((int)*(short *)(iVar10 + 0x1e) != 0xffffffff) {
                    FUN_800201ac((int)*(short *)(iVar10 + 0x1e),1);
                  }
                  sVar2 = *(short *)(iVar8 + 0x46);
                  if (sVar2 < 0x5b7) {
                    if ((sVar2 == 0x13a) || ((sVar2 < 0x13a && (sVar2 == 0x11)))) {
LAB_8016c228:
                      FUN_80150950(iVar8,bVar1 & 0xf);
                    }
                  }
                  else if ((sVar2 == 0x5e1) || ((sVar2 < 0x5e1 && (sVar2 < 0x5ba))))
                  goto LAB_8016c228;
                }
              }
              else if (bVar4 == 0) {
                iVar8 = puVar7[uVar3];
                if ((int)*(short *)(iVar10 + 0x1e) != 0xffffffff) {
                  FUN_800201ac((int)*(short *)(iVar10 + 0x1e),1);
                }
                sVar2 = *(short *)(iVar8 + 0x46);
                if (sVar2 < 0x5b7) {
                  if ((sVar2 == 0x13a) || ((sVar2 < 0x13a && (sVar2 == 0x11)))) {
LAB_8016c1a0:
                    FUN_80150950(iVar8,bVar1 & 0xf);
                  }
                }
                else if ((sVar2 == 0x5e1) || ((sVar2 < 0x5e1 && (sVar2 < 0x5ba))))
                goto LAB_8016c1a0;
              }
              else if ((bVar4 < 3) &&
                      (iVar8 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_28), iVar8 != 0)) {
                bVar1 = *(byte *)(iVar10 + 0x18);
                iVar8 = puVar7[uVar3];
                if ((int)*(short *)(iVar10 + 0x1e) != 0xffffffff) {
                  FUN_800201ac((int)*(short *)(iVar10 + 0x1e),1);
                }
                sVar2 = *(short *)(iVar8 + 0x46);
                if (sVar2 < 0x5b7) {
                  if ((sVar2 == 0x13a) || ((sVar2 < 0x13a && (sVar2 == 0x11)))) {
LAB_8016c2b0:
                    FUN_80150950(iVar8,bVar1 & 0xf);
                  }
                }
                else if ((sVar2 == 0x5e1) || ((sVar2 < 0x5e1 && (sVar2 < 0x5ba))))
                goto LAB_8016c2b0;
              }
            }
            *(undefined4 *)(iVar5 + 0xf4) = 1;
          }
          unaff_r27 = '\x01';
        }
        uVar6 = local_24[0] & 0xffff;
      }
    }
    if (unaff_r27 == '\0') {
      *(undefined4 *)(iVar5 + 0xf4) = 0;
    }
  }
  FUN_80286884();
  return;
}

