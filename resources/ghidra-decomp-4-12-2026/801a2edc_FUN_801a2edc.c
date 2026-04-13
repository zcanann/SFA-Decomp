// Function: FUN_801a2edc
// Entry: 801a2edc
// Size: 464 bytes

void FUN_801a2edc(void)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  
  iVar2 = FUN_80286834();
  iVar9 = *(int *)(iVar2 + 0x4c);
  iVar8 = *(int *)(iVar2 + 0xb8);
  iVar7 = (int)*(short *)(iVar9 + 0x1a);
  if (*(int *)(iVar8 + 0xc) == 0) {
    uVar3 = FUN_80020078((int)*(short *)(iVar9 + 0x1e));
    if (uVar3 == 0) {
      iVar11 = 0;
      for (iVar10 = 0; iVar5 = *(int *)(iVar2 + 0x54), iVar10 < *(char *)(iVar5 + 0x71);
          iVar10 = iVar10 + 1) {
        iVar6 = *(int *)(iVar5 + iVar11 + 0x7c);
        bVar1 = false;
        if (*(char *)(iVar5 + iVar10 + 0x75) == '\x05') {
          if (iVar7 == 0) {
            FUN_800201ac((int)*(short *)(iVar9 + 0x1e),1);
            break;
          }
          uVar3 = 0;
          while (uVar3 != *(byte *)(iVar8 + 0x11)) {
            iVar5 = uVar3 * 4;
            uVar3 = uVar3 + 1;
            if (iVar6 == *(int *)(iVar8 + iVar5)) {
              bVar1 = true;
              uVar3 = (uint)*(byte *)(iVar8 + 0x11);
            }
          }
          if (!bVar1) {
            *(int *)(iVar8 + (uint)*(byte *)(iVar8 + 0x11) * 4) = iVar6;
            FUN_800201ac(*(byte *)(iVar8 + 0x11) + 0x2de,0);
            FUN_800201ac(*(byte *)(iVar8 + 0x11) + 0x2df,1);
            if ((int)*(short *)(iVar9 + 0x20) != 0xffffffff) {
              FUN_800201ac((int)*(short *)(iVar9 + 0x20),*(byte *)(iVar8 + 0x11) + 1);
            }
            DAT_803de798 = 300;
            iVar5 = *(byte *)(iVar8 + 0x11) + 1;
            if (iVar7 < iVar5) {
              for (iVar5 = 0; iVar5 < iVar7 + 1; iVar5 = iVar5 + 1) {
                FUN_800201ac(iVar5 + 0x2de,0);
              }
              FUN_800201ac((int)*(short *)(iVar9 + 0x1e),1);
              FUN_801a2d6c(iVar2,(int)*(short *)(iVar9 + 0x1c));
              FUN_8002b95c(iVar2,2);
              *(undefined4 *)(iVar8 + 0xc) = 1;
            }
            else {
              *(char *)(iVar8 + 0x11) = (char)iVar5;
              FUN_8002b95c(iVar2,(uint)*(byte *)(iVar8 + 0x11));
            }
          }
        }
        iVar11 = iVar11 + 4;
      }
    }
    else {
      uVar4 = FUN_801a2d6c(iVar2,(int)*(short *)(iVar9 + 0x1c));
      *(undefined4 *)(iVar8 + 0xc) = uVar4;
    }
  }
  FUN_80286880();
  return;
}

