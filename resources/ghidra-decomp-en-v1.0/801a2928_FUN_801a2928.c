// Function: FUN_801a2928
// Entry: 801a2928
// Size: 464 bytes

void FUN_801a2928(void)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  bool bVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  
  iVar1 = FUN_802860d0();
  iVar10 = *(int *)(iVar1 + 0x4c);
  iVar9 = *(int *)(iVar1 + 0xb8);
  iVar8 = (int)*(short *)(iVar10 + 0x1a);
  if (*(int *)(iVar9 + 0xc) == 0) {
    iVar2 = FUN_8001ffb4((int)*(short *)(iVar10 + 0x1e));
    if (iVar2 == 0) {
      iVar11 = 0;
      for (iVar2 = 0; iVar4 = *(int *)(iVar1 + 0x54), iVar2 < *(char *)(iVar4 + 0x71);
          iVar2 = iVar2 + 1) {
        iVar5 = *(int *)(iVar4 + iVar11 + 0x7c);
        bVar7 = false;
        if (*(char *)(iVar4 + iVar2 + 0x75) == '\x05') {
          if (iVar8 == 0) {
            FUN_800200e8((int)*(short *)(iVar10 + 0x1e),1);
            break;
          }
          uVar6 = 0;
          while (uVar6 != *(byte *)(iVar9 + 0x11)) {
            iVar4 = uVar6 * 4;
            uVar6 = uVar6 + 1;
            if (iVar5 == *(int *)(iVar9 + iVar4)) {
              bVar7 = true;
              uVar6 = (uint)*(byte *)(iVar9 + 0x11);
            }
          }
          if (!bVar7) {
            *(int *)(iVar9 + (uint)*(byte *)(iVar9 + 0x11) * 4) = iVar5;
            FUN_800200e8(*(byte *)(iVar9 + 0x11) + 0x2de,0);
            FUN_800200e8(*(byte *)(iVar9 + 0x11) + 0x2df,1);
            if (*(short *)(iVar10 + 0x20) != -1) {
              FUN_800200e8((int)*(short *)(iVar10 + 0x20),*(byte *)(iVar9 + 0x11) + 1);
            }
            DAT_803ddb18 = 300;
            iVar4 = *(byte *)(iVar9 + 0x11) + 1;
            if (iVar8 < iVar4) {
              for (iVar4 = 0; iVar4 < iVar8 + 1; iVar4 = iVar4 + 1) {
                FUN_800200e8(iVar4 + 0x2de,0);
              }
              FUN_800200e8((int)*(short *)(iVar10 + 0x1e),1);
              FUN_801a27b8(iVar1,(int)*(short *)(iVar10 + 0x1c));
              FUN_8002b884(iVar1,2);
              *(undefined4 *)(iVar9 + 0xc) = 1;
            }
            else {
              *(char *)(iVar9 + 0x11) = (char)iVar4;
              FUN_8002b884(iVar1,*(undefined *)(iVar9 + 0x11));
            }
          }
        }
        iVar11 = iVar11 + 4;
      }
    }
    else {
      uVar3 = FUN_801a27b8(iVar1,(int)*(short *)(iVar10 + 0x1c));
      *(undefined4 *)(iVar9 + 0xc) = uVar3;
    }
  }
  FUN_8028611c();
  return;
}

