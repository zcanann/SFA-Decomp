// Function: FUN_80191f54
// Entry: 80191f54
// Size: 480 bytes

void FUN_80191f54(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined uVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined8 uVar13;
  
  uVar13 = FUN_802860c8();
  iVar3 = (int)((ulonglong)uVar13 >> 0x20);
  iVar8 = (int)uVar13;
  iVar10 = *(int *)(iVar3 + 0x4c);
  FUN_8005b2fc((double)*(float *)(iVar3 + 0xc),(double)*(float *)(iVar3 + 0x10),
               (double)*(float *)(iVar3 + 0x14));
  iVar4 = FUN_8005aeec();
  if (iVar4 == 0) {
    *(undefined *)(iVar8 + 0x10) = 1;
  }
  else {
    iVar5 = FUN_8002e07c(0xe);
    if ((iVar5 != 0) &&
       (iVar10 = FUN_80053ee0(-*(int *)(iVar5 + *(short *)(iVar10 + 0x18) * 4)), iVar10 != 0)) {
      for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(iVar4 + 0xa2); iVar5 = iVar5 + 1) {
        iVar6 = FUN_8006070c(iVar4,iVar5);
        iVar12 = iVar6;
        for (iVar11 = 0; iVar11 < (int)(uint)*(byte *)(iVar6 + 0x41); iVar11 = iVar11 + 1) {
          if (*(int *)(iVar12 + 0x24) == iVar10) {
            iVar1 = (uint)*(ushort *)(iVar10 + 10) << 6;
            iVar2 = (uint)*(ushort *)(iVar10 + 0xc) << 6;
            if (*(char *)(iVar12 + 0x2a) == -1) {
              uVar7 = FUN_80056bf4((int)*(char *)(iVar8 + 0x11),(int)*(char *)(iVar8 + 0x12),iVar1,
                                   iVar2,(int)*(char *)(iVar8 + 0x13),(int)*(char *)(iVar8 + 0x14),
                                   iVar1,iVar2);
              *(undefined *)(iVar12 + 0x2a) = uVar7;
            }
            else {
              iVar9 = *(int *)(*(int *)(iVar3 + 0x4c) + 0x14);
              if ((iVar9 == 0x49b2f) || (iVar9 == 0x49b67)) {
                iVar9 = FUN_8001ffb4(*(undefined4 *)(iVar8 + 8));
                if (iVar9 != 0) {
                  FUN_80056bbc(*(undefined *)(iVar12 + 0x2a),(int)*(char *)(iVar8 + 0x11),
                               (int)*(char *)(iVar8 + 0x12),iVar1,iVar2,(int)*(char *)(iVar8 + 0x13)
                               ,(int)*(char *)(iVar8 + 0x14),iVar1,iVar2);
                }
              }
              else {
                FUN_80056bbc(*(char *)(iVar12 + 0x2a),(int)*(char *)(iVar8 + 0x11),
                             (int)*(char *)(iVar8 + 0x12),iVar1,iVar2,(int)*(char *)(iVar8 + 0x13),
                             (int)*(char *)(iVar8 + 0x14),iVar1,iVar2);
              }
            }
          }
          iVar12 = iVar12 + 8;
        }
      }
    }
  }
  FUN_80286114();
  return;
}

