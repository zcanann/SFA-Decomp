// Function: FUN_801924d0
// Entry: 801924d0
// Size: 480 bytes

void FUN_801924d0(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined8 uVar13;
  
  uVar13 = FUN_8028682c();
  iVar2 = (int)((ulonglong)uVar13 >> 0x20);
  iVar8 = (int)uVar13;
  iVar10 = *(int *)(iVar2 + 0x4c);
  iVar3 = FUN_8005b478((double)*(float *)(iVar2 + 0xc),(double)*(float *)(iVar2 + 0x10));
  iVar3 = FUN_8005b068(iVar3);
  if (iVar3 == 0) {
    *(undefined *)(iVar8 + 0x10) = 1;
  }
  else {
    iVar4 = FUN_8002e174(0xe);
    if ((iVar4 != 0) &&
       (iVar10 = FUN_8005405c(-*(int *)(iVar4 + *(short *)(iVar10 + 0x18) * 4)), iVar10 != 0)) {
      for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(iVar3 + 0xa2); iVar4 = iVar4 + 1) {
        iVar5 = FUN_80060888(iVar3,iVar4);
        iVar12 = iVar5;
        for (iVar11 = 0; iVar11 < (int)(uint)*(byte *)(iVar5 + 0x41); iVar11 = iVar11 + 1) {
          if (*(int *)(iVar12 + 0x24) == iVar10) {
            iVar7 = (uint)*(ushort *)(iVar10 + 10) << 6;
            iVar1 = (uint)*(ushort *)(iVar10 + 0xc) << 6;
            if (*(byte *)(iVar12 + 0x2a) == 0xff) {
              iVar7 = FUN_80056d70((int)*(char *)(iVar8 + 0x11),(int)*(char *)(iVar8 + 0x12),iVar7,
                                   iVar1);
              *(char *)(iVar12 + 0x2a) = (char)iVar7;
            }
            else {
              iVar9 = *(int *)(*(int *)(iVar2 + 0x4c) + 0x14);
              if ((iVar9 == 0x49b2f) || (iVar9 == 0x49b67)) {
                uVar6 = FUN_80020078(*(uint *)(iVar8 + 8));
                if (uVar6 != 0) {
                  FUN_80056d38((uint)*(byte *)(iVar12 + 0x2a),(int)*(char *)(iVar8 + 0x11),
                               (int)*(char *)(iVar8 + 0x12),iVar7,iVar1);
                }
              }
              else {
                FUN_80056d38((uint)*(byte *)(iVar12 + 0x2a),(int)*(char *)(iVar8 + 0x11),
                             (int)*(char *)(iVar8 + 0x12),iVar7,iVar1);
              }
            }
          }
          iVar12 = iVar12 + 8;
        }
      }
    }
  }
  FUN_80286878();
  return;
}

