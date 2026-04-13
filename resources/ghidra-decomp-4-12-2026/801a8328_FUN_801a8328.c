// Function: FUN_801a8328
// Entry: 801a8328
// Size: 848 bytes

void FUN_801a8328(undefined4 param_1,undefined4 param_2,uint param_3)

{
  char cVar1;
  undefined4 uVar2;
  char cVar4;
  ushort uVar3;
  int iVar5;
  int iVar6;
  uint uVar7;
  char cVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  double dVar12;
  ulonglong uVar13;
  int local_38;
  int local_34 [13];
  
  uVar13 = FUN_80286830();
  iVar5 = (int)(uVar13 >> 0x20);
  iVar11 = *(int *)(iVar5 + 0xb8);
  iVar6 = FUN_8002e1f4(local_34,&local_38);
  for (; local_34[0] < local_38; local_34[0] = local_34[0] + 1) {
    iVar9 = *(int *)(iVar6 + local_34[0] * 4);
    if (((iVar9 != iVar5) && (*(short *)(iVar9 + 0x46) == 0x518)) &&
       (dVar12 = (double)FUN_800217c8((float *)(iVar5 + 0x18),(float *)(iVar9 + 0x18)),
       dVar12 < (double)FLOAT_803e5218)) {
      iVar10 = *(int *)(*(int *)(iVar6 + local_34[0] * 4) + 0x4c);
      iVar9 = *(int *)(iVar5 + 0x4c);
      uVar7 = FUN_80020078(0x88c);
      cVar4 = (char)uVar7;
      uVar7 = FUN_80020078(0x894);
      cVar8 = (char)uVar7;
      if ((uVar13 & 0xff) == 0) {
        (**(code **)(*DAT_803dd740 + 0x20))(iVar11,1);
        if ((int)*(short *)(iVar10 + 0x1e) != 0xffffffff) {
          FUN_800201ac((int)*(short *)(iVar10 + 0x1e),0);
        }
        cVar1 = *(char *)(iVar11 + 0x2e);
        if (((cVar1 == '\x03') || (cVar1 == '\x04')) || (cVar1 == '\x06')) {
          cVar4 = cVar4 + -1;
        }
        else {
          cVar8 = cVar8 + -1;
        }
        uVar7 = (uint)*(short *)(iVar9 + 0x1a);
        if (uVar7 != 0xffffffff) {
          FUN_800201ac(uVar7,0);
          *(undefined *)(iVar11 + 0x2e) = 0;
        }
        uVar2 = *(undefined4 *)(iVar5 + 0x10);
        *(undefined4 *)(iVar11 + 0xc) = uVar2;
        *(undefined4 *)(iVar11 + 0x10) = uVar2;
        *(ushort *)(iVar11 + 0x24) = *(ushort *)(iVar11 + 0x24) & 0xfbff;
        *(undefined4 *)(iVar5 + 0xc) = *(undefined4 *)(iVar11 + 0x18);
        *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(iVar11 + 0x1c);
        *(undefined4 *)(iVar5 + 0x14) = *(undefined4 *)(iVar11 + 0x20);
        FUN_800e85f4(iVar5);
      }
      else {
        (**(code **)(*DAT_803dd740 + 0x20))(iVar11,0);
        if ((int)*(short *)(iVar10 + 0x1e) != 0xffffffff) {
          FUN_800201ac((int)*(short *)(iVar10 + 0x1e),1);
        }
        if ((param_3 & 0xff) == 0) {
          *(undefined4 *)(iVar5 + 0xc) = *(undefined4 *)(*(int *)(iVar6 + local_34[0] * 4) + 0xc);
          *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(*(int *)(iVar6 + local_34[0] * 4) + 0x10);
          *(undefined4 *)(iVar5 + 0x14) = *(undefined4 *)(*(int *)(iVar6 + local_34[0] * 4) + 0x14);
          FUN_800e85f4(iVar5);
        }
        uVar2 = *(undefined4 *)(iVar5 + 0x10);
        *(undefined4 *)(iVar11 + 0xc) = uVar2;
        *(undefined4 *)(iVar11 + 0x10) = uVar2;
        uVar7 = (uint)*(short *)(iVar9 + 0x1a);
        if (uVar7 != 0xffffffff) {
          FUN_800201ac(uVar7,(int)*(short *)(iVar10 + 0x1a));
          *(char *)(iVar11 + 0x2e) = (char)*(undefined2 *)(iVar10 + 0x1a);
        }
        cVar1 = *(char *)(iVar11 + 0x2e);
        if (((cVar1 == '\x03') || (cVar1 == '\x04')) || (cVar1 == '\x06')) {
          if ((param_3 & 0xff) != 2) {
            cVar4 = cVar4 + '\x01';
          }
          if ((param_3 & 0xff) == 0) {
            if (cVar4 < '\x03') {
              uVar3 = 0x109;
            }
            else {
              uVar3 = 0x7e;
            }
            FUN_8000bb38(0,uVar3);
            FUN_800201ac(0x9ae,1);
          }
          *(ushort *)(iVar11 + 0x24) = *(ushort *)(iVar11 + 0x24) | 0x400;
          FUN_8011f6d0(0);
        }
        else if ((param_3 & 0xff) != 2) {
          cVar8 = cVar8 + '\x01';
        }
      }
      if (cVar4 < '\x03') {
        FUN_800201ac(0x89b,0);
      }
      else {
        FUN_800201ac(0x89b,1);
      }
      if (cVar4 < '\x04') {
        if (cVar4 < '\0') {
          cVar4 = '\0';
        }
      }
      else {
        cVar4 = '\x03';
      }
      if (cVar8 < '\x04') {
        if (cVar8 < '\0') {
          cVar8 = '\0';
        }
      }
      else {
        cVar8 = '\x03';
      }
      FUN_800201ac(0x88c,(int)cVar4);
      FUN_800201ac(0x894,(int)cVar8);
    }
  }
  FUN_8028687c();
  return;
}

