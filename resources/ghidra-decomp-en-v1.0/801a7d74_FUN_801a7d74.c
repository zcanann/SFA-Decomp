// Function: FUN_801a7d74
// Entry: 801a7d74
// Size: 848 bytes

void FUN_801a7d74(undefined4 param_1,undefined4 param_2,uint param_3)

{
  char cVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  char cVar5;
  char cVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  double dVar10;
  ulonglong uVar11;
  int local_38;
  int local_34 [13];
  
  uVar11 = FUN_802860cc();
  iVar3 = (int)(uVar11 >> 0x20);
  iVar9 = *(int *)(iVar3 + 0xb8);
  iVar4 = FUN_8002e0fc(local_34,&local_38);
  for (; local_34[0] < local_38; local_34[0] = local_34[0] + 1) {
    iVar7 = *(int *)(iVar4 + local_34[0] * 4);
    if (((iVar7 != iVar3) && (*(short *)(iVar7 + 0x46) == 0x518)) &&
       (dVar10 = (double)FUN_80021704(iVar3 + 0x18,iVar7 + 0x18), dVar10 < (double)FLOAT_803e4580))
    {
      iVar8 = *(int *)(*(int *)(iVar4 + local_34[0] * 4) + 0x4c);
      iVar7 = *(int *)(iVar3 + 0x4c);
      cVar5 = FUN_8001ffb4(0x88c);
      cVar6 = FUN_8001ffb4(0x894);
      if ((uVar11 & 0xff) == 0) {
        (**(code **)(*DAT_803dcac0 + 0x20))(iVar9,1);
        if (*(short *)(iVar8 + 0x1e) != -1) {
          FUN_800200e8((int)*(short *)(iVar8 + 0x1e),0);
        }
        cVar1 = *(char *)(iVar9 + 0x2e);
        if (((cVar1 == '\x03') || (cVar1 == '\x04')) || (cVar1 == '\x06')) {
          cVar5 = cVar5 + -1;
        }
        else {
          cVar6 = cVar6 + -1;
        }
        iVar7 = (int)*(short *)(iVar7 + 0x1a);
        if (iVar7 != -1) {
          FUN_800200e8(iVar7,0);
          *(undefined *)(iVar9 + 0x2e) = 0;
        }
        uVar2 = *(undefined4 *)(iVar3 + 0x10);
        *(undefined4 *)(iVar9 + 0xc) = uVar2;
        *(undefined4 *)(iVar9 + 0x10) = uVar2;
        *(ushort *)(iVar9 + 0x24) = *(ushort *)(iVar9 + 0x24) & 0xfbff;
        *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(iVar9 + 0x18);
        *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(iVar9 + 0x1c);
        *(undefined4 *)(iVar3 + 0x14) = *(undefined4 *)(iVar9 + 0x20);
        FUN_800e8370(iVar3);
      }
      else {
        (**(code **)(*DAT_803dcac0 + 0x20))(iVar9,0);
        if (*(short *)(iVar8 + 0x1e) != -1) {
          FUN_800200e8((int)*(short *)(iVar8 + 0x1e),1);
        }
        if ((param_3 & 0xff) == 0) {
          *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(*(int *)(iVar4 + local_34[0] * 4) + 0xc);
          *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(*(int *)(iVar4 + local_34[0] * 4) + 0x10);
          *(undefined4 *)(iVar3 + 0x14) = *(undefined4 *)(*(int *)(iVar4 + local_34[0] * 4) + 0x14);
          FUN_800e8370(iVar3);
        }
        uVar2 = *(undefined4 *)(iVar3 + 0x10);
        *(undefined4 *)(iVar9 + 0xc) = uVar2;
        *(undefined4 *)(iVar9 + 0x10) = uVar2;
        iVar7 = (int)*(short *)(iVar7 + 0x1a);
        if (iVar7 != -1) {
          FUN_800200e8(iVar7,(int)*(short *)(iVar8 + 0x1a));
          *(char *)(iVar9 + 0x2e) = (char)*(undefined2 *)(iVar8 + 0x1a);
        }
        cVar1 = *(char *)(iVar9 + 0x2e);
        if (((cVar1 == '\x03') || (cVar1 == '\x04')) || (cVar1 == '\x06')) {
          if ((param_3 & 0xff) != 2) {
            cVar5 = cVar5 + '\x01';
          }
          if ((param_3 & 0xff) == 0) {
            if (cVar5 < '\x03') {
              uVar2 = 0x109;
            }
            else {
              uVar2 = 0x7e;
            }
            FUN_8000bb18(0,uVar2);
            FUN_800200e8(0x9ae,1);
          }
          *(ushort *)(iVar9 + 0x24) = *(ushort *)(iVar9 + 0x24) | 0x400;
          FUN_8011f3ec(0);
        }
        else if ((param_3 & 0xff) != 2) {
          cVar6 = cVar6 + '\x01';
        }
      }
      if (cVar5 < '\x03') {
        FUN_800200e8(0x89b,0);
      }
      else {
        FUN_800200e8(0x89b,1);
      }
      if (cVar5 < '\x04') {
        if (cVar5 < '\0') {
          cVar5 = '\0';
        }
      }
      else {
        cVar5 = '\x03';
      }
      if (cVar6 < '\x04') {
        if (cVar6 < '\0') {
          cVar6 = '\0';
        }
      }
      else {
        cVar6 = '\x03';
      }
      FUN_800200e8(0x88c,(int)cVar5);
      FUN_800200e8(0x894,(int)cVar6);
    }
  }
  FUN_80286118();
  return;
}

