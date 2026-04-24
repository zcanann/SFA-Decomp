// Function: FUN_8015dc04
// Entry: 8015dc04
// Size: 588 bytes

void FUN_8015dc04(void)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined8 uVar10;
  int local_38;
  int local_34;
  undefined4 local_30;
  uint uStack44;
  
  uVar10 = FUN_802860d4();
  iVar1 = (int)((ulonglong)uVar10 >> 0x20);
  iVar6 = (int)uVar10;
  iVar9 = *(int *)(iVar1 + 0xb8);
  if ((*(char *)(iVar6 + 0x346) != '\0') || (*(char *)(iVar6 + 0x27b) != '\0')) {
    iVar8 = *(int *)(iVar9 + 0x40c);
    uStack44 = (uint)*(ushort *)(iVar9 + 0x3fe);
    local_30 = 0x43300000;
    iVar2 = (**(code **)(*DAT_803dcab8 + 0x44))
                      ((double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e2dc0),
                       iVar1,iVar6,1);
    if (iVar2 != 0) {
      *(byte *)(iVar8 + 9) = *(byte *)(iVar8 + 9) & 0xfd;
      uVar3 = 5;
      goto LAB_8015de38;
    }
    iVar7 = 0;
    iVar2 = 0;
    iVar4 = FUN_8002e0fc(&local_38,&local_34);
    for (; local_38 < local_34; local_38 = local_38 + 1) {
      iVar5 = *(int *)(iVar4 + local_38 * 4);
      if ((iVar5 != iVar1) && (*(short *)(iVar5 + 0x46) == 0x306)) {
        iVar5 = (**(code **)(**(int **)(iVar5 + 0x68) + 0x20))(iVar5,0);
        if (iVar2 < iVar5) {
          iVar2 = iVar5;
        }
        if (iVar5 == 4) {
          iVar7 = iVar7 + 1;
        }
      }
    }
    iVar4 = FUN_800221a0(0,*(undefined *)(iVar9 + 0x406));
    if ((iVar2 < 5) && ((*(byte *)(iVar8 + 9) & 1) == 0)) {
      if (iVar4 < 0x21) {
        if (iVar4 < 0x11) {
          (**(code **)(*DAT_803dca8c + 0x14))(iVar1,iVar6,3);
        }
        else {
          (**(code **)(*DAT_803dca8c + 0x14))(iVar1,iVar6,2);
        }
      }
      else if (iVar7 < 2) {
        (**(code **)(*DAT_803dca8c + 0x14))(iVar1,iVar6,4);
      }
      else {
        (**(code **)(*DAT_803dca8c + 0x14))(iVar1,iVar6,2);
      }
    }
    else {
      if ((*(byte *)(iVar9 + 0x404) & 2) != 0) {
        *(byte *)(iVar8 + 9) = *(byte *)(iVar8 + 9) | 1;
      }
      (**(code **)(*DAT_803dca8c + 0x14))(iVar1,iVar6,4);
    }
  }
  uVar3 = 0;
LAB_8015de38:
  FUN_80286120(uVar3);
  return;
}

