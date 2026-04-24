// Function: FUN_8015e0b0
// Entry: 8015e0b0
// Size: 588 bytes

void FUN_8015e0b0(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined8 uVar10;
  int local_38;
  int local_34 [13];
  
  uVar10 = FUN_80286838();
  iVar1 = (int)((ulonglong)uVar10 >> 0x20);
  iVar6 = (int)uVar10;
  iVar9 = *(int *)(iVar1 + 0xb8);
  if ((*(char *)(iVar6 + 0x346) != '\0') || (*(char *)(iVar6 + 0x27b) != '\0')) {
    iVar8 = *(int *)(iVar9 + 0x40c);
    local_34[2] = (int)*(ushort *)(iVar9 + 0x3fe);
    local_34[1] = 0x43300000;
    iVar2 = (**(code **)(*DAT_803dd738 + 0x44))
                      ((double)(float)((double)CONCAT44(0x43300000,local_34[2]) - DOUBLE_803e3a58),
                       iVar1,iVar6,1);
    if (iVar2 == 0) {
      iVar7 = 0;
      iVar2 = 0;
      iVar3 = FUN_8002e1f4(&local_38,local_34);
      for (; local_38 < local_34[0]; local_38 = local_38 + 1) {
        iVar4 = *(int *)(iVar3 + local_38 * 4);
        if ((iVar4 != iVar1) && (*(short *)(iVar4 + 0x46) == 0x306)) {
          iVar4 = (**(code **)(**(int **)(iVar4 + 0x68) + 0x20))(iVar4,0);
          if (iVar2 < iVar4) {
            iVar2 = iVar4;
          }
          if (iVar4 == 4) {
            iVar7 = iVar7 + 1;
          }
        }
      }
      uVar5 = FUN_80022264(0,(uint)*(byte *)(iVar9 + 0x406));
      if ((iVar2 < 5) && ((*(byte *)(iVar8 + 9) & 1) == 0)) {
        if ((int)uVar5 < 0x21) {
          if ((int)uVar5 < 0x11) {
            (**(code **)(*DAT_803dd70c + 0x14))(iVar1,iVar6,3);
          }
          else {
            (**(code **)(*DAT_803dd70c + 0x14))(iVar1,iVar6,2);
          }
        }
        else if (iVar7 < 2) {
          (**(code **)(*DAT_803dd70c + 0x14))(iVar1,iVar6,4);
        }
        else {
          (**(code **)(*DAT_803dd70c + 0x14))(iVar1,iVar6,2);
        }
      }
      else {
        if ((*(byte *)(iVar9 + 0x404) & 2) != 0) {
          *(byte *)(iVar8 + 9) = *(byte *)(iVar8 + 9) | 1;
        }
        (**(code **)(*DAT_803dd70c + 0x14))(iVar1,iVar6,4);
      }
    }
    else {
      *(byte *)(iVar8 + 9) = *(byte *)(iVar8 + 9) & 0xfd;
    }
  }
  FUN_80286884();
  return;
}

