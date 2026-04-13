// Function: FUN_802297b4
// Entry: 802297b4
// Size: 408 bytes

/* WARNING: Removing unreachable block (ram,0x80229804) */

void FUN_802297b4(int param_1)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int *piVar6;
  double dVar7;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  piVar6 = *(int **)(param_1 + 0xb8);
  iVar2 = FUN_8002bac4();
  *(undefined2 *)(piVar6 + 1) = 0;
  bVar1 = *(byte *)((int)piVar6 + 6);
  if (bVar1 == 1) {
    iVar3 = (**(code **)(*DAT_803dd6d0 + 0x10))();
    if ((iVar3 == 0x44) && (uVar4 = FUN_80297150(iVar2), uVar4 == 0x21)) {
      *(undefined2 *)(piVar6 + 1) = 0xff;
      dVar7 = FUN_8000fc54();
      if ((dVar7 <= (double)FLOAT_803e7ad0) && ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
        FUN_800201ac((int)*(short *)(iVar5 + 0x1e),1);
        *(undefined *)((int)piVar6 + 6) = 2;
      }
    }
  }
  else if (bVar1 == 0) {
    uVar4 = FUN_80020078((int)*(short *)(iVar5 + 0x20));
    if (uVar4 != 0) {
      *(undefined *)((int)piVar6 + 6) = 1;
    }
  }
  else if (bVar1 < 3) {
    *(undefined2 *)(piVar6 + 1) = 0;
  }
  uVar4 = (uint)*(byte *)(param_1 + 0x36);
  iVar2 = (int)*(short *)(piVar6 + 1);
  if ((int)uVar4 < iVar2) {
    iVar5 = uVar4 + (uint)DAT_803dc070 * 4;
    if (iVar2 < iVar5) {
      iVar5 = iVar2;
    }
    *(char *)(param_1 + 0x36) = (char)iVar5;
  }
  else if (iVar2 < (int)uVar4) {
    iVar5 = uVar4 + (uint)DAT_803dc070 * -4;
    if (iVar5 < iVar2) {
      iVar5 = iVar2;
    }
    *(char *)(param_1 + 0x36) = (char)iVar5;
  }
  iVar2 = *piVar6;
  if (iVar2 != 0) {
    if (*(byte *)(param_1 + 0x36) < 0x81) {
      FUN_8001dc30((double)FLOAT_803e7ac4,iVar2,'\0');
    }
    else {
      FUN_8001dc30((double)FLOAT_803e7ac4,iVar2,'\x01');
    }
  }
  return;
}

