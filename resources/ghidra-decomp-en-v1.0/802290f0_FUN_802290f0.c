// Function: FUN_802290f0
// Entry: 802290f0
// Size: 408 bytes

/* WARNING: Removing unreachable block (ram,0x80229140) */

void FUN_802290f0(int param_1)

{
  byte bVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  int *piVar6;
  double dVar7;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  piVar6 = *(int **)(param_1 + 0xb8);
  uVar3 = FUN_8002b9ec();
  *(undefined2 *)(piVar6 + 1) = 0;
  bVar1 = *(byte *)((int)piVar6 + 6);
  if (bVar1 == 1) {
    iVar2 = (**(code **)(*DAT_803dca50 + 0x10))();
    if ((iVar2 == 0x44) && (iVar2 = FUN_802969f0(uVar3), iVar2 == 0x21)) {
      *(undefined2 *)(piVar6 + 1) = 0xff;
      dVar7 = (double)FUN_8000fc34();
      if ((dVar7 <= (double)FLOAT_803e6e38) && ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
        FUN_800200e8((int)*(short *)(iVar5 + 0x1e),1);
        *(undefined *)((int)piVar6 + 6) = 2;
      }
    }
  }
  else if (bVar1 == 0) {
    iVar5 = FUN_8001ffb4((int)*(short *)(iVar5 + 0x20));
    if (iVar5 != 0) {
      *(undefined *)((int)piVar6 + 6) = 1;
    }
  }
  else if (bVar1 < 3) {
    *(undefined2 *)(piVar6 + 1) = 0;
  }
  uVar4 = (uint)*(byte *)(param_1 + 0x36);
  iVar5 = (int)*(short *)(piVar6 + 1);
  if ((int)uVar4 < iVar5) {
    iVar2 = uVar4 + (uint)DAT_803db410 * 4;
    if (iVar5 < iVar2) {
      iVar2 = iVar5;
    }
    *(char *)(param_1 + 0x36) = (char)iVar2;
  }
  else if (iVar5 < (int)uVar4) {
    iVar2 = uVar4 + (uint)DAT_803db410 * -4;
    if (iVar2 < iVar5) {
      iVar2 = iVar5;
    }
    *(char *)(param_1 + 0x36) = (char)iVar2;
  }
  iVar5 = *piVar6;
  if (iVar5 != 0) {
    if (*(byte *)(param_1 + 0x36) < 0x81) {
      FUN_8001db6c((double)FLOAT_803e6e2c,iVar5,0);
    }
    else {
      FUN_8001db6c((double)FLOAT_803e6e2c,iVar5,1);
    }
  }
  return;
}

