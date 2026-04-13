// Function: FUN_80186a38
// Entry: 80186a38
// Size: 364 bytes

void FUN_80186a38(int param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  uVar1 = FUN_8002bac4();
  iVar5 = *(int *)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  uVar2 = FUN_80296c50(uVar1,3);
  if (uVar2 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
  }
  if (*(char *)(iVar5 + 0xc) < '\0') {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
    iVar3 = FUN_80297300(uVar1);
    if (iVar3 == 0x5bd) {
      FUN_802972d8(uVar1,-1);
    }
    FUN_800201ac((int)*(short *)(iVar4 + 0x1e),1);
  }
  else {
    iVar4 = FUN_80297300(uVar1);
    if ((iVar4 == 0x5bd) && (*(int *)(iVar5 + 8) == -1)) {
      *(undefined4 *)(iVar5 + 8) = 0;
    }
  }
  if ((*(int *)(iVar5 + 8) != -1) &&
     (iVar4 = *(int *)(iVar5 + 8) - (uint)DAT_803dc070, *(int *)(iVar5 + 8) = iVar4, iVar4 < 0)) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    iVar4 = FUN_8002ba84();
    if (iVar4 != 0) {
      FUN_80139280(iVar4);
    }
    *(byte *)(iVar5 + 0xc) = *(byte *)(iVar5 + 0xc) & 0x7f | 0x80;
    *(undefined4 *)(iVar5 + 8) = 0xffffffff;
  }
  return;
}

