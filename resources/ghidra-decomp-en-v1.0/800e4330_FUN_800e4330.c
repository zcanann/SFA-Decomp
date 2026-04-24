// Function: FUN_800e4330
// Entry: 800e4330
// Size: 668 bytes

int FUN_800e4330(int param_1)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  uint local_18 [4];
  
  iVar6 = 1;
  do {
    if (param_1 == 0) {
      return iVar6;
    }
    bVar1 = false;
    if ((*(int *)(param_1 + 0x1c) == -1) || ((*(byte *)(param_1 + 0x1b) & 1) != 0)) {
      if ((*(int *)(param_1 + 0x20) == -1) || ((*(byte *)(param_1 + 0x1b) & 2) != 0)) {
        if ((*(int *)(param_1 + 0x24) == -1) || ((*(byte *)(param_1 + 0x1b) & 4) != 0)) {
          if ((*(int *)(param_1 + 0x28) == -1) || ((*(byte *)(param_1 + 0x1b) & 8) != 0)) {
            bVar1 = true;
          }
          else {
            bVar1 = false;
          }
        }
        else {
          bVar1 = false;
        }
      }
      else {
        bVar1 = false;
      }
    }
    if (bVar1) {
      return iVar6;
    }
    iVar2 = 0;
    uVar4 = *(uint *)(param_1 + 0x1c);
    if (((-1 < (int)uVar4) && ((*(byte *)(param_1 + 0x1b) & 1) == 0)) && (uVar4 != 0)) {
      iVar2 = 1;
      local_18[0] = uVar4;
    }
    uVar4 = *(uint *)(param_1 + 0x20);
    iVar3 = iVar2;
    if (((-1 < (int)uVar4) && ((*(byte *)(param_1 + 0x1b) & 2) == 0)) && (uVar4 != 0)) {
      iVar3 = iVar2 + 1;
      local_18[iVar2] = uVar4;
    }
    uVar4 = *(uint *)(param_1 + 0x24);
    iVar2 = iVar3;
    if (((-1 < (int)uVar4) && ((*(byte *)(param_1 + 0x1b) & 4) == 0)) && (uVar4 != 0)) {
      iVar2 = iVar3 + 1;
      local_18[iVar3] = uVar4;
    }
    uVar4 = *(uint *)(param_1 + 0x28);
    iVar3 = iVar2;
    if (((-1 < (int)uVar4) && ((*(byte *)(param_1 + 0x1b) & 8) == 0)) && (uVar4 != 0)) {
      iVar3 = iVar2 + 1;
      local_18[iVar2] = uVar4;
    }
    if (iVar3 == 0) {
      uVar4 = 0xffffffff;
    }
    else {
      iVar2 = FUN_800221a0(0,iVar3 + -1);
      uVar4 = local_18[iVar2];
    }
    if ((int)uVar4 < 0) {
      param_1 = 0;
    }
    else {
      iVar3 = DAT_803dd478 + -1;
      iVar2 = 0;
      while (iVar2 <= iVar3) {
        iVar5 = iVar3 + iVar2 >> 1;
        param_1 = (&DAT_803a17e8)[iVar5];
        if (*(uint *)(param_1 + 0x14) < uVar4) {
          iVar2 = iVar5 + 1;
        }
        else {
          if (*(uint *)(param_1 + 0x14) <= uVar4) goto LAB_800e44d4;
          iVar3 = iVar5 + -1;
        }
      }
      param_1 = 0;
    }
LAB_800e44d4:
    if (param_1 != 0) {
      iVar6 = iVar6 + 1;
    }
  } while( true );
}

