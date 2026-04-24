// Function: FUN_80263f08
// Entry: 80263f08
// Size: 504 bytes

void FUN_80263f08(int param_1,int param_2)

{
  bool bVar1;
  uint uVar2;
  byte bVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  
  iVar6 = *(int *)(param_1 + 0x2c);
  if (iVar6 == -1) {
    *(undefined *)(param_2 + 0x2e) = 0;
    iVar6 = 0;
    *(undefined2 *)(param_2 + 0x34) = 0;
    *(undefined2 *)(param_2 + 0x36) = 0;
  }
  bVar1 = false;
  bVar3 = *(byte *)(param_1 + 7) & 3;
  if (bVar3 == 2) {
    *(int *)(param_2 + 0x3c) = iVar6;
    iVar6 = iVar6 + 0x1800;
    *(undefined4 *)(param_2 + 0x40) = 0xffffffff;
  }
  else if ((bVar3 < 2) && ((*(byte *)(param_1 + 7) & 3) != 0)) {
    *(int *)(param_2 + 0x3c) = iVar6;
    iVar5 = iVar6 + 0xc00;
    iVar6 = iVar6 + 0xe00;
    *(int *)(param_2 + 0x40) = iVar5;
  }
  else {
    *(undefined4 *)(param_2 + 0x3c) = 0xffffffff;
    *(undefined4 *)(param_2 + 0x40) = 0xffffffff;
  }
  iVar7 = 2;
  uVar4 = 0;
  iVar5 = param_2;
  do {
    uVar2 = (int)(uint)*(ushort *)(param_1 + 0x30) >> (uVar4 & 0x3f) & 3;
    if (uVar2 == 2) {
      *(int *)(iVar5 + 0x44) = iVar6;
      iVar6 = iVar6 + 0x800;
    }
    else if ((uVar2 < 2) && (uVar2 != 0)) {
      *(int *)(iVar5 + 0x44) = iVar6;
      bVar1 = true;
      iVar6 = iVar6 + 0x400;
    }
    else {
      *(undefined4 *)(iVar5 + 0x44) = 0xffffffff;
    }
    uVar2 = (int)(uint)*(ushort *)(param_1 + 0x30) >> (uVar4 + 2 & 0x3f) & 3;
    if (uVar2 == 2) {
      *(int *)(iVar5 + 0x48) = iVar6;
      iVar6 = iVar6 + 0x800;
    }
    else if ((uVar2 < 2) && (uVar2 != 0)) {
      *(int *)(iVar5 + 0x48) = iVar6;
      bVar1 = true;
      iVar6 = iVar6 + 0x400;
    }
    else {
      *(undefined4 *)(iVar5 + 0x48) = 0xffffffff;
    }
    uVar2 = (int)(uint)*(ushort *)(param_1 + 0x30) >> (uVar4 + 4 & 0x3f) & 3;
    if (uVar2 == 2) {
      *(int *)(iVar5 + 0x4c) = iVar6;
      iVar6 = iVar6 + 0x800;
    }
    else if ((uVar2 < 2) && (uVar2 != 0)) {
      *(int *)(iVar5 + 0x4c) = iVar6;
      bVar1 = true;
      iVar6 = iVar6 + 0x400;
    }
    else {
      *(undefined4 *)(iVar5 + 0x4c) = 0xffffffff;
    }
    uVar2 = (int)(uint)*(ushort *)(param_1 + 0x30) >> (uVar4 + 6 & 0x3f) & 3;
    if (uVar2 == 2) {
      *(int *)(iVar5 + 0x50) = iVar6;
      iVar6 = iVar6 + 0x800;
    }
    else if ((uVar2 < 2) && (uVar2 != 0)) {
      *(int *)(iVar5 + 0x50) = iVar6;
      bVar1 = true;
      iVar6 = iVar6 + 0x400;
    }
    else {
      *(undefined4 *)(iVar5 + 0x50) = 0xffffffff;
    }
    uVar4 = uVar4 + 8;
    iVar5 = iVar5 + 0x10;
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  if (bVar1) {
    *(int *)(param_2 + 100) = iVar6;
    iVar6 = iVar6 + 0x200;
  }
  else {
    *(undefined4 *)(param_2 + 100) = 0xffffffff;
  }
  *(int *)(param_2 + 0x68) = iVar6;
  return;
}

