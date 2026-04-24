// Function: FUN_8004b2c4
// Entry: 8004b2c4
// Size: 208 bytes

int FUN_8004b2c4(int *param_1)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  undefined4 *puVar5;
  
  uVar3 = param_1[7];
  iVar1 = *param_1 + uVar3 * 0x10;
  *(undefined *)(iVar1 + 0xd) = 0xff;
  while (uVar2 = (uint)*(byte *)(iVar1 + 0xc), uVar2 != 0xff) {
    iVar1 = *param_1 + uVar2 * 0x10;
    *(char *)(iVar1 + 0xd) = (char)uVar3;
    uVar3 = uVar2;
  }
  if (*(byte *)(iVar1 + 0xd) == 0xff) {
    puVar5 = (undefined4 *)0x0;
  }
  else {
    puVar5 = (undefined4 *)(*param_1 + (uint)*(byte *)(iVar1 + 0xd) * 0x10);
  }
  iVar4 = 0;
  iVar1 = 0;
  while (puVar5 != (undefined4 *)0x0) {
    *(undefined4 *)(param_1[2] + iVar1) = *puVar5;
    iVar1 = iVar1 + 4;
    iVar4 = iVar4 + 1;
    if (iVar4 < 100) {
      if (*(byte *)((int)puVar5 + 0xd) == 0xff) {
        puVar5 = (undefined4 *)0x0;
      }
      else {
        puVar5 = (undefined4 *)(*param_1 + (uint)*(byte *)((int)puVar5 + 0xd) * 0x10);
      }
    }
    else {
      puVar5 = (undefined4 *)0x0;
    }
  }
  *(short *)((int)param_1 + 0x2a) = (short)iVar4;
  *(undefined2 *)(param_1 + 0xb) = 0;
  return iVar4;
}

