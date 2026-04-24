// Function: FUN_8021f8cc
// Entry: 8021f8cc
// Size: 364 bytes

int FUN_8021f8cc(int *param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  uint uVar2;
  char cVar5;
  int iVar3;
  undefined4 uVar4;
  int *piVar6;
  
  cVar5 = FUN_8002e04c();
  if (cVar5 == '\0') {
    iVar3 = 0;
  }
  else {
    piVar6 = param_1;
    for (uVar2 = (uint)*(byte *)(param_1 + 8); uVar2 != 0; uVar2 = uVar2 - 1) {
      iVar3 = *piVar6;
      if ((*(ushort *)(iVar3 + 0xb0) & 0x200) == 0) {
        *(ushort *)(iVar3 + 0xb0) = *(ushort *)(iVar3 + 0xb0) | 0x200;
        FUN_80003494(*(undefined4 *)(iVar3 + 0x4c),param_3,*(undefined *)(param_3 + 2));
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) & 0xbfff;
        *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(param_3 + 8);
        *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(param_3 + 0xc);
        *(undefined4 *)(iVar3 + 0x14) = *(undefined4 *)(param_3 + 0x10);
        (**(code **)(**(int **)(iVar3 + 0x68) + 4))(iVar3,param_3,0);
        uVar4 = FUN_80023834(0);
        FUN_80023800(param_3);
        FUN_80023834(uVar4);
        FUN_8002ce14(iVar3);
        *(ushort *)(iVar3 + 0xb0) = *(ushort *)(iVar3 + 0xb0) & 0x7fff;
        return iVar3;
      }
      piVar6 = piVar6 + 1;
    }
    iVar3 = FUN_8002b5a0(param_2,param_3);
    if (*(char *)(param_1 + 8) != '\b') {
      *(ushort *)(iVar3 + 0xb0) = *(ushort *)(iVar3 + 0xb0) | 0x200;
      bVar1 = *(byte *)(param_1 + 8);
      *(byte *)(param_1 + 8) = bVar1 + 1;
      param_1[bVar1] = iVar3;
    }
  }
  return iVar3;
}

