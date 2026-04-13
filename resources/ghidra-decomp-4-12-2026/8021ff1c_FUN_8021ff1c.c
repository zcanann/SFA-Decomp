// Function: FUN_8021ff1c
// Entry: 8021ff1c
// Size: 364 bytes

int FUN_8021ff1c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int *param_9,int param_10,uint param_11)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  int *piVar5;
  
  uVar2 = FUN_8002e144();
  if ((uVar2 & 0xff) == 0) {
    iVar3 = 0;
  }
  else {
    piVar5 = param_9;
    for (uVar2 = (uint)*(byte *)(param_9 + 8); uVar2 != 0; uVar2 = uVar2 - 1) {
      iVar3 = *piVar5;
      if ((*(ushort *)(iVar3 + 0xb0) & 0x200) == 0) {
        *(ushort *)(iVar3 + 0xb0) = *(ushort *)(iVar3 + 0xb0) | 0x200;
        FUN_80003494(*(uint *)(iVar3 + 0x4c),param_11,(uint)*(byte *)(param_11 + 2));
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) & 0xbfff;
        *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(param_11 + 8);
        *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(param_11 + 0xc);
        *(undefined4 *)(iVar3 + 0x14) = *(undefined4 *)(param_11 + 0x10);
        (**(code **)(**(int **)(iVar3 + 0x68) + 4))(iVar3,param_11,0);
        uVar4 = FUN_800238f8(0);
        FUN_800238c4(param_11);
        FUN_800238f8(uVar4);
        FUN_8002cf0c(iVar3);
        *(ushort *)(iVar3 + 0xb0) = *(ushort *)(iVar3 + 0xb0) & 0x7fff;
        return iVar3;
      }
      piVar5 = piVar5 + 1;
    }
    iVar3 = FUN_8002b678(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_10,
                         param_11);
    if (*(char *)(param_9 + 8) != '\b') {
      *(ushort *)(iVar3 + 0xb0) = *(ushort *)(iVar3 + 0xb0) | 0x200;
      bVar1 = *(byte *)(param_9 + 8);
      *(byte *)(param_9 + 8) = bVar1 + 1;
      param_9[bVar1] = iVar3;
    }
  }
  return iVar3;
}

