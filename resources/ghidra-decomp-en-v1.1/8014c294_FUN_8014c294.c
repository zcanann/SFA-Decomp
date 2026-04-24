// Function: FUN_8014c294
// Entry: 8014c294
// Size: 584 bytes

void FUN_8014c294(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)

{
  ushort *puVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  double dVar6;
  
  puVar1 = (ushort *)FUN_8028683c();
  iVar4 = *(int *)(puVar1 + 0x5c);
  if (*(int *)(puVar1 + 0x7a) == 0) {
    *(uint *)(iVar4 + 0x2dc) = *(uint *)(iVar4 + 0x2dc) | 0x8000;
    FUN_80003494(iVar4 + 0x2c4,iVar4 + 0x2b8,0xc);
    uVar5 = FUN_80003494(iVar4 + 0x2b8,(uint)(puVar1 + 0x12),0xc);
    for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar3 = iVar3 + 1) {
      switch(*(undefined *)(param_11 + iVar3 + 0x81)) {
      case 1:
        iVar2 = FUN_8002ba84();
        if (iVar2 != 0) {
          uVar5 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x34))(iVar2,1,puVar1);
          *(uint *)(iVar4 + 0x2dc) = *(uint *)(iVar4 + 0x2dc) | 0x200000;
          *(int *)(iVar4 + 0x29c) = iVar2;
        }
        break;
      case 2:
        if (puVar1[0x23] == 0x7a6) {
          *(undefined2 *)(iVar4 + 0x2b6) = 0x7a5;
        }
        else {
          *(undefined2 *)(iVar4 + 0x2b6) = 0x33;
        }
        break;
      case 3:
        uVar5 = (**(code **)(*DAT_803dd6d4 + 0x50))(0x49,4,puVar1,0x3c);
        break;
      case 4:
        iVar2 = FUN_8002bac4();
        if (iVar2 != 0) {
          *(uint *)(iVar4 + 0x2dc) = *(uint *)(iVar4 + 0x2dc) & 0xffdfffff;
          *(int *)(iVar4 + 0x29c) = iVar2;
        }
        break;
      case 6:
        if (*(int *)(iVar4 + 0x36c) != 0) {
          uVar5 = FUN_80026cf4(*(int *)(iVar4 + 0x36c),1);
        }
        break;
      case 7:
        if (*(int *)(iVar4 + 0x36c) != 0) {
          uVar5 = FUN_80026cf4(*(int *)(iVar4 + 0x36c),0);
        }
      }
    }
    FUN_8014a4b8(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)puVar1,iVar4);
    if (puVar1[0x5a] == 0xffff) {
      *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) & 0xfffffffc;
      FUN_80035ff8((int)puVar1);
    }
    else if ((*(uint *)(iVar4 + 0x2dc) & 0x1800) == 0) {
      dVar6 = (double)FUN_8014c110(puVar1,iVar4);
      FUN_8014bcf0(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)puVar1,iVar4);
    }
  }
  FUN_80286888();
  return;
}

