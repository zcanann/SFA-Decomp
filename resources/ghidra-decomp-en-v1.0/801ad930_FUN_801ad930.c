// Function: FUN_801ad930
// Entry: 801ad930
// Size: 576 bytes

undefined4 FUN_801ad930(int param_1,undefined4 param_2,int param_3)

{
  char cVar3;
  undefined4 uVar1;
  int iVar2;
  int *piVar4;
  int iVar5;
  short sStack42;
  undefined4 local_28;
  undefined4 local_24;
  undefined2 local_20;
  
  piVar4 = *(int **)(param_1 + 0xb8);
  *(undefined *)(piVar4 + 8) = 0xff;
  iVar5 = *piVar4;
  if (*(char *)(param_3 + 0x80) == '\x03') {
    *(undefined *)((int)piVar4 + 0x21) = 0xff;
    *(undefined *)(param_3 + 0x80) = 0;
  }
  local_28 = DAT_802c2308;
  local_24 = DAT_802c230c;
  local_20 = DAT_802c2310;
  if (*(char *)((int)piVar4 + 0x21) != *(char *)((int)piVar4 + 0x22)) {
    if (*(int *)(param_1 + 200) != 0) {
      FUN_8002cbc4();
      *(undefined4 *)(param_1 + 200) = 0;
      *(undefined *)(param_1 + 0xeb) = 0;
    }
    cVar3 = FUN_8002e04c();
    if (cVar3 == '\0') {
      *(undefined *)((int)piVar4 + 0x22) = 0;
    }
    else {
      if (0 < *(char *)((int)piVar4 + 0x21)) {
        uVar1 = FUN_8002bdf4(0x18,(int)(&sStack42)[*(char *)((int)piVar4 + 0x21)]);
        uVar1 = FUN_8002df90(uVar1,4,0xffffffff,0xffffffff,*(undefined4 *)(param_1 + 0x30));
        *(undefined4 *)(param_1 + 200) = uVar1;
        *(undefined *)(param_1 + 0xeb) = 1;
      }
      *(undefined *)((int)piVar4 + 0x22) = *(undefined *)((int)piVar4 + 0x21);
    }
  }
  *(undefined2 *)(param_3 + 0x6e) = *(undefined2 *)(param_3 + 0x70);
  if ((iVar5 == 0) || (*(char *)(param_3 + 0x80) != '\x02')) {
    if ((iVar5 != 0) && (*(char *)(param_3 + 0x80) == '\x01')) {
      (**(code **)(**(int **)(iVar5 + 0x68) + 0x3c))(iVar5,0);
      *(undefined *)(param_3 + 0x80) = 0;
    }
  }
  else {
    piVar4[1] = (int)FLOAT_803e4758;
    piVar4[2] = piVar4[5];
    piVar4[3] = piVar4[6];
    piVar4[4] = piVar4[7];
    (**(code **)(**(int **)(iVar5 + 0x68) + 0x3c))(iVar5,2);
    FUN_80030334((double)FLOAT_803e4748,param_1,0x100,1);
    iVar2 = *(int *)(param_1 + 100);
    if (iVar2 != 0) {
      *(uint *)(iVar2 + 0x30) = *(uint *)(iVar2 + 0x30) | 0x1000;
    }
    *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfffb;
    *(undefined *)(param_3 + 0x80) = 0;
  }
  if ((iVar5 != 0) && (iVar5 = (**(code **)(**(int **)(iVar5 + 0x68) + 0x38))(iVar5), iVar5 == 2)) {
    *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfffc;
  }
  return 0;
}

