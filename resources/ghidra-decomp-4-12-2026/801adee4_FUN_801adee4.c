// Function: FUN_801adee4
// Entry: 801adee4
// Size: 576 bytes

undefined4
FUN_801adee4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,uint *param_13,undefined4 param_14,undefined4 param_15
            ,undefined4 param_16)

{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  undefined2 uStack_2a;
  undefined4 local_28;
  undefined4 local_24;
  undefined2 local_20;
  
  piVar5 = *(int **)(param_9 + 0xb8);
  *(undefined *)(piVar5 + 8) = 0xff;
  iVar6 = *piVar5;
  if (*(char *)(param_11 + 0x80) == '\x03') {
    *(undefined *)((int)piVar5 + 0x21) = 0xff;
    *(undefined *)(param_11 + 0x80) = 0;
  }
  local_28 = DAT_802c2a88;
  local_24 = DAT_802c2a8c;
  local_20 = DAT_802c2a90;
  if (*(char *)((int)piVar5 + 0x21) != *(char *)((int)piVar5 + 0x22)) {
    if (*(int *)(param_9 + 200) != 0) {
      param_1 = FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             *(int *)(param_9 + 200));
      *(undefined4 *)(param_9 + 200) = 0;
      *(undefined *)(param_9 + 0xeb) = 0;
    }
    uVar1 = FUN_8002e144();
    if ((uVar1 & 0xff) == 0) {
      *(undefined *)((int)piVar5 + 0x22) = 0;
    }
    else {
      if (0 < *(char *)((int)piVar5 + 0x21)) {
        puVar2 = FUN_8002becc(0x18,(&uStack_2a)[*(char *)((int)piVar5 + 0x21)]);
        param_12 = 0xffffffff;
        param_13 = *(uint **)(param_9 + 0x30);
        uVar3 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,
                             4,0xff,0xffffffff,param_13,param_14,param_15,param_16);
        *(undefined4 *)(param_9 + 200) = uVar3;
        *(undefined *)(param_9 + 0xeb) = 1;
      }
      *(undefined *)((int)piVar5 + 0x22) = *(undefined *)((int)piVar5 + 0x21);
    }
  }
  *(undefined2 *)(param_11 + 0x6e) = *(undefined2 *)(param_11 + 0x70);
  if ((iVar6 == 0) || (*(char *)(param_11 + 0x80) != '\x02')) {
    if ((iVar6 != 0) && (*(char *)(param_11 + 0x80) == '\x01')) {
      (**(code **)(**(int **)(iVar6 + 0x68) + 0x3c))(iVar6,0);
      *(undefined *)(param_11 + 0x80) = 0;
    }
  }
  else {
    piVar5[1] = (int)FLOAT_803e53f0;
    piVar5[2] = piVar5[5];
    piVar5[3] = piVar5[6];
    piVar5[4] = piVar5[7];
    (**(code **)(**(int **)(iVar6 + 0x68) + 0x3c))(iVar6,2);
    FUN_8003042c((double)FLOAT_803e53e0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x100,1,param_12,param_13,param_14,param_15,param_16);
    iVar4 = *(int *)(param_9 + 100);
    if (iVar4 != 0) {
      *(uint *)(iVar4 + 0x30) = *(uint *)(iVar4 + 0x30) | 0x1000;
    }
    *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xfffb;
    *(undefined *)(param_11 + 0x80) = 0;
  }
  if ((iVar6 != 0) && (iVar6 = (**(code **)(**(int **)(iVar6 + 0x68) + 0x38))(iVar6), iVar6 == 2)) {
    *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xfffc;
  }
  return 0;
}

