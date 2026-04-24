// Function: FUN_801c55e8
// Entry: 801c55e8
// Size: 412 bytes

void FUN_801c55e8(int param_1,int param_2)

{
  char cVar2;
  undefined4 uVar1;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  *(undefined2 *)(iVar4 + 0x6a) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(iVar4 + 0x6e) = 0xffff;
  *(float *)(iVar4 + 0x24) =
       FLOAT_803e4f68 /
       (FLOAT_803e4f68 +
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x24)) - DOUBLE_803e4f70));
  *(undefined4 *)(iVar4 + 0x28) = 0xffffffff;
  iVar3 = *(int *)(param_1 + 0xf4);
  if ((iVar3 == 0) && (*(short *)(param_2 + 0x18) != 1)) {
    (**(code **)(*DAT_803dca54 + 0x1c))(iVar4);
    *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
  }
  else if ((iVar3 != 0) && ((int)*(short *)(param_2 + 0x18) != iVar3 + -1)) {
    (**(code **)(*DAT_803dca54 + 0x24))(iVar4);
    if (*(short *)(param_2 + 0x18) != -1) {
      (**(code **)(*DAT_803dca54 + 0x1c))(iVar4,param_2);
    }
    *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
  }
  cVar2 = FUN_8002e04c();
  if (cVar2 != '\0') {
    iVar3 = FUN_8002bdf4(0x24,0x1b8);
    *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(param_1 + 0x14);
    *(undefined *)(iVar3 + 4) = 0x20;
    *(undefined *)(iVar3 + 5) = 4;
    *(undefined *)(iVar3 + 7) = 0xff;
    uVar1 = FUN_8002df90(iVar3,5,0xffffffff,0xffffffff,0);
    *(undefined4 *)(param_1 + 200) = uVar1;
    *(float *)(*(int *)(param_1 + 200) + 8) =
         *(float *)(*(int *)(param_1 + 200) + 8) * FLOAT_803e4f78;
  }
  return;
}

