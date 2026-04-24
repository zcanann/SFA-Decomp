// Function: FUN_80053d58
// Entry: 80053d58
// Size: 356 bytes

void FUN_80053d58(int param_1)

{
  bool bVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  double dVar6;
  
  *(undefined4 *)(param_1 + 0x40) = 0;
  *(undefined *)(param_1 + 0x48) = 0;
  iVar5 = param_1 + 0x20;
  bVar1 = 0 < (int)((uint)*(byte *)(param_1 + 0x1d) - (uint)*(byte *)(param_1 + 0x1c));
  FUN_8025a310(iVar5,param_1 + 0x60,*(undefined2 *)(param_1 + 10),*(undefined2 *)(param_1 + 0xc),
               *(undefined *)(param_1 + 0x16),*(undefined *)(param_1 + 0x17),
               *(undefined *)(param_1 + 0x18),bVar1);
  if (bVar1) {
    FUN_8025a584((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x1c)) -
                                DOUBLE_803deba0),
                 (double)(float)((double)CONCAT44(0x43300000,*(byte *)(param_1 + 0x1d) ^ 0x80000000)
                                - DOUBLE_803deba8),(double)FLOAT_803deb98,iVar5,
                 *(undefined *)(param_1 + 0x19),*(undefined *)(param_1 + 0x1a),0,0,0);
  }
  else {
    dVar6 = (double)FLOAT_803deb9c;
    FUN_8025a584(dVar6,dVar6,dVar6,iVar5,*(undefined *)(param_1 + 0x19),
                 *(undefined *)(param_1 + 0x1a),0,0,0);
  }
  FUN_8025a718(iVar5,param_1);
  uVar2 = FUN_8025a740(iVar5);
  uVar3 = FUN_8025a720(iVar5);
  uVar4 = FUN_8025a730(iVar5);
  uVar2 = FUN_8025a0ec(uVar3,uVar4,uVar2,0,0);
  *(undefined4 *)(param_1 + 0x44) = uVar2;
  return;
}

