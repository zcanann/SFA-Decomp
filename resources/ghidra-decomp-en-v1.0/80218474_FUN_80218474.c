// Function: FUN_80218474
// Entry: 80218474
// Size: 340 bytes

/* WARNING: Removing unreachable block (ram,0x802185a8) */

void FUN_80218474(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  undefined2 uVar1;
  undefined2 uVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  int *piVar7;
  undefined4 uVar8;
  undefined8 in_f31;
  double dVar9;
  undefined8 uVar10;
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar10 = FUN_802860c4();
  iVar4 = (int)((ulonglong)uVar10 >> 0x20);
  piVar5 = *(int **)(iVar4 + 0xb8);
  if ((param_6 != '\0') && (*(char *)(piVar5 + 1) != '\x01')) {
    uVar1 = *(undefined2 *)(iVar4 + 4);
    uVar2 = *(undefined2 *)(iVar4 + 2);
    dVar9 = (double)*(float *)(iVar4 + 8);
    *(undefined *)(iVar4 + 0xad) = 1;
    iVar3 = FUN_8002b588();
    iVar6 = 0;
    piVar7 = piVar5;
    do {
      *(short *)(piVar7 + 4) = *(short *)(piVar7 + 4) + *(short *)((int)piVar7 + 0x1a);
      *(short *)(piVar7 + 9) = *(short *)(piVar7 + 9) + *(short *)((int)piVar7 + 0x2e);
      *(undefined2 *)(iVar4 + 4) = *(undefined2 *)(piVar7 + 4);
      *(undefined2 *)(iVar4 + 2) = *(undefined2 *)(piVar7 + 9);
      *(ushort *)(iVar3 + 0x18) = *(ushort *)(iVar3 + 0x18) & 0xfff7;
      FUN_8003b8f4((double)FLOAT_803e6964,iVar4,(int)uVar10,param_3,param_4,param_5);
      piVar7 = (int *)((int)piVar7 + 2);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 5);
    *(undefined2 *)(iVar4 + 4) = uVar1;
    *(undefined2 *)(iVar4 + 2) = uVar2;
    *(float *)(iVar4 + 8) = (float)dVar9;
    *(undefined *)(iVar4 + 0xad) = 0;
    FUN_8003b8f4((double)FLOAT_803e6964,iVar4,(int)uVar10,param_3,param_4,param_5);
    if ((*piVar5 != 0) && (iVar4 = FUN_8001db64(), iVar4 != 0)) {
      FUN_800604b4(*piVar5);
    }
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  FUN_80286110();
  return;
}

