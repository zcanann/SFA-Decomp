// Function: FUN_8016fde0
// Entry: 8016fde0
// Size: 540 bytes

void FUN_8016fde0(void)

{
  int iVar1;
  undefined2 uVar3;
  int iVar2;
  int *piVar4;
  int iVar5;
  int *piVar6;
  double dVar7;
  
  iVar1 = FUN_802860dc();
  piVar6 = *(int **)(iVar1 + 0xb8);
  iVar5 = *(int *)(iVar1 + 0x4c);
  if (*(short *)(iVar5 + 0x1c) == 0) {
    uVar3 = FUN_800221a0(600,900);
    *(undefined2 *)(piVar6 + 0x10) = uVar3;
    uVar3 = FUN_800221a0(0xfffffda8,600);
    *(undefined2 *)((int)piVar6 + 0x42) = uVar3;
    *(undefined *)((int)piVar6 + 0x71) = 0;
    if (*(int *)(iVar1 + 0x54) != 0) {
      *(undefined2 *)(*(int *)(iVar1 + 0x54) + 0xb2) = 0x101;
    }
    if (*piVar6 == 0) {
      iVar2 = FUN_8001f4c8(iVar1,1);
      *piVar6 = iVar2;
      if (*piVar6 != 0) {
        FUN_8001db2c(*piVar6,2);
        FUN_8001db54(*piVar6,0);
        dVar7 = (double)FLOAT_803e3330;
        FUN_8001dd88(dVar7,dVar7,dVar7,*piVar6);
        FUN_8001db14(*piVar6,1);
        iVar2 = (uint)*(byte *)((int)piVar6 + 0x71) * 3;
        FUN_8001daf0(*piVar6,(&DAT_80320978)[iVar2],(&DAT_80320979)[iVar2],(&DAT_8032097a)[iVar2],0)
        ;
        FUN_8001dc38((double)FLOAT_803e3358,(double)FLOAT_803e3378,*piVar6);
        iVar2 = (uint)*(byte *)((int)piVar6 + 0x71) * 3;
        FUN_8001d730((double)FLOAT_803e337c,*piVar6,0,(&DAT_80320978)[iVar2],(&DAT_80320979)[iVar2],
                     (&DAT_8032097a)[iVar2],0x20);
        FUN_8001d714((double)FLOAT_803e337c,*piVar6);
      }
    }
    *(undefined *)(iVar1 + 0x36) = 200;
    iVar2 = 0;
    piVar4 = piVar6;
    do {
      uVar3 = FUN_800221a0(0xffff8001,0x7fff);
      *(undefined2 *)(piVar4 + 0x12) = uVar3;
      uVar3 = FUN_800221a0(0xfffffc00,0x400);
      *(undefined2 *)((int)piVar4 + 0x52) = uVar3;
      uVar3 = FUN_800221a0(0xffff8001,0x7fff);
      *(undefined2 *)(piVar4 + 0x17) = uVar3;
      uVar3 = FUN_800221a0(0xfffffc00,0x400);
      *(undefined2 *)((int)piVar4 + 0x66) = uVar3;
      piVar4 = (int *)((int)piVar4 + 2);
      iVar2 = iVar2 + 1;
    } while (iVar2 < 5);
    *(code **)(iVar1 + 0xbc) = FUN_8016f178;
    FUN_80037200(iVar1,2);
    if ((*(short *)(iVar1 + 0x46) != 0x83e) && (*(short *)(iVar5 + 0x1a) != 0)) {
      piVar6[0xf] = (int)FLOAT_803e3380;
    }
  }
  else {
    *(byte *)(piVar6 + 0x1c) = *(byte *)(piVar6 + 0x1c) | 8;
  }
  FUN_80286128();
  return;
}

