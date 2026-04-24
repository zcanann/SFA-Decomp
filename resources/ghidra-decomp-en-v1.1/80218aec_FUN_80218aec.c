// Function: FUN_80218aec
// Entry: 80218aec
// Size: 340 bytes

/* WARNING: Removing unreachable block (ram,0x80218c20) */
/* WARNING: Removing unreachable block (ram,0x80218afc) */

void FUN_80218aec(void)

{
  undefined2 uVar1;
  undefined2 uVar2;
  int iVar3;
  int iVar4;
  char in_r8;
  int *piVar5;
  int iVar6;
  int *piVar7;
  double dVar8;
  
  iVar3 = FUN_80286828();
  piVar5 = *(int **)(iVar3 + 0xb8);
  if ((in_r8 != '\0') && (*(char *)(piVar5 + 1) != '\x01')) {
    uVar1 = *(undefined2 *)(iVar3 + 4);
    uVar2 = *(undefined2 *)(iVar3 + 2);
    dVar8 = (double)*(float *)(iVar3 + 8);
    *(undefined *)(iVar3 + 0xad) = 1;
    iVar4 = FUN_8002b660(iVar3);
    iVar6 = 0;
    piVar7 = piVar5;
    do {
      *(short *)(piVar7 + 4) = *(short *)(piVar7 + 4) + *(short *)((int)piVar7 + 0x1a);
      *(short *)(piVar7 + 9) = *(short *)(piVar7 + 9) + *(short *)((int)piVar7 + 0x2e);
      *(undefined2 *)(iVar3 + 4) = *(undefined2 *)(piVar7 + 4);
      *(undefined2 *)(iVar3 + 2) = *(undefined2 *)(piVar7 + 9);
      *(ushort *)(iVar4 + 0x18) = *(ushort *)(iVar4 + 0x18) & 0xfff7;
      FUN_8003b9ec(iVar3);
      piVar7 = (int *)((int)piVar7 + 2);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 5);
    *(undefined2 *)(iVar3 + 4) = uVar1;
    *(undefined2 *)(iVar3 + 2) = uVar2;
    *(float *)(iVar3 + 8) = (float)dVar8;
    *(undefined *)(iVar3 + 0xad) = 0;
    FUN_8003b9ec(iVar3);
    if ((*piVar5 != 0) && (iVar3 = FUN_8001dc28(*piVar5), iVar3 != 0)) {
      FUN_80060630(*piVar5);
    }
  }
  FUN_80286874();
  return;
}

