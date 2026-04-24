// Function: FUN_801b039c
// Entry: 801b039c
// Size: 520 bytes

void FUN_801b039c(int param_1)

{
  float fVar1;
  undefined uVar6;
  int iVar2;
  char cVar7;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  int iVar8;
  int iVar9;
  
  iVar8 = *(int *)(param_1 + 0xb8);
  iVar9 = *(int *)(param_1 + 0x4c);
  uVar6 = FUN_8001ffb4((int)*(short *)(iVar9 + 0x24));
  *(undefined *)(iVar8 + 0x1a) = uVar6;
  if (*(char *)(iVar8 + 0x1b) != '\0') {
    iVar2 = FUN_8001ffb4((int)*(short *)(iVar9 + 0x1e));
    if (iVar2 == 0) {
      *(undefined *)(iVar8 + 0x1a) = 0;
    }
    else {
      *(undefined *)(iVar8 + 0x1a) = 1;
      *(undefined *)(iVar8 + 0x1b) = 0;
      *(float *)(iVar8 + 0xc) = FLOAT_803e4814;
    }
  }
  if ((*(int *)(iVar8 + 8) == 0) && (cVar7 = FUN_8002e04c(), cVar7 != '\0')) {
    iVar2 = FUN_8002bdf4(0x24,0x18d);
    *(undefined *)(iVar2 + 2) = 9;
    *(undefined *)(iVar2 + 4) = 2;
    *(undefined *)(iVar2 + 6) = 0xff;
    *(undefined *)(iVar2 + 5) = 4;
    *(undefined *)(iVar2 + 7) = 0x50;
    *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(param_1 + 0x14);
    *(undefined *)(iVar2 + 0x18) = *(undefined *)(iVar9 + 0x1c);
    *(ushort *)(iVar2 + 0x1a) = (ushort)*(byte *)(iVar9 + 0x1a);
    *(ushort *)(iVar2 + 0x1c) = (ushort)*(byte *)(iVar9 + 0x1b);
    *(undefined4 *)(iVar2 + 0x14) = *(undefined4 *)(iVar9 + 0x14);
    uVar3 = FUN_8002df90(iVar2,5,(int)*(char *)(param_1 + 0xac),0xffffffff,0);
    *(undefined4 *)(iVar8 + 8) = uVar3;
  }
  iVar2 = *(int *)(iVar8 + 8);
  fVar1 = *(float *)(iVar8 + 0xc) - FLOAT_803db414;
  *(float *)(iVar8 + 0xc) = fVar1;
  if ((fVar1 <= FLOAT_803e4814) &&
     (iVar4 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x24))(iVar2), iVar4 != 0)) {
    if (*(char *)(iVar8 + 0x1a) != '\0') {
      iVar4 = FUN_8001ffb4((int)*(short *)(iVar9 + 0x1e));
      if ((iVar4 == 0) || (*(char *)(iVar8 + 0x18) != '\0')) {
        uVar6 = *(undefined *)(iVar9 + 0x1a);
      }
      else {
        uVar6 = *(undefined *)(iVar9 + 0x20);
        *(undefined *)(iVar8 + 0x18) = 1;
      }
      (**(code **)(**(int **)(iVar2 + 0x68) + 0x20))(iVar2,uVar6,*(undefined *)(iVar9 + 0x1b));
    }
    uVar5 = FUN_800221a0(0,0x3c);
    *(float *)(iVar8 + 0xc) =
         *(float *)(iVar8 + 0x10) +
         (float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) - DOUBLE_803e4818);
  }
  return;
}

