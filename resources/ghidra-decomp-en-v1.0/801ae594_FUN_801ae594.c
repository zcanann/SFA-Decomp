// Function: FUN_801ae594
// Entry: 801ae594
// Size: 608 bytes

/* WARNING: Removing unreachable block (ram,0x801ae5f0) */

void FUN_801ae594(int param_1)

{
  byte bVar1;
  ushort uVar2;
  int iVar3;
  short sVar4;
  byte *pbVar5;
  double dVar6;
  double dVar7;
  
  pbVar5 = *(byte **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x30);
  if (iVar3 != 0) {
    sVar4 = (**(code **)(**(int **)(iVar3 + 0x68) + 0x20))(iVar3,*pbVar5);
    bVar1 = pbVar5[1];
    if (bVar1 == 1) {
      if (sVar4 == 0) {
        FUN_800279cc((double)FLOAT_803e4790,
                     *(undefined4 *)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4),0,
                     0xffffffff,0,0x10);
        *(undefined2 *)(pbVar5 + 2) = 0xb4;
        *(undefined *)(param_1 + 0x36) = 0xa4;
        pbVar5[1] = 2;
      }
    }
    else if (bVar1 == 0) {
      if (sVar4 == 1) {
        FUN_800279cc((double)FLOAT_803e478c,
                     *(undefined4 *)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4),0,
                     0xffffffff,0,0x10);
        *(undefined *)(param_1 + 0x36) = 0xff;
        pbVar5[1] = 1;
      }
      else {
        iVar3 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803db410 * -8;
        if (iVar3 < 0) {
          iVar3 = 0;
        }
        *(char *)(param_1 + 0x36) = (char)iVar3;
      }
    }
    else if (bVar1 < 3) {
      if (sVar4 == 1) {
        pbVar5[1] = 1;
      }
      else {
        sVar4 = *(short *)(pbVar5 + 2);
        uVar2 = (ushort)DAT_803db410;
        *(ushort *)(pbVar5 + 2) = sVar4 - uVar2;
        if ((short)(sVar4 - uVar2) < 0) {
          pbVar5[1] = 0;
        }
      }
    }
    if (*pbVar5 < 5) {
      dVar7 = (double)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36)) -
                              DOUBLE_803e47a0) / FLOAT_803e4794);
      dVar6 = (double)FLOAT_803e4788;
      if ((dVar7 <= dVar6) && (dVar6 = dVar7, dVar7 < (double)FLOAT_803e4798)) {
        dVar6 = (double)FLOAT_803e4798;
      }
      (**(code **)(**(int **)(*(int *)(param_1 + 0x30) + 0x68) + 0x28))(dVar6);
    }
    iVar3 = FUN_800394ac(param_1,0,0);
    sVar4 = -*(short *)(iVar3 + 10) + 0x100;
    if (0x800 < sVar4) {
      sVar4 = -*(short *)(iVar3 + 10) + -0x700;
    }
    *(short *)(iVar3 + 10) = -sVar4;
    iVar3 = FUN_800394ac(param_1,1,0);
    sVar4 = -*(short *)(iVar3 + 10) + 0xa0;
    if (0x800 < sVar4) {
      sVar4 = -*(short *)(iVar3 + 10) + -0x760;
    }
    *(short *)(iVar3 + 10) = -sVar4;
  }
  return;
}

