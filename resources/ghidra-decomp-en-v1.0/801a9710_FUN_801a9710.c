// Function: FUN_801a9710
// Entry: 801a9710
// Size: 1388 bytes

/* WARNING: Removing unreachable block (ram,0x801a97f0) */

void FUN_801a9710(int param_1)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  undefined *puVar5;
  byte *pbVar6;
  double dVar7;
  
  pbVar6 = *(byte **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if ((pbVar6[1] & 1) != 0) {
    *pbVar6 = 2;
    FUN_800200e8((int)*(short *)(pbVar6 + 8),1);
    pbVar6[1] = pbVar6[1] & 0xfe;
    *(undefined *)(param_1 + 0x36) = 0xff;
  }
  if (((*(byte *)(param_1 + 0xaf) & 4) != 0) && ((*(byte *)(param_1 + 0xaf) & 8) == 0)) {
    iVar2 = FUN_8001ffb4(0x86a);
    if (iVar2 == 0) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
    }
    else {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
    }
  }
  pbVar6[1] = pbVar6[1] | 2;
  bVar1 = *pbVar6;
  if (bVar1 == 2) {
    iVar2 = FUN_8002b9ac();
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    if ((pbVar6[1] & 2) != 0) {
      if ((pbVar6[1] & 4) != 0) {
        uVar3 = FUN_800221a0(0xffffffff,1);
        *(float *)(param_1 + 0x10) =
             *(float *)(iVar4 + 0xc) +
             (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e45e8);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x70f,0,2,0xffffffff,0);
      }
      *(float *)(pbVar6 + 0x14) = *(float *)(pbVar6 + 0x14) - FLOAT_803db414;
      if (*(float *)(pbVar6 + 0x14) <= FLOAT_803e45f4) {
        iVar4 = FUN_800221a0(0,1);
        if (iVar4 == 0) {
          uVar3 = FUN_800221a0(0x32,200);
          *(float *)(pbVar6 + 0x14) =
               (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e45e8);
          pbVar6[1] = pbVar6[1] & 0xfb;
        }
        else {
          *(float *)(pbVar6 + 0x14) = FLOAT_803e45f8;
          pbVar6[1] = pbVar6[1] | 4;
          FUN_8000bb18(param_1,0x438);
        }
      }
      iVar4 = FUN_8002b9ec();
      if ((iVar4 == 0) ||
         (dVar7 = (double)FUN_8002166c(iVar4 + 0x18,param_1 + 0x18), (double)FLOAT_803e45fc < dVar7)
         ) {
        FUN_800972dc((double)FLOAT_803e45dc,(double)FLOAT_803e4604,param_1,5,6,1,0x28,0,0);
      }
      else {
        FUN_800972dc((double)FLOAT_803e45dc,(double)FLOAT_803e4600,param_1,5,5,1,0x28,0,0);
        (**(code **)(**(int **)(iVar2 + 0x68) + 0x28))(iVar2,param_1,1,4);
      }
      iVar4 = FUN_8003687c(param_1,0,0,0);
      if (iVar4 == 0x1a) {
        *pbVar6 = 3;
        *(undefined2 *)(pbVar6 + 0xc) = 0;
        *(float *)(pbVar6 + 0x10) = FLOAT_803e4608;
      }
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      *pbVar6 = 1;
      *(float *)(param_1 + 0x10) = *(float *)(iVar4 + 0xc) - FLOAT_803e45f0;
      iVar2 = FUN_8001ffb4((int)*(short *)(pbVar6 + 8));
      if (iVar2 != 0) {
        *pbVar6 = 2;
        *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
        *(undefined *)(param_1 + 0x36) = 0xff;
      }
      iVar4 = FUN_8001ffb4((int)*(short *)(pbVar6 + 10));
      if (iVar4 != 0) {
        puVar5 = *(undefined **)(param_1 + 0xb8);
        iVar2 = *(int *)(param_1 + 0x4c);
        iVar4 = FUN_8001ffb4((int)*(short *)(puVar5 + 8));
        if (iVar4 != 0) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
          FUN_800200e8((int)*(short *)(puVar5 + 10),1);
          *puVar5 = 4;
          *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar2 + 0xc);
        }
      }
    }
    else if ((((*(byte *)(param_1 + 0xaf) & 1) != 0) &&
             (iVar2 = (**(code **)(*DAT_803dca68 + 0x20))(0x86a), iVar2 != 0)) &&
            (iVar2 = FUN_8001ffb4(0x86a), iVar2 != 0)) {
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
      *(undefined *)(param_1 + 0x36) = 0;
      (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
      FUN_800200e8(0x86a,iVar2 + -1);
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    }
  }
  else if (bVar1 < 4) {
    iVar2 = FUN_8002b9ac();
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
    dVar7 = (double)FUN_8002166c(iVar2 + 0x18,param_1 + 0x18);
    if ((double)FLOAT_803e45fc < dVar7) {
      FUN_800972dc((double)FLOAT_803e45dc,(double)FLOAT_803e4604,param_1,5,6,1,0x28,0,0);
    }
    else {
      FUN_800972dc((double)FLOAT_803e45dc,(double)FLOAT_803e4600,param_1,5,5,1,0x28,0,0);
    }
    if (((*(float *)(pbVar6 + 0x10) <= FLOAT_803e45f4) &&
        (iVar4 = FUN_8001ffb4((int)*(short *)(pbVar6 + 8)), iVar4 != 0)) &&
       (iVar4 = FUN_8001ffb4((int)*(short *)(pbVar6 + 10)), iVar4 == 0)) {
      puVar5 = *(undefined **)(param_1 + 0xb8);
      iVar2 = *(int *)(param_1 + 0x4c);
      iVar4 = FUN_8001ffb4((int)*(short *)(puVar5 + 8));
      if (iVar4 != 0) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
        FUN_800200e8((int)*(short *)(puVar5 + 10),1);
        *puVar5 = 4;
        *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar2 + 0xc);
      }
    }
    *(float *)(pbVar6 + 0x10) = *(float *)(pbVar6 + 0x10) - FLOAT_803db414;
    if (*(float *)(pbVar6 + 0x10) < FLOAT_803e45f4) {
      *(float *)(pbVar6 + 0x10) = FLOAT_803e45f4;
    }
  }
  return;
}

