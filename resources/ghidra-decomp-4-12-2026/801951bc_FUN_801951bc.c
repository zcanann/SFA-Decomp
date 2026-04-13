// Function: FUN_801951bc
// Entry: 801951bc
// Size: 968 bytes

/* WARNING: Removing unreachable block (ram,0x80195564) */
/* WARNING: Removing unreachable block (ram,0x8019555c) */
/* WARNING: Removing unreachable block (ram,0x801951d4) */
/* WARNING: Removing unreachable block (ram,0x801951cc) */

void FUN_801951bc(undefined4 param_1,undefined4 param_2,undefined4 *param_3)

{
  ushort uVar1;
  float fVar2;
  int iVar3;
  ushort *puVar4;
  uint uVar5;
  int iVar6;
  undefined4 uVar7;
  int iVar8;
  undefined2 *puVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  double dVar15;
  double dVar16;
  undefined8 uVar17;
  undefined8 local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  
  uVar17 = FUN_8028682c();
  iVar3 = (int)((ulonglong)uVar17 >> 0x20);
  iVar8 = (int)uVar17;
  iVar12 = 0;
  iVar11 = 0;
  for (iVar10 = 0; iVar10 < (int)(uint)*(ushort *)((int)param_3 + 0x9a); iVar10 = iVar10 + 1) {
    puVar4 = (ushort *)FUN_80060868((int)param_3,iVar10);
    uVar5 = FUN_800607f4((int)puVar4);
    dVar16 = DOUBLE_803e4ca8;
    if ((int)*(char *)(iVar3 + 0x28) == uVar5) {
      local_a8 = (double)CONCAT44(0x43300000,
                                  (int)*(short *)(*(int *)(iVar8 + 0x10) + iVar12) ^ 0x80000000);
      puVar4[3] = (ushort)(int)(*(float *)(iVar8 + 0x44) + (float)(local_a8 - DOUBLE_803e4ca8));
      local_98 = (double)CONCAT44(0x43300000,
                                  (int)*(short *)(*(int *)(iVar8 + 0x14) + iVar12) ^ 0x80000000);
      puVar4[4] = (ushort)(int)(*(float *)(iVar8 + 0x44) + (float)(local_98 - dVar16));
      iVar12 = iVar12 + 2;
      uVar1 = puVar4[10];
      dVar15 = (double)FLOAT_803e4ca0;
      iVar6 = iVar11;
      for (uVar5 = (uint)*puVar4; (int)uVar5 < (int)(uint)uVar1; uVar5 = uVar5 + 1) {
        puVar4 = (ushort *)FUN_80060858((int)param_3,uVar5);
        iVar14 = 3;
        iVar13 = iVar6;
        do {
          puVar9 = (undefined2 *)(param_3[0x16] + (uint)*puVar4 * 6);
          local_90 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(*(int *)(iVar8 + 0xc) + iVar6) ^ 0x80000000);
          *puVar9 = (short)(int)(dVar15 * (double)*(float *)(iVar8 + 0x40) +
                                (double)(float)(local_90 - dVar16));
          local_a0 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(*(int *)(iVar8 + 0xc) + iVar6 + 2) ^
                                      0x80000000);
          puVar9[1] = (short)(int)(dVar15 * (double)*(float *)(iVar8 + 0x44) +
                                  (double)(float)(local_a0 - dVar16));
          local_88 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(*(int *)(iVar8 + 0xc) + iVar6 + 4) ^
                                      0x80000000);
          puVar9[2] = (short)(int)(dVar15 * (double)*(float *)(iVar8 + 0x48) +
                                  (double)(float)(local_88 - dVar16));
          iVar6 = iVar6 + 6;
          iVar13 = iVar13 + 6;
          iVar11 = iVar11 + 6;
          puVar4 = puVar4 + 1;
          iVar14 = iVar14 + -1;
        } while (iVar14 != 0);
        iVar6 = iVar13;
      }
    }
  }
  FUN_80242114(param_3[0x16],(uint)*(ushort *)(param_3 + 0x24) * 6);
  iVar10 = 0;
  for (iVar11 = 0; iVar11 < (int)(uint)*(byte *)((int)param_3 + 0xa1); iVar11 = iVar11 + 1) {
    iVar12 = FUN_80060878((int)param_3,iVar11);
    iVar6 = FUN_80060888((int)param_3,(uint)*(byte *)(iVar12 + 0x13));
    iVar6 = FUN_8004c3cc(iVar6,0);
    dVar16 = DOUBLE_803e4ca8;
    fVar2 = FLOAT_803e4ca0;
    if ((uint)*(byte *)(iVar6 + 5) == (int)*(char *)(iVar3 + 0x28)) {
      local_80 = (double)CONCAT44(0x43300000,
                                  (int)*(short *)(*(int *)(iVar8 + 0x28) + iVar10) ^ 0x80000000);
      *(short *)(iVar12 + 6) =
           (short)(int)(FLOAT_803e4ca0 * *(float *)(iVar8 + 0x40) +
                       (float)(local_80 - DOUBLE_803e4ca8));
      local_90 = (double)CONCAT44(0x43300000,
                                  (int)*(short *)(*(int *)(iVar8 + 0x2c) + iVar10) ^ 0x80000000);
      *(short *)(iVar12 + 0xc) =
           (short)(int)(fVar2 * *(float *)(iVar8 + 0x40) + (float)(local_90 - dVar16));
      local_a0 = (double)CONCAT44(0x43300000,
                                  (int)*(short *)(*(int *)(iVar8 + 0x30) + iVar10) ^ 0x80000000);
      *(short *)(iVar12 + 8) =
           (short)(int)(fVar2 * *(float *)(iVar8 + 0x44) + (float)(local_a0 - dVar16));
      *(short *)(iVar12 + 0xe) =
           (short)(int)(fVar2 * *(float *)(iVar8 + 0x44) +
                       (float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(*(int *)(iVar8 + 0x34) + iVar10) ^
                                                0x80000000) - dVar16));
      *(short *)(iVar12 + 10) =
           (short)(int)(fVar2 * *(float *)(iVar8 + 0x48) +
                       (float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(*(int *)(iVar8 + 0x38) + iVar10) ^
                                                0x80000000) - dVar16));
      *(short *)(iVar12 + 0x10) =
           (short)(int)(fVar2 * *(float *)(iVar8 + 0x48) +
                       (float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(*(int *)(iVar8 + 0x3c) + iVar10) ^
                                                0x80000000) - dVar16));
    }
    iVar10 = iVar10 + 2;
  }
  uVar7 = FUN_80060d0c();
  *param_3 = uVar7;
  FUN_80286878();
  return;
}

