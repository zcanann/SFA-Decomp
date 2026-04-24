// Function: FUN_80219c70
// Entry: 80219c70
// Size: 732 bytes

void FUN_80219c70(short *param_1)

{
  char cVar7;
  int iVar1;
  undefined4 uVar2;
  undefined2 *puVar3;
  undefined2 uVar5;
  uint uVar4;
  short sVar6;
  uint *puVar8;
  int iVar9;
  double dVar10;
  
  iVar9 = *(int *)(param_1 + 0x26);
  puVar8 = *(uint **)(param_1 + 0x5c);
  cVar7 = FUN_8002e04c();
  if (cVar7 != '\0') {
    sVar6 = *(short *)(iVar9 + 0x1a);
    if (sVar6 == 4) {
      iVar9 = FUN_8001ffb4((int)*(short *)(puVar8 + 1));
      if ((iVar9 != 0) &&
         (*(ushort *)(puVar8 + 2) = *(short *)(puVar8 + 2) - (ushort)DAT_803db410,
         *(short *)(puVar8 + 2) < 1)) {
        iVar9 = FUN_8002bdf4(0x24,0x6bd);
        *(undefined4 *)(iVar9 + 8) = *(undefined4 *)(param_1 + 6);
        *(undefined4 *)(iVar9 + 0xc) = *(undefined4 *)(param_1 + 8);
        *(undefined4 *)(iVar9 + 0x10) = *(undefined4 *)(param_1 + 10);
        *(undefined *)(iVar9 + 4) = 1;
        *(undefined *)(iVar9 + 5) = 1;
        *(undefined *)(iVar9 + 6) = 0xff;
        *(undefined *)(iVar9 + 7) = 0xfa;
        if (*(char *)(param_1 + 0x56) == '\x02') {
          *(undefined *)(iVar9 + 0x19) = 4;
        }
        else {
          *(undefined *)(iVar9 + 0x19) = 1;
        }
        puVar3 = (undefined2 *)FUN_8002df90(iVar9,5,0xffffffff,0xffffffff,0);
        if (puVar3 != (undefined2 *)0x0) {
          puVar3[1] = 0;
          uVar5 = FUN_800221a0(0,0xffff);
          *puVar3 = uVar5;
          dVar10 = (double)FUN_80293e80((double)((FLOAT_803e69c0 *
                                                 (float)((double)CONCAT44(0x43300000,
                                                                          (int)*param_1 ^ 0x80000000
                                                                         ) - DOUBLE_803e69b0)) /
                                                FLOAT_803e69c4));
          *(float *)(puVar3 + 0x12) =
               FLOAT_803e69b8 *
               FLOAT_803e69bc *
               (float)((double)(float)((double)CONCAT44(0x43300000,*puVar8 ^ 0x80000000) -
                                      DOUBLE_803e69b0) * -dVar10);
          uVar4 = FUN_800221a0(0,1000);
          dVar10 = DOUBLE_803e69b0;
          *(float *)(puVar3 + 0x14) =
               FLOAT_803e69b8 *
               (float)((double)CONCAT44(0x43300000,*puVar8 ^ 0x80000000) - DOUBLE_803e69b0) *
               FLOAT_803e69c8 *
               (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e69b0);
          dVar10 = (double)FUN_80294204((double)((FLOAT_803e69c0 *
                                                 (float)((double)CONCAT44(0x43300000,
                                                                          (int)*param_1 ^ 0x80000000
                                                                         ) - dVar10)) /
                                                FLOAT_803e69c4));
          *(float *)(puVar3 + 0x16) =
               FLOAT_803e69b8 *
               FLOAT_803e69bc *
               (float)((double)(float)((double)CONCAT44(0x43300000,*puVar8 ^ 0x80000000) -
                                      DOUBLE_803e69b0) * -dVar10);
          *(short **)(puVar3 + 0x62) = param_1;
        }
        sVar6 = FUN_800221a0(0,(int)*(short *)((int)puVar8 + 10));
        *(short *)(puVar8 + 2) = *(short *)((int)puVar8 + 6) + sVar6;
      }
    }
    else {
      if (sVar6 < 4) {
        if (sVar6 < 3) {
          return;
        }
      }
      else if (sVar6 != 9) {
        return;
      }
      iVar1 = FUN_8001ffb4((int)*(short *)(puVar8 + 1));
      if (iVar1 != 0) {
        if (*(short *)(iVar9 + 0x1a) == 3) {
          uVar2 = 0;
        }
        else {
          uVar2 = 4;
        }
        (**(code **)(*DAT_803dca54 + 0x48))(uVar2,param_1,0xffffffff);
      }
    }
  }
  return;
}

