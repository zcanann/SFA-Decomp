// Function: FUN_80219a88
// Entry: 80219a88
// Size: 460 bytes

void FUN_80219a88(undefined4 param_1,undefined4 param_2,int param_3)

{
  short sVar1;
  float fVar2;
  double dVar3;
  int iVar4;
  char cVar9;
  int iVar5;
  undefined2 *puVar6;
  undefined2 uVar8;
  uint uVar7;
  uint *puVar10;
  int iVar11;
  int iVar12;
  
  iVar4 = FUN_802860d8();
  iVar11 = *(int *)(iVar4 + 0x4c);
  FUN_80137948(s__Time__i____i_8032a8b0,(int)*(short *)(iVar11 + 0x1a),
               (int)*(short *)(param_3 + 0x58));
  cVar9 = FUN_8002e04c();
  if (cVar9 != '\0') {
    for (iVar12 = 0; iVar12 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar12 = iVar12 + 1) {
      sVar1 = *(short *)(iVar11 + 0x1a);
      if ((sVar1 == 9) || (((sVar1 < 9 && (sVar1 < 5)) && (2 < sVar1)))) {
        puVar10 = *(uint **)(iVar4 + 0xb8);
        iVar5 = FUN_8001ffb4((int)*(short *)(puVar10 + 1));
        if (iVar5 != 0) {
          iVar5 = FUN_8002bdf4(0x24,0x6bd);
          *(undefined4 *)(iVar5 + 8) = *(undefined4 *)(iVar4 + 0xc);
          *(undefined4 *)(iVar5 + 0xc) = *(undefined4 *)(iVar4 + 0x10);
          *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(iVar4 + 0x14);
          *(undefined *)(iVar5 + 4) = 1;
          *(undefined *)(iVar5 + 5) = 1;
          *(undefined *)(iVar5 + 6) = 0xff;
          *(undefined *)(iVar5 + 7) = 0xff;
          *(undefined *)(iVar5 + 0x19) = 2;
          puVar6 = (undefined2 *)FUN_8002df90(iVar5,5,0xffffffff,0xffffffff,0);
          if (puVar6 != (undefined2 *)0x0) {
            puVar6[1] = 0;
            uVar8 = FUN_800221a0(0,0xffff);
            *puVar6 = uVar8;
            uVar7 = FUN_800221a0(-(int)*(short *)((int)puVar10 + 10));
            dVar3 = DOUBLE_803e69b0;
            fVar2 = FLOAT_803e69a8;
            *(float *)(puVar6 + 0x12) =
                 FLOAT_803e69a8 *
                 (float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) - DOUBLE_803e69b0);
            *(float *)(puVar6 + 0x14) =
                 fVar2 * (float)((double)CONCAT44(0x43300000,*puVar10 ^ 0x80000000) - dVar3);
            uVar7 = FUN_800221a0(-(int)*(short *)((int)puVar10 + 10));
            *(float *)(puVar6 + 0x16) =
                 FLOAT_803e69a8 *
                 (float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) - DOUBLE_803e69b0);
            *(int *)(puVar6 + 0x62) = iVar4;
          }
        }
      }
    }
  }
  FUN_80286124(0);
  return;
}

