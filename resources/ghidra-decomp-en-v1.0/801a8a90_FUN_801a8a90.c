// Function: FUN_801a8a90
// Entry: 801a8a90
// Size: 764 bytes

void FUN_801a8a90(void)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  short *psVar4;
  
  iVar1 = FUN_802860dc();
  psVar4 = *(short **)(iVar1 + 0xb8);
  if ((*psVar4 == -1) || (iVar2 = FUN_8001ffb4(), iVar2 != 0)) {
    *(float *)(psVar4 + 0x14) = *(float *)(psVar4 + 0x14) - FLOAT_803db414;
    if (*(float *)(psVar4 + 0x14) < FLOAT_803e45b0) {
      *(float *)(psVar4 + 0xc) = FLOAT_803e45b4;
      uVar3 = FUN_800221a0(-(uint)(ushort)psVar4[1]);
      *(float *)(psVar4 + 0xe) =
           (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e45b8);
      uVar3 = FUN_800221a0(-(uint)(ushort)psVar4[3]);
      *(float *)(psVar4 + 0x10) =
           (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e45b8);
      uVar3 = FUN_800221a0(-(uint)(ushort)psVar4[2]);
      *(float *)(psVar4 + 0x12) =
           (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e45b8);
      FUN_80021ac8(psVar4 + 4,psVar4 + 0xe);
      *(float *)(psVar4 + 0xe) = *(float *)(psVar4 + 0xe) + *(float *)(iVar1 + 0xc);
      *(float *)(psVar4 + 0x10) = *(float *)(psVar4 + 0x10) + *(float *)(iVar1 + 0x10);
      *(float *)(psVar4 + 0x12) = *(float *)(psVar4 + 0x12) + *(float *)(iVar1 + 0x14);
      uVar3 = FUN_800221a0(100,200);
      *(float *)(psVar4 + 0x14) =
           (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e45b8);
      uVar3 = FUN_800221a0(0x32,100);
      *(float *)(psVar4 + 0x16) =
           (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e45b8);
    }
    *(float *)(psVar4 + 0x16) = *(float *)(psVar4 + 0x16) - FLOAT_803db414;
    if (FLOAT_803e45b0 < *(float *)(psVar4 + 0x16)) {
      (**(code **)(*DAT_803dca88 + 8))(iVar1,0x71f,psVar4 + 8,0x200001,0xffffffff,0);
    }
    DAT_803ac938 = FLOAT_803e45b4;
    uVar3 = FUN_800221a0(-(uint)(ushort)psVar4[1]);
    DAT_803ac93c = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e45b8);
    uVar3 = FUN_800221a0(-(uint)(ushort)psVar4[3]);
    DAT_803ac940 = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e45b8);
    uVar3 = FUN_800221a0(-(uint)(ushort)psVar4[2]);
    DAT_803ac944 = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e45b8);
    FUN_80021ac8(psVar4 + 4,&DAT_803ac93c);
    DAT_803ac93c = DAT_803ac93c + *(float *)(iVar1 + 0xc);
    DAT_803ac940 = DAT_803ac940 + *(float *)(iVar1 + 0x10);
    DAT_803ac944 = DAT_803ac944 + *(float *)(iVar1 + 0x14);
    (**(code **)(*DAT_803dca88 + 8))(iVar1,0x720,&DAT_803ac930,0x200001,0xffffffff,0);
  }
  FUN_80286128();
  return;
}

