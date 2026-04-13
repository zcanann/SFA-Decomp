// Function: FUN_801a9044
// Entry: 801a9044
// Size: 764 bytes

void FUN_801a9044(void)

{
  int iVar1;
  uint uVar2;
  short *psVar3;
  
  iVar1 = FUN_80286840();
  psVar3 = *(short **)(iVar1 + 0xb8);
  if (((int)*psVar3 == 0xffffffff) || (uVar2 = FUN_80020078((int)*psVar3), uVar2 != 0)) {
    *(float *)(psVar3 + 0x14) = *(float *)(psVar3 + 0x14) - FLOAT_803dc074;
    if (*(float *)(psVar3 + 0x14) < FLOAT_803e5248) {
      *(float *)(psVar3 + 0xc) = FLOAT_803e524c;
      uVar2 = FUN_80022264(-(uint)(ushort)psVar3[1],(uint)(ushort)psVar3[1]);
      *(float *)(psVar3 + 0xe) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5250);
      uVar2 = FUN_80022264(-(uint)(ushort)psVar3[3],(uint)(ushort)psVar3[3]);
      *(float *)(psVar3 + 0x10) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5250);
      uVar2 = FUN_80022264(-(uint)(ushort)psVar3[2],(uint)(ushort)psVar3[2]);
      *(float *)(psVar3 + 0x12) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5250);
      FUN_80021b8c((ushort *)(psVar3 + 4),(float *)(psVar3 + 0xe));
      *(float *)(psVar3 + 0xe) = *(float *)(psVar3 + 0xe) + *(float *)(iVar1 + 0xc);
      *(float *)(psVar3 + 0x10) = *(float *)(psVar3 + 0x10) + *(float *)(iVar1 + 0x10);
      *(float *)(psVar3 + 0x12) = *(float *)(psVar3 + 0x12) + *(float *)(iVar1 + 0x14);
      uVar2 = FUN_80022264(100,200);
      *(float *)(psVar3 + 0x14) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5250);
      uVar2 = FUN_80022264(0x32,100);
      *(float *)(psVar3 + 0x16) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5250);
    }
    *(float *)(psVar3 + 0x16) = *(float *)(psVar3 + 0x16) - FLOAT_803dc074;
    if (FLOAT_803e5248 < *(float *)(psVar3 + 0x16)) {
      (**(code **)(*DAT_803dd708 + 8))(iVar1,0x71f,psVar3 + 8,0x200001,0xffffffff,0);
    }
    DAT_803ad598 = FLOAT_803e524c;
    uVar2 = FUN_80022264(-(uint)(ushort)psVar3[1],(uint)(ushort)psVar3[1]);
    DAT_803ad59c = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5250);
    uVar2 = FUN_80022264(-(uint)(ushort)psVar3[3],(uint)(ushort)psVar3[3]);
    DAT_803ad5a0 = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5250);
    uVar2 = FUN_80022264(-(uint)(ushort)psVar3[2],(uint)(ushort)psVar3[2]);
    DAT_803ad5a4 = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5250);
    FUN_80021b8c((ushort *)(psVar3 + 4),&DAT_803ad59c);
    DAT_803ad59c = DAT_803ad59c + *(float *)(iVar1 + 0xc);
    DAT_803ad5a0 = DAT_803ad5a0 + *(float *)(iVar1 + 0x10);
    DAT_803ad5a4 = DAT_803ad5a4 + *(float *)(iVar1 + 0x14);
    (**(code **)(*DAT_803dd708 + 8))(iVar1,0x720,&DAT_803ad590,0x200001,0xffffffff,0);
  }
  FUN_8028688c();
  return;
}

