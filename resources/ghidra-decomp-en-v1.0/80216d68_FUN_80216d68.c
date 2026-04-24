// Function: FUN_80216d68
// Entry: 80216d68
// Size: 304 bytes

/* WARNING: Removing unreachable block (ram,0x80216e78) */

void FUN_80216d68(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  undefined8 in_f31;
  double dVar5;
  undefined auStack88 [12];
  float local_4c;
  undefined4 local_48;
  float local_44;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar1 = FUN_802860dc();
  iVar3 = *(int *)(iVar1 + 0x4c);
  iVar2 = FUN_8001ffb4((int)*(short *)(iVar3 + 0x24));
  if ((iVar2 != 0) && (iVar2 = FUN_8002b9ec(), iVar2 != 0)) {
    *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
    *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
    iVar2 = 0;
    dVar5 = DOUBLE_803e68d0;
    do {
      uStack60 = FUN_800221a0(0xffffff38,200);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_4c = *(float *)(iVar1 + 0xc) + (float)((double)CONCAT44(0x43300000,uStack60) - dVar5);
      local_48 = *(undefined4 *)(iVar1 + 0x10);
      uStack52 = FUN_800221a0(0xffffff38,200);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_44 = *(float *)(iVar1 + 0x14) + (float)((double)CONCAT44(0x43300000,uStack52) - dVar5);
      (**(code **)(*DAT_803dca88 + 8))
                (iVar1,*(undefined2 *)(iVar3 + 0x20),auStack88,0x200001,0xffffffff,0);
      iVar2 = iVar2 + 1;
    } while (iVar2 < 10);
    FUN_8000bb18(iVar1,0x2b8);
    FUN_800200e8((int)*(short *)(iVar3 + 0x24),0);
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  FUN_80286128();
  return;
}

