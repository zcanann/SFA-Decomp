// Function: FUN_8016855c
// Entry: 8016855c
// Size: 496 bytes

void FUN_8016855c(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  undefined uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar6 >> 0x20);
  iVar4 = (int)uVar6;
  iVar5 = *(int *)(iVar4 + 0x40c);
  FLOAT_803dda98 =
       FLOAT_803e30a0 +
       (float)((double)CONCAT44(0x43300000,
                                (int)*(char *)(*(int *)(iVar1 + 0x4c) + 0x28) ^ 0x80000000) -
              DOUBLE_803e3070) / FLOAT_803e30a4;
  if ((*(uint *)(param_3 + 0x314) & 1) != 0) {
    *(uint *)(param_3 + 0x314) = *(uint *)(param_3 + 0x314) & 0xfffffffe;
    FUN_8000bb18(iVar1,0x273);
  }
  if ((*(uint *)(param_3 + 0x314) & 0x80) != 0) {
    uVar2 = FUN_800221a0(0,2);
    *(undefined *)(iVar5 + 0x4a) = uVar2;
    *(uint *)(param_3 + 0x314) = *(uint *)(param_3 + 0x314) & 0xffffff7f;
    FUN_8000bb18(iVar1,0x274);
    for (iVar3 = (2 - (uint)*(byte *)(iVar5 + 0x4a)) * 10; iVar3 != 0; iVar3 = iVar3 + -1) {
      (**(code **)(*DAT_803dca88 + 8))(iVar1,0x711,0,4,0xffffffff,&FLOAT_803dda98);
    }
  }
  if ((*(uint *)(param_3 + 0x314) & 0x40) != 0) {
    *(uint *)(param_3 + 0x314) = *(uint *)(param_3 + 0x314) & 0xffffffbf;
    FUN_80168374(iVar1,iVar4,0);
  }
  if ((*(uint *)(param_3 + 0x314) & 0x800) != 0) {
    *(uint *)(param_3 + 0x314) = *(uint *)(param_3 + 0x314) & 0xfffff7ff;
    FUN_80168374(iVar1,iVar4,1);
  }
  if ((*(uint *)(param_3 + 0x314) & 0x200) != 0) {
    *(uint *)(param_3 + 0x314) = *(uint *)(param_3 + 0x314) & 0xfffffdff;
    FUN_8000bb18(iVar1,0x275);
  }
  if ((*(uint *)(param_3 + 0x314) & 0x400) != 0) {
    *(undefined *)(iVar5 + 0x4a) = 3;
    iVar4 = 10;
    do {
      (**(code **)(*DAT_803dca88 + 8))(iVar1,0x710,0,4,0xffffffff,&FLOAT_803dda98);
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *(uint *)(param_3 + 0x314) = *(uint *)(param_3 + 0x314) & 0xfffffbff;
  }
  FUN_80286128();
  return;
}

