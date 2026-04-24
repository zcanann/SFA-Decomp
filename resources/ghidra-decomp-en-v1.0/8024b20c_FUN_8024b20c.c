// Function: FUN_8024b20c
// Entry: 8024b20c
// Size: 208 bytes

undefined4 FUN_8024b20c(int param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  
  *(undefined4 *)(param_1 + 8) = 0xe;
  *(undefined4 *)(param_1 + 0x18) = param_2;
  *(undefined4 *)(param_1 + 0x14) = 0x20;
  *(undefined4 *)(param_1 + 0x20) = 0;
  *(undefined4 *)(param_1 + 0x28) = param_3;
  if ((DAT_803dc568 != 0) &&
     (((iVar1 = *(int *)(param_1 + 8), iVar1 == 1 || (iVar1 - 4U < 2)) || (iVar1 == 0xe)))) {
    FUN_802419b8(*(undefined4 *)(param_1 + 0x18),*(undefined4 *)(param_1 + 0x14));
  }
  uVar2 = FUN_8024377c();
  *(undefined4 *)(param_1 + 0xc) = 2;
  uVar3 = FUN_8024b9a8(2,param_1);
  if ((DAT_803ddf08 == 0) && (DAT_803ddf14 == 0)) {
    FUN_8024a1b8();
  }
  FUN_802437a4(uVar2);
  return uVar3;
}

