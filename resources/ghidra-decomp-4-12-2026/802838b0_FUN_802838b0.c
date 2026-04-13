// Function: FUN_802838b0
// Entry: 802838b0
// Size: 196 bytes

undefined4 FUN_802838b0(undefined4 *param_1,undefined param_2,undefined param_3,uint param_4)

{
  bool bVar3;
  int iVar1;
  undefined4 uVar2;
  
  FUN_802851f0();
  DAT_803defff = 0;
  DAT_803deffe = 0;
  DAT_803defc8 = 0;
  bVar3 = FUN_80284ef0(&LAB_80283744,param_4,param_1);
  if (((bVar3) && (iVar1 = FUN_8027c168(param_2,param_3,(uint)((param_4 & 1) != 0)), iVar1 != 0)) &&
     (iVar1 = FUN_8028503c(), iVar1 != 0)) {
    FUN_80285220();
    FUN_80284fbc();
    uVar2 = 0;
  }
  else {
    uVar2 = 0xffffffff;
  }
  return uVar2;
}

