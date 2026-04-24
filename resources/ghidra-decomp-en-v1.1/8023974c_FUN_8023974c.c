// Function: FUN_8023974c
// Entry: 8023974c
// Size: 192 bytes

/* WARNING: Removing unreachable block (ram,0x80239788) */

undefined4 FUN_8023974c(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    bVar1 = *(byte *)(param_3 + iVar3 + 0x81);
    if (bVar1 == 1) {
      iVar2 = FUN_8002bac4();
      FUN_802971fc(iVar2,0x19);
      (**(code **)(*DAT_803dd6e8 + 0x38))(0x468,0x14,0x8c,0);
    }
    else if (bVar1 == 0) {
      FUN_8011f670(1);
    }
    else if (bVar1 < 3) {
      FUN_8011f670(0);
    }
  }
  return 0;
}

