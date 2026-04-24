// Function: FUN_80239054
// Entry: 80239054
// Size: 192 bytes

/* WARNING: Removing unreachable block (ram,0x80239090) */

undefined4 FUN_80239054(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  undefined4 uVar2;
  int iVar3;
  
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    bVar1 = *(byte *)(param_3 + iVar3 + 0x81);
    if (bVar1 == 1) {
      uVar2 = FUN_8002b9ec();
      FUN_80296a9c(uVar2,0x19);
      (**(code **)(*DAT_803dca68 + 0x38))(0x468,0x14,0x8c,0);
    }
    else if (bVar1 == 0) {
      FUN_8011f38c(1);
    }
    else if (bVar1 < 3) {
      FUN_8011f38c(0);
    }
  }
  return 0;
}

