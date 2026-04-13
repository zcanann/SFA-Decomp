// Function: FUN_801f30a8
// Entry: 801f30a8
// Size: 284 bytes

undefined4 FUN_801f30a8(int param_1,undefined4 param_2,int param_3)

{
  undefined uVar1;
  int iVar2;
  int iVar3;
  
  uVar1 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0xac));
  switch(uVar1) {
  case 1:
    FUN_801f2fac(param_1,param_2,param_3);
    break;
  case 4:
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    break;
  case 6:
    iVar2 = *(int *)(param_1 + 0xb8);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
      if ((*(char *)(param_3 + iVar3 + 0x81) == '\x01') && (1 < *(byte *)(iVar2 + 0x27))) {
        FUN_800201ac(0x314,1);
      }
    }
  }
  return 0;
}

