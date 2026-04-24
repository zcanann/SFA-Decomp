// Function: FUN_8021dda8
// Entry: 8021dda8
// Size: 352 bytes

undefined4 FUN_8021dda8(int param_1,undefined param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  switch(param_2) {
  case 5:
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar1,8);
    break;
  case 6:
    FUN_800200e8(0x634,1);
    (**(code **)(*DAT_803dca54 + 0x48))(4,param_1,0xffffffff);
    break;
  case 7:
    FUN_800200e8(0x634,0);
    FUN_800200e8(0x631,1);
    *(byte *)(*(int *)(param_1 + 0x50) + 0x71) = *(byte *)(*(int *)(param_1 + 0x50) + 0x71) | 1;
    *(ushort *)(iVar1 + 0xc40) = *(ushort *)(iVar1 + 0xc40) & 0xfebf;
    *(byte *)(iVar1 + 0x9fd) = *(byte *)(iVar1 + 0x9fd) & 0xfd;
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar1,7);
    break;
  case 8:
    (**(code **)(*DAT_803dca54 + 0x48))(7,param_1,0xffffffff);
    break;
  case 9:
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar1,7);
  }
  return 0;
}

