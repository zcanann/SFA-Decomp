// Function: FUN_80296ce0
// Entry: 80296ce0
// Size: 284 bytes

uint FUN_80296ce0(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (param_2 == 0) {
    if (*(int *)(iVar2 + 0x7f8) != 0) {
      *(undefined *)(iVar2 + 0x800) = 0;
      iVar1 = *(int *)(iVar2 + 0x7f8);
      if (iVar1 != 0) {
        if ((*(short *)(iVar1 + 0x46) == 0x3cf) || (*(short *)(iVar1 + 0x46) == 0x662)) {
          FUN_80182a5c(iVar1);
        }
        else {
          FUN_800ea9f8(iVar1);
        }
        *(ushort *)(*(int *)(iVar2 + 0x7f8) + 6) = *(ushort *)(*(int *)(iVar2 + 0x7f8) + 6) & 0xbfff
        ;
        *(undefined4 *)(*(int *)(iVar2 + 0x7f8) + 0xf8) = 0;
        *(undefined4 *)(iVar2 + 0x7f8) = 0;
      }
      *(uint *)(iVar2 + 0x360) = *(uint *)(iVar2 + 0x360) | 0x800000;
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,iVar2,1);
      *(code **)(iVar2 + 0x304) = FUN_802a58ac;
    }
  }
  else {
    *(int *)(iVar2 + 0x7f8) = param_2;
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,iVar2,5);
    *(undefined **)(iVar2 + 0x304) = &LAB_802a52ac;
  }
  return (-*(uint *)(iVar2 + 0x7f8) | *(uint *)(iVar2 + 0x7f8)) >> 0x1f;
}

