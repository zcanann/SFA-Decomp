// Function: FUN_80296580
// Entry: 80296580
// Size: 284 bytes

uint FUN_80296580(int param_1,int param_2)

{
  short sVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (param_2 == 0) {
    if (*(int *)(iVar2 + 0x7f8) != 0) {
      *(undefined *)(iVar2 + 0x800) = 0;
      if (*(int *)(iVar2 + 0x7f8) != 0) {
        sVar1 = *(short *)(*(int *)(iVar2 + 0x7f8) + 0x46);
        if ((sVar1 == 0x3cf) || (sVar1 == 0x662)) {
          FUN_80182504();
        }
        else {
          FUN_800ea774();
        }
        *(ushort *)(*(int *)(iVar2 + 0x7f8) + 6) = *(ushort *)(*(int *)(iVar2 + 0x7f8) + 6) & 0xbfff
        ;
        *(undefined4 *)(*(int *)(iVar2 + 0x7f8) + 0xf8) = 0;
        *(undefined4 *)(iVar2 + 0x7f8) = 0;
      }
      *(uint *)(iVar2 + 0x360) = *(uint *)(iVar2 + 0x360) | 0x800000;
      (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar2,1);
      *(code **)(iVar2 + 0x304) = FUN_802a514c;
    }
  }
  else {
    *(int *)(iVar2 + 0x7f8) = param_2;
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar2,5);
    *(undefined **)(iVar2 + 0x304) = &LAB_802a4b4c;
  }
  return (-*(uint *)(iVar2 + 0x7f8) | *(uint *)(iVar2 + 0x7f8)) >> 0x1f;
}

