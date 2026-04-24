// Function: FUN_802a4b78
// Entry: 802a4b78
// Size: 444 bytes

undefined4 FUN_802a4b78(int param_1,int param_2)

{
  short sVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e7ea4,param_1,0x447,0);
    *(undefined2 *)(param_2 + 0x278) = 1;
    *(code **)(iVar3 + 0x898) = FUN_802a514c;
  }
  if (((*(uint *)(param_2 + 0x314) & 1) == 0) || (*(int *)(iVar3 + 0x7f8) == 0)) goto LAB_802a4c54;
  sVar1 = *(short *)(*(int *)(iVar3 + 0x7f8) + 0x46);
  if (sVar1 == 0x519) {
LAB_802a4c38:
    FUN_8000bb18(param_1,0x39b);
    goto LAB_802a4c54;
  }
  if (sVar1 < 0x519) {
    if (sVar1 < 500) {
      if (sVar1 == 0x6d) goto LAB_802a4c28;
    }
    else if (sVar1 < 0x1fa) goto LAB_802a4c38;
  }
  else if (sVar1 == 0x754) {
LAB_802a4c28:
    FUN_8000bb18(param_1,799);
    goto LAB_802a4c54;
  }
  FUN_8000bb18(param_1,0x6d);
LAB_802a4c54:
  *(float *)(param_2 + 0x280) = FLOAT_803e7ea4;
  *(float *)(param_2 + 0x2a0) = FLOAT_803e7f40;
  if ((*(int *)(iVar3 + 0x7f8) == 0) && (*(char *)(param_2 + 0x346) != '\0')) {
    *(uint *)(iVar3 + 0x360) = *(uint *)(iVar3 + 0x360) | 0x800000;
    *(code **)(param_2 + 0x308) = FUN_802a514c;
    uVar2 = 2;
  }
  else {
    if ((*(int *)(iVar3 + 0x7f8) != 0) && (FLOAT_803e7f48 < *(float *)(param_1 + 0x98))) {
      *(undefined *)(iVar3 + 0x800) = 0;
      if (*(int *)(iVar3 + 0x7f8) != 0) {
        sVar1 = *(short *)(*(int *)(iVar3 + 0x7f8) + 0x46);
        if ((sVar1 == 0x3cf) || (sVar1 == 0x662)) {
          FUN_80182504();
        }
        else {
          FUN_800ea774();
        }
        *(ushort *)(*(int *)(iVar3 + 0x7f8) + 6) = *(ushort *)(*(int *)(iVar3 + 0x7f8) + 6) & 0xbfff
        ;
        *(undefined4 *)(*(int *)(iVar3 + 0x7f8) + 0xf8) = 0;
        *(undefined4 *)(iVar3 + 0x7f8) = 0;
      }
    }
    uVar2 = 0;
  }
  return uVar2;
}

