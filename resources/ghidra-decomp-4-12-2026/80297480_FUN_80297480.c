// Function: FUN_80297480
// Entry: 80297480
// Size: 404 bytes

void FUN_80297480(short *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  if (*(int *)(param_1 + 0x18) == param_2) {
    FUN_80063000(param_1,(short *)0x0,1);
    if ((*(short *)(iVar1 + 0x274) == 10) || (*(short *)(iVar1 + 0x274) == 0xc)) {
      *(uint *)(iVar1 + 4) = *(uint *)(iVar1 + 4) & 0xffefffff;
      FUN_802abd04((int)param_1,iVar1,5);
      *(byte *)(iVar1 + 0x3f0) = *(byte *)(iVar1 + 0x3f0) & 0x7f;
      *(byte *)(iVar1 + 0x3f0) = *(byte *)(iVar1 + 0x3f0) & 0xef;
      *(byte *)(iVar1 + 0x3f0) = *(byte *)(iVar1 + 0x3f0) & 0xf7;
      FUN_8017082c();
      *(byte *)(iVar1 + 0x3f0) = *(byte *)(iVar1 + 0x3f0) & 0xfd;
      *(uint *)(iVar1 + 0x360) = *(uint *)(iVar1 + 0x360) | 0x800000;
      FUN_80035f9c((int)param_1);
      *(byte *)(iVar1 + 0x3f0) = *(byte *)(iVar1 + 0x3f0) & 0xbf;
      *(byte *)(iVar1 + 0x3f0) = *(byte *)(iVar1 + 0x3f0) & 0xfb | 4;
      *(byte *)(iVar1 + 0x3f4) = *(byte *)(iVar1 + 0x3f4) & 0xef | 0x10;
      *(undefined *)(iVar1 + 0x800) = 0;
      iVar2 = *(int *)(iVar1 + 0x7f8);
      if (iVar2 != 0) {
        if ((*(short *)(iVar2 + 0x46) == 0x3cf) || (*(short *)(iVar2 + 0x46) == 0x662)) {
          FUN_80182a5c(iVar2);
        }
        else {
          FUN_800ea9f8(iVar2);
        }
        *(ushort *)(*(int *)(iVar1 + 0x7f8) + 6) = *(ushort *)(*(int *)(iVar1 + 0x7f8) + 6) & 0xbfff
        ;
        *(undefined4 *)(*(int *)(iVar1 + 0x7f8) + 0xf8) = 0;
        *(undefined4 *)(iVar1 + 0x7f8) = 0;
      }
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,iVar1,2);
      *(code **)(iVar1 + 0x304) = FUN_802a58ac;
    }
  }
  return;
}

