// Function: FUN_80296d20
// Entry: 80296d20
// Size: 404 bytes

void FUN_80296d20(int param_1,int param_2)

{
  short sVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(int *)(param_1 + 0x30) == param_2) {
    FUN_80062e84(param_1,0,1);
    if ((*(short *)(iVar2 + 0x274) == 10) || (*(short *)(iVar2 + 0x274) == 0xc)) {
      *(uint *)(iVar2 + 4) = *(uint *)(iVar2 + 4) & 0xffefffff;
      FUN_802ab5a4(param_1,iVar2,5);
      *(byte *)(iVar2 + 0x3f0) = *(byte *)(iVar2 + 0x3f0) & 0x7f;
      *(byte *)(iVar2 + 0x3f0) = *(byte *)(iVar2 + 0x3f0) & 0xef;
      *(byte *)(iVar2 + 0x3f0) = *(byte *)(iVar2 + 0x3f0) & 0xf7;
      FUN_80170380(DAT_803de450,2);
      *(byte *)(iVar2 + 0x3f0) = *(byte *)(iVar2 + 0x3f0) & 0xfd;
      *(uint *)(iVar2 + 0x360) = *(uint *)(iVar2 + 0x360) | 0x800000;
      FUN_80035ea4(param_1);
      *(byte *)(iVar2 + 0x3f0) = *(byte *)(iVar2 + 0x3f0) & 0xbf;
      *(byte *)(iVar2 + 0x3f0) = *(byte *)(iVar2 + 0x3f0) & 0xfb | 4;
      *(byte *)(iVar2 + 0x3f4) = *(byte *)(iVar2 + 0x3f4) & 0xef | 0x10;
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
      (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar2,2);
      *(code **)(iVar2 + 0x304) = FUN_802a514c;
    }
  }
  return;
}

