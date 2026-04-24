// Function: FUN_80295918
// Entry: 80295918
// Size: 236 bytes

void FUN_80295918(double param_1,int param_2,undefined4 param_3)

{
  byte bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_2 + 0xb8);
  switch(param_3) {
  case 1:
    bVar1 = *(byte *)(iVar2 + 0x8b8);
    if (bVar1 < 4) {
      *(byte *)(iVar2 + 0x8b8) = bVar1 + 1;
      *(char *)(iVar2 + (uint)bVar1 + 0x8b9) = (char)(int)param_1;
    }
    break;
  case 5:
    (**(code **)(*DAT_803dca8c + 0x14))(param_2,iVar2,1);
    *(code **)(iVar2 + 0x304) = FUN_802a514c;
    break;
  case 6:
    (**(code **)(*DAT_803dca8c + 0x14))(param_2,iVar2,0x3f);
    break;
  case 10:
    *(uint *)(iVar2 + 0x360) = *(uint *)(iVar2 + 0x360) | 0x80000;
    break;
  case 0xb:
    *(uint *)(iVar2 + 0x360) = *(uint *)(iVar2 + 0x360) & 0xfff7ffff;
  }
  return;
}

