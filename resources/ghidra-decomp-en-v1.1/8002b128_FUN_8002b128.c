// Function: FUN_8002b128
// Entry: 8002b128
// Size: 328 bytes

void FUN_8002b128(ushort *param_1,ushort param_2)

{
  ushort uVar1;
  byte bVar2;
  float afStack_58 [19];
  
  bVar2 = 10;
  uVar1 = param_1[0x22];
  if (((uVar1 == 0x1c) || (uVar1 == 0x6d)) || (uVar1 == 0x2a)) {
    bVar2 = 0x28;
  }
  if ((*(byte *)(*(int *)(param_1 + 0x28) + 0x76) & 1) != 0) {
    if (*(byte *)(param_1 + 0x78) < bVar2) {
      *(byte *)(param_1 + 0x78) = *(byte *)(param_1 + 0x78) + 1;
      FUN_8002ad08(param_1,0x1e,0xa0,0xff,0xff,0);
    }
    if (*(byte *)(param_1 + 0x78) == bVar2) {
      if ((*(byte *)((int)param_1 + 0xe5) & 2) != 0) {
        FUN_8002a8ec();
      }
      param_1[0x73] = param_2;
      *(byte *)((int)param_1 + 0xe5) = *(byte *)((int)param_1 + 0xe5) | 1;
      FUN_8002b554(param_1,afStack_58,'\0');
      FUN_8002854c(param_1,*(int *)(*(int *)(param_1 + 0x3e) + *(char *)((int)param_1 + 0xad) * 4));
      (**(code **)(*DAT_803dd734 + 0xc))(param_1,0x7fc,0,100,0);
    }
  }
  return;
}

