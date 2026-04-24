// Function: FUN_801aa4fc
// Entry: 801aa4fc
// Size: 92 bytes

void FUN_801aa4fc(short *param_1,int param_2)

{
  int iVar1;
  undefined *puVar2;
  
  puVar2 = *(undefined **)(param_1 + 0x5c);
  *(code **)(param_1 + 0x5e) = FUN_801a9fa8;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  iVar1 = FUN_8001ffb4(0xa3);
  if (iVar1 != 0) {
    *puVar2 = 7;
  }
  return;
}

