// Function: FUN_801d96b4
// Entry: 801d96b4
// Size: 360 bytes

void FUN_801d96b4(int param_1)

{
  int iVar1;
  undefined uVar2;
  uint *puVar3;
  short *psVar4;
  
  puVar3 = *(uint **)(param_1 + 0xb8);
  *(code **)(param_1 + 0xbc) = FUN_801d7c14;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x4000;
  *(undefined4 *)(param_1 + 0xf8) = 3;
  iVar1 = FUN_800e87c4();
  if (iVar1 == 0) {
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  else {
    *(undefined4 *)(param_1 + 0xf4) = 2;
  }
  *(undefined2 *)(puVar3 + 4) = 0xffff;
  puVar3[3] = (uint)FLOAT_803e54c0;
  iVar1 = FUN_8001ffb4(0x611);
  if (iVar1 != 0) {
    *puVar3 = *puVar3 | 0x40;
  }
  uVar2 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
  *(undefined *)((int)puVar3 + 5) = uVar2;
  *(undefined2 *)((int)puVar3 + 0x12) = 0xffff;
  FUN_8000a518(0x22,0);
  FUN_8000a518(0x31,0);
  FUN_8000a518(0xb2,0);
  FUN_8000a518(0xc4,0);
  FUN_8000a518(0xa6,0);
  FUN_8000a518(0xac,0);
  FUN_8000a518(0xa8,0);
  FUN_800200e8(0xc8d,1);
  iVar1 = FUN_8001ffb4(0x13f);
  if (iVar1 == 0) {
    iVar1 = 0;
    psVar4 = &DAT_80327618;
    do {
      FUN_800200e8((int)*psVar4,0);
      psVar4 = psVar4 + 1;
      iVar1 = iVar1 + 1;
    } while (iVar1 < 0x12);
  }
  FUN_80055000();
  return;
}

