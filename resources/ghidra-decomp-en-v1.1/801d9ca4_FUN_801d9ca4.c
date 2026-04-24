// Function: FUN_801d9ca4
// Entry: 801d9ca4
// Size: 360 bytes

void FUN_801d9ca4(int param_1)

{
  int iVar1;
  uint uVar2;
  undefined uVar3;
  uint *puVar4;
  short *psVar5;
  
  puVar4 = *(uint **)(param_1 + 0xb8);
  *(code **)(param_1 + 0xbc) = FUN_801d8204;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x4000;
  *(undefined4 *)(param_1 + 0xf8) = 3;
  iVar1 = FUN_800e8a48();
  if (iVar1 == 0) {
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  else {
    *(undefined4 *)(param_1 + 0xf4) = 2;
  }
  *(undefined2 *)(puVar4 + 4) = 0xffff;
  puVar4[3] = (uint)FLOAT_803e6158;
  uVar2 = FUN_80020078(0x611);
  if (uVar2 != 0) {
    *puVar4 = *puVar4 | 0x40;
  }
  uVar3 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0xac));
  *(undefined *)((int)puVar4 + 5) = uVar3;
  *(undefined2 *)((int)puVar4 + 0x12) = 0xffff;
  FUN_8000a538((int *)0x22,0);
  FUN_8000a538((int *)0x31,0);
  FUN_8000a538((int *)0xb2,0);
  FUN_8000a538((int *)0xc4,0);
  FUN_8000a538((int *)0xa6,0);
  FUN_8000a538((int *)0xac,0);
  FUN_8000a538((int *)0xa8,0);
  FUN_800201ac(0xc8d,1);
  uVar2 = FUN_80020078(0x13f);
  if (uVar2 == 0) {
    iVar1 = 0;
    psVar5 = &DAT_80328258;
    do {
      FUN_800201ac((int)*psVar5,0);
      psVar5 = psVar5 + 1;
      iVar1 = iVar1 + 1;
    } while (iVar1 < 0x12);
  }
  FUN_8005517c();
  return;
}

