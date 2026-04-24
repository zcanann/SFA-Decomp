// Function: FUN_801b69ac
// Entry: 801b69ac
// Size: 408 bytes

void FUN_801b69ac(int param_1)

{
  int iVar1;
  undefined uVar2;
  uint uVar3;
  float *pfVar4;
  
  FUN_800221a0(0,0xb);
  pfVar4 = *(float **)(param_1 + 0xb8);
  *(undefined *)(pfVar4 + 2) = 0;
  *pfVar4 = FLOAT_803e4a28;
  iVar1 = FUN_800e87c4();
  if (iVar1 == 0) {
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  else {
    *(undefined4 *)(param_1 + 0xf4) = 2;
  }
  for (uVar3 = 1; (uVar3 & 0xff) < 0x27; uVar3 = uVar3 + 1) {
    FUN_800ea2e0(uVar3);
  }
  uVar2 = FUN_8001ffb4(0xdc);
  *(undefined *)(pfVar4 + 3) = uVar2;
  FUN_800200e8(0xf0a,0);
  iVar1 = FUN_8001ffb4(0x89d);
  if ((iVar1 != 0) && (iVar1 = FUN_8001ffb4(0x8a5), iVar1 == 0)) {
    FUN_800200e8(0x89d,0);
  }
  uVar3 = FUN_8001ffb4(0xd0b);
  *(byte *)((int)pfVar4 + 0xe) = (byte)((uVar3 & 0xff) << 7) | *(byte *)((int)pfVar4 + 0xe) & 0x7f;
  uVar3 = FUN_8001ffb4(0xd0c);
  *(byte *)((int)pfVar4 + 0xe) =
       (byte)((uVar3 & 0xff) << 6) & 0x40 | *(byte *)((int)pfVar4 + 0xe) & 0xbf;
  uVar3 = FUN_8001ffb4(0xd0d);
  *(byte *)((int)pfVar4 + 0xe) =
       (byte)((uVar3 & 0xff) << 5) & 0x20 | *(byte *)((int)pfVar4 + 0xe) & 0xdf;
  uVar3 = FUN_8001ffb4(0xd0e);
  *(byte *)((int)pfVar4 + 0xe) =
       (byte)((uVar3 & 0xff) << 4) & 0x10 | *(byte *)((int)pfVar4 + 0xe) & 0xef;
  uVar3 = FUN_8001ffb4(0xa21);
  *(byte *)((int)pfVar4 + 0xe) =
       (byte)((uVar3 & 0xff) << 3) & 8 | *(byte *)((int)pfVar4 + 0xe) & 0xf7;
  (**(code **)(*DAT_803dcaac + 0x44))((int)*(char *)(param_1 + 0xac),1);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  FUN_8004350c(0,0,1);
  return;
}

