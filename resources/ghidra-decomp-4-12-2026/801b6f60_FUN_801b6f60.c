// Function: FUN_801b6f60
// Entry: 801b6f60
// Size: 408 bytes

void FUN_801b6f60(int param_1)

{
  int iVar1;
  uint uVar2;
  byte bVar3;
  float *pfVar4;
  
  FUN_80022264(0,0xb);
  pfVar4 = *(float **)(param_1 + 0xb8);
  *(undefined *)(pfVar4 + 2) = 0;
  *pfVar4 = FLOAT_803e56c0;
  iVar1 = FUN_800e8a48();
  if (iVar1 == 0) {
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  else {
    *(undefined4 *)(param_1 + 0xf4) = 2;
  }
  for (bVar3 = 1; bVar3 < 0x27; bVar3 = bVar3 + 1) {
    FUN_800ea564();
  }
  uVar2 = FUN_80020078(0xdc);
  *(char *)(pfVar4 + 3) = (char)uVar2;
  FUN_800201ac(0xf0a,0);
  uVar2 = FUN_80020078(0x89d);
  if ((uVar2 != 0) && (uVar2 = FUN_80020078(0x8a5), uVar2 == 0)) {
    FUN_800201ac(0x89d,0);
  }
  uVar2 = FUN_80020078(0xd0b);
  *(byte *)((int)pfVar4 + 0xe) = (byte)((uVar2 & 0xff) << 7) | *(byte *)((int)pfVar4 + 0xe) & 0x7f;
  uVar2 = FUN_80020078(0xd0c);
  *(byte *)((int)pfVar4 + 0xe) =
       (byte)((uVar2 & 0xff) << 6) & 0x40 | *(byte *)((int)pfVar4 + 0xe) & 0xbf;
  uVar2 = FUN_80020078(0xd0d);
  *(byte *)((int)pfVar4 + 0xe) =
       (byte)((uVar2 & 0xff) << 5) & 0x20 | *(byte *)((int)pfVar4 + 0xe) & 0xdf;
  uVar2 = FUN_80020078(0xd0e);
  *(byte *)((int)pfVar4 + 0xe) =
       (byte)((uVar2 & 0xff) << 4) & 0x10 | *(byte *)((int)pfVar4 + 0xe) & 0xef;
  uVar2 = FUN_80020078(0xa21);
  *(byte *)((int)pfVar4 + 0xe) =
       (byte)((uVar2 & 0xff) << 3) & 8 | *(byte *)((int)pfVar4 + 0xe) & 0xf7;
  (**(code **)(*DAT_803dd72c + 0x44))((int)*(char *)(param_1 + 0xac),1);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  FUN_80043604(0,0,1);
  return;
}

