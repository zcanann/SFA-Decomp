// Function: FUN_801acf74
// Entry: 801acf74
// Size: 828 bytes

void FUN_801acf74(int param_1)

{
  uint uVar1;
  undefined uVar2;
  byte bVar3;
  undefined *puVar4;
  
  puVar4 = *(undefined **)(param_1 + 0xb8);
  *(code **)(param_1 + 0xbc) = FUN_801acc78;
  for (bVar3 = 1; bVar3 < 0xe; bVar3 = bVar3 + 1) {
    FUN_800ea564();
  }
  *(float *)(puVar4 + 0x10) = FLOAT_803e5378;
  (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),1,0);
  (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),5,1);
  FUN_80043604(0,0,1);
  uVar1 = FUN_80020078(0x379);
  if (uVar1 != 0) {
    (**(code **)(*DAT_803dd72c + 0x44))((int)*(char *)(param_1 + 0xac),2);
  }
  uVar2 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0xac));
  puVar4[0xc] = uVar2;
  bVar3 = puVar4[0xc];
  if (bVar3 == 2) {
    FUN_800201ac(0x3a3,0);
    FUN_800201ac(0x3a2,0);
    FUN_800201ac(0xce,0);
    FUN_800201ac(0x37b,0);
    FUN_800201ac(200,0);
    FUN_800201ac(0x374,0);
    FUN_800201ac(0x37c,0);
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),2,0);
  }
  else if ((bVar3 < 2) && (bVar3 != 0)) {
    uVar1 = FUN_80020078(0x72);
    if (uVar1 == 0) {
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),0,1);
      uVar1 = FUN_80020078(0xadc);
      if ((uVar1 != 0) && (uVar1 = FUN_80020078(0xadd), uVar1 != 0)) {
        (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),0xb,1);
      }
      uVar1 = FUN_80020078(0x6e);
      if (uVar1 == 0) {
        (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),2,1);
        *puVar4 = 7;
      }
      else {
        *puVar4 = 1;
      }
    }
    else {
      uVar1 = FUN_80020078(0x379);
      if (uVar1 == 0) {
        FUN_800201ac(0x3a3,0);
        FUN_800201ac(0x3a2,0);
        FUN_800201ac(0xcb,0);
        FUN_800201ac(0x379,0);
        *puVar4 = 3;
      }
      else {
        *puVar4 = 5;
      }
    }
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),3,1);
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),4,1);
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),7,1);
  }
  return;
}

