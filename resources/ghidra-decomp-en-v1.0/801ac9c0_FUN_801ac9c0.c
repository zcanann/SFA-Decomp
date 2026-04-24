// Function: FUN_801ac9c0
// Entry: 801ac9c0
// Size: 828 bytes

void FUN_801ac9c0(int param_1)

{
  byte bVar1;
  int iVar2;
  undefined uVar3;
  uint uVar4;
  undefined *puVar5;
  
  puVar5 = *(undefined **)(param_1 + 0xb8);
  *(code **)(param_1 + 0xbc) = FUN_801ac6c4;
  for (uVar4 = 1; (uVar4 & 0xff) < 0xe; uVar4 = uVar4 + 1) {
    FUN_800ea2e0(uVar4);
  }
  *(float *)(puVar5 + 0x10) = FLOAT_803e46e0;
  (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),1,0);
  (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),5,1);
  FUN_8004350c(0,0,1);
  iVar2 = FUN_8001ffb4(0x379);
  if (iVar2 != 0) {
    (**(code **)(*DAT_803dcaac + 0x44))((int)*(char *)(param_1 + 0xac),2);
  }
  uVar3 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
  puVar5[0xc] = uVar3;
  bVar1 = puVar5[0xc];
  if (bVar1 == 2) {
    FUN_800200e8(0x3a3,0);
    FUN_800200e8(0x3a2,0);
    FUN_800200e8(0xce,0);
    FUN_800200e8(0x37b,0);
    FUN_800200e8(200,0);
    FUN_800200e8(0x374,0);
    FUN_800200e8(0x37c,0);
    (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),2,0);
  }
  else if ((bVar1 < 2) && (bVar1 != 0)) {
    iVar2 = FUN_8001ffb4(0x72);
    if (iVar2 == 0) {
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0,1);
      iVar2 = FUN_8001ffb4(0xadc);
      if ((iVar2 != 0) && (iVar2 = FUN_8001ffb4(0xadd), iVar2 != 0)) {
        (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0xb,1);
      }
      iVar2 = FUN_8001ffb4(0x6e);
      if (iVar2 == 0) {
        (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),2,1);
        *puVar5 = 7;
      }
      else {
        *puVar5 = 1;
      }
    }
    else {
      iVar2 = FUN_8001ffb4(0x379);
      if (iVar2 == 0) {
        FUN_800200e8(0x3a3,0);
        FUN_800200e8(0x3a2,0);
        FUN_800200e8(0xcb,0);
        FUN_800200e8(0x379,0);
        *puVar5 = 3;
      }
      else {
        *puVar5 = 5;
      }
    }
    (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),3,1);
    (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),4,1);
    (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),7,1);
  }
  return;
}

