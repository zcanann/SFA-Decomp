// Function: FUN_801ac248
// Entry: 801ac248
// Size: 1148 bytes

void FUN_801ac248(int param_1)

{
  char cVar1;
  int iVar2;
  undefined *puVar3;
  
  puVar3 = *(undefined **)(param_1 + 0xb8);
  switch(*puVar3) {
  case 1:
    iVar2 = FUN_8001ffb4(0xadc);
    if ((iVar2 == 0) || (iVar2 = FUN_8001ffb4(0xadd), iVar2 == 0)) {
      iVar2 = FUN_8001ffb4(0x70);
      if (iVar2 != 0) {
        *puVar3 = 2;
        (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0xb,1);
      }
    }
    else {
      FUN_800200e8(0xade,1);
      *puVar3 = 2;
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0xb,1);
    }
    break;
  case 2:
    iVar2 = FUN_8001ffb4(0x70);
    if (iVar2 != 0) {
      *puVar3 = 3;
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),6,1);
    }
    break;
  case 3:
    iVar2 = FUN_8001ffb4(0x72);
    if (iVar2 != 0) {
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0,0);
    }
    iVar2 = FUN_8001ffb4(0x3a2);
    if (iVar2 != 0) {
      *puVar3 = 4;
      FUN_800200e8(0xe5d,1);
      FUN_800200e8(0xe5e,1);
      FUN_800200e8(0xe5f,1);
      FUN_800200e8(0xe60,1);
      FUN_800200e8(0xe61,1);
      FUN_800200e8(0xe62,1);
      FUN_800200e8(0xe63,1);
      FUN_800200e8(0xe64,1);
      FUN_800200e8(0xe65,1);
      FUN_800200e8(0xe66,1);
      FUN_800200e8(0xe67,1);
      FUN_800200e8(0xe68,1);
      FUN_800200e8(0xe69,1);
      FUN_800200e8(0xe6a,1);
      FUN_800200e8(0xe6b,1);
    }
    if (*(int *)(param_1 + 0xf4) == 0) {
      FUN_80008cbc(param_1,param_1,0xa3,0);
      FUN_80008cbc(param_1,param_1,0x9e,0);
      FUN_80008cbc(param_1,param_1,0x119,0);
      FUN_800066e0(param_1,param_1,0x15b,0,0,0);
      FUN_800066e0(param_1,param_1,0x15c,0,0,0);
      FUN_800066e0(param_1,param_1,0x17c,0,0,0);
      FUN_800066e0(param_1,param_1,0x17b,0,0,0);
      (**(code **)(*DAT_803dca64 + 0x1c))(1);
      *(undefined4 *)(param_1 + 0xf4) = 1;
    }
    break;
  case 4:
    FUN_801ac108(param_1,puVar3);
    break;
  case 5:
    if ((*(uint *)(puVar3 + 4) & 1) != 0) {
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),3,0);
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),4,0);
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),6,0);
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),7,0);
      *puVar3 = 0;
      (**(code **)(*DAT_803dcaac + 0x44))((int)*(char *)(param_1 + 0xac),2);
    }
    break;
  case 6:
    if ((*(uint *)(puVar3 + 4) & 1) != 0) {
      puVar3[8] = 2;
    }
    if (('\0' < (char)puVar3[8]) && (cVar1 = puVar3[8] + -1, puVar3[8] = cVar1, cVar1 == '\0')) {
      FUN_800200e8(0x4e5,0);
      FUN_800552e8(0x1a,0);
    }
    break;
  case 7:
    iVar2 = FUN_8001ffb4(0x6e);
    if (iVar2 != 0) {
      *puVar3 = 1;
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),2,0);
    }
  }
  return;
}

