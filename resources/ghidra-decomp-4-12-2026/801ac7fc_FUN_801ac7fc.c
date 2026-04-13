// Function: FUN_801ac7fc
// Entry: 801ac7fc
// Size: 1148 bytes

void FUN_801ac7fc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  char cVar1;
  uint uVar2;
  undefined *puVar3;
  undefined8 uVar4;
  
  puVar3 = *(undefined **)(param_9 + 0xb8);
  switch(*puVar3) {
  case 1:
    uVar2 = FUN_80020078(0xadc);
    if ((uVar2 == 0) || (uVar2 = FUN_80020078(0xadd), uVar2 == 0)) {
      uVar2 = FUN_80020078(0x70);
      if (uVar2 != 0) {
        *puVar3 = 2;
        (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0xb,1);
      }
    }
    else {
      FUN_800201ac(0xade,1);
      *puVar3 = 2;
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0xb,1);
    }
    break;
  case 2:
    uVar2 = FUN_80020078(0x70);
    if (uVar2 != 0) {
      *puVar3 = 3;
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),6,1);
    }
    break;
  case 3:
    uVar2 = FUN_80020078(0x72);
    if (uVar2 != 0) {
      param_1 = (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0,0);
    }
    uVar2 = FUN_80020078(0x3a2);
    if (uVar2 != 0) {
      *puVar3 = 4;
      FUN_800201ac(0xe5d,1);
      FUN_800201ac(0xe5e,1);
      FUN_800201ac(0xe5f,1);
      FUN_800201ac(0xe60,1);
      FUN_800201ac(0xe61,1);
      FUN_800201ac(0xe62,1);
      FUN_800201ac(0xe63,1);
      FUN_800201ac(0xe64,1);
      FUN_800201ac(0xe65,1);
      FUN_800201ac(0xe66,1);
      FUN_800201ac(0xe67,1);
      FUN_800201ac(0xe68,1);
      FUN_800201ac(0xe69,1);
      FUN_800201ac(0xe6a,1);
      param_1 = FUN_800201ac(0xe6b,1);
    }
    if (*(int *)(param_9 + 0xf4) == 0) {
      uVar4 = FUN_80008cbc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0xa3,0,param_13,param_14,param_15,param_16);
      uVar4 = FUN_80008cbc(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0x9e,0,param_13,param_14,param_15,param_16);
      uVar4 = FUN_80008cbc(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0x119,0,param_13,param_14,param_15,param_16);
      FUN_800066e0(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x15b,0,0,0,param_15,param_16);
      FUN_800066e0(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x15c,0,0,0,param_15,param_16);
      FUN_800066e0(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x17c,0,0,0,param_15,param_16);
      FUN_800066e0(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x17b,0,0,0,param_15,param_16);
      (**(code **)(*DAT_803dd6e4 + 0x1c))(1);
      *(undefined4 *)(param_9 + 0xf4) = 1;
    }
    break;
  case 4:
    FUN_801ac6bc(param_9,puVar3);
    break;
  case 5:
    if ((*(uint *)(puVar3 + 4) & 1) != 0) {
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),3,0);
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),4,0);
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),6,0);
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),7,0);
      *puVar3 = 0;
      (**(code **)(*DAT_803dd72c + 0x44))((int)*(char *)(param_9 + 0xac),2);
    }
    break;
  case 6:
    if ((*(uint *)(puVar3 + 4) & 1) != 0) {
      puVar3[8] = 2;
    }
    if (('\0' < (char)puVar3[8]) && (cVar1 = puVar3[8] + -1, puVar3[8] = cVar1, cVar1 == '\0')) {
      uVar4 = FUN_800201ac(0x4e5,0);
      FUN_80055464(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x1a,'\0',param_11,
                   param_12,param_13,param_14,param_15,param_16);
    }
    break;
  case 7:
    uVar2 = FUN_80020078(0x6e);
    if (uVar2 != 0) {
      *puVar3 = 1;
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),2,0);
    }
  }
  return;
}

