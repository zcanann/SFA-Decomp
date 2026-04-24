// Function: FUN_8005a9b0
// Entry: 8005a9b0
// Size: 448 bytes

void FUN_8005a9b0(void)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  float *pfVar4;
  undefined4 *puVar5;
  undefined *puVar6;
  double dVar7;
  float local_88;
  undefined4 local_84;
  float local_80;
  undefined auStack124 [12];
  float local_70 [4];
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  FUN_802860dc();
  local_5c = DAT_802c1e58;
  local_58 = DAT_802c1e5c;
  local_54 = DAT_802c1e60;
  local_50 = DAT_802c1e64;
  local_4c = DAT_802c1e68;
  local_48 = DAT_802c1e6c;
  local_44 = DAT_802c1e70;
  local_40 = DAT_802c1e74;
  local_3c = DAT_802c1e78;
  local_38 = DAT_802c1e7c;
  local_34 = DAT_802c1e80;
  local_30 = DAT_802c1e84;
  local_2c = DAT_802c1e88;
  local_28 = DAT_802c1e8c;
  local_24 = DAT_802c1e90;
  local_70[0] = DAT_802c1e94;
  local_70[1] = (float)DAT_802c1e98;
  local_70[2] = (float)DAT_802c1e9c;
  local_70[3] = (float)DAT_802c1ea0;
  local_60 = DAT_802c1ea4;
  iVar1 = FUN_8002b9ec();
  iVar2 = FUN_8000faac();
  local_88 = *(float *)(iVar2 + 0x44) - FLOAT_803dcdd8;
  local_84 = *(undefined4 *)(iVar2 + 0x48);
  local_80 = *(float *)(iVar2 + 0x4c) - FLOAT_803dcddc;
  uVar3 = FUN_8000f540();
  if (iVar1 == 0) {
    dVar7 = (double)FLOAT_803debf4;
  }
  else {
    dVar7 = (double)FUN_8000f480((double)*(float *)(iVar1 + 0x18),(double)*(float *)(iVar1 + 0x1c),
                                 (double)*(float *)(iVar1 + 0x20));
    dVar7 = -dVar7;
  }
  local_70[0] = (float)dVar7;
  iVar1 = 0;
  puVar6 = &DAT_803878d8;
  puVar5 = &local_5c;
  pfVar4 = local_70;
  do {
    FUN_80247494(uVar3,puVar5,puVar6);
    FUN_80247778((double)*pfVar4,puVar6,auStack124);
    FUN_80247730(&local_88,auStack124,auStack124);
    dVar7 = (double)FUN_8024782c(auStack124,puVar6);
    *(float *)(puVar6 + 0xc) = (float)-dVar7;
    puVar6 = puVar6 + 0x14;
    puVar5 = puVar5 + 3;
    pfVar4 = pfVar4 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 5);
  FUN_8005a8a4(&DAT_803878d8,5);
  FUN_80286128();
  return;
}

