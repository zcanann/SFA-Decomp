// Function: FUN_8005ab2c
// Entry: 8005ab2c
// Size: 448 bytes

void FUN_8005ab2c(void)

{
  int iVar1;
  undefined2 *puVar2;
  float *pfVar3;
  float *pfVar4;
  float *pfVar5;
  float *pfVar6;
  double dVar7;
  float local_88;
  undefined4 local_84;
  float local_80;
  float afStack_7c [3];
  float local_70 [4];
  undefined4 local_60;
  float local_5c;
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
  
  FUN_80286840();
  local_5c = DAT_802c25d8;
  local_58 = DAT_802c25dc;
  local_54 = DAT_802c25e0;
  local_50 = DAT_802c25e4;
  local_4c = DAT_802c25e8;
  local_48 = DAT_802c25ec;
  local_44 = DAT_802c25f0;
  local_40 = DAT_802c25f4;
  local_3c = DAT_802c25f8;
  local_38 = DAT_802c25fc;
  local_34 = DAT_802c2600;
  local_30 = DAT_802c2604;
  local_2c = DAT_802c2608;
  local_28 = DAT_802c260c;
  local_24 = DAT_802c2610;
  local_70[0] = DAT_802c2614;
  local_70[1] = (float)DAT_802c2618;
  local_70[2] = (float)DAT_802c261c;
  local_70[3] = (float)DAT_802c2620;
  local_60 = DAT_802c2624;
  iVar1 = FUN_8002bac4();
  puVar2 = FUN_8000facc();
  local_88 = *(float *)(puVar2 + 0x22) - FLOAT_803dda58;
  local_84 = *(undefined4 *)(puVar2 + 0x24);
  local_80 = *(float *)(puVar2 + 0x26) - FLOAT_803dda5c;
  pfVar3 = (float *)FUN_8000f560();
  if (iVar1 == 0) {
    dVar7 = (double)FLOAT_803df874;
  }
  else {
    dVar7 = (double)FUN_8000f4a0((double)*(float *)(iVar1 + 0x18),(double)*(float *)(iVar1 + 0x1c),
                                 (double)*(float *)(iVar1 + 0x20));
    dVar7 = -dVar7;
  }
  local_70[0] = (float)dVar7;
  iVar1 = 0;
  pfVar6 = (float *)&DAT_80388538;
  pfVar5 = &local_5c;
  pfVar4 = local_70;
  do {
    FUN_80247bf8(pfVar3,pfVar5,pfVar6);
    FUN_80247edc((double)*pfVar4,pfVar6,afStack_7c);
    FUN_80247e94(&local_88,afStack_7c,afStack_7c);
    dVar7 = FUN_80247f90(afStack_7c,pfVar6);
    pfVar6[3] = (float)-dVar7;
    pfVar6 = pfVar6 + 5;
    pfVar5 = pfVar5 + 3;
    pfVar4 = pfVar4 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 5);
  FUN_8005aa20((float *)&DAT_80388538,5);
  FUN_8028688c();
  return;
}

