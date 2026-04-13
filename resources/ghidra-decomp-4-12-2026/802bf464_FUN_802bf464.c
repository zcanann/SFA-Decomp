// Function: FUN_802bf464
// Entry: 802bf464
// Size: 804 bytes

void FUN_802bf464(void)

{
  short sVar1;
  float fVar2;
  short *psVar3;
  uint uVar4;
  int iVar5;
  uint *puVar6;
  uint *puVar7;
  undefined8 uVar8;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined2 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined2 local_20;
  
  uVar8 = FUN_80286840();
  psVar3 = (short *)((ulonglong)uVar8 >> 0x20);
  iVar5 = (int)uVar8;
  puVar7 = *(uint **)(psVar3 + 0x5c);
  local_38 = DAT_803e8f70;
  local_28 = DAT_802c3428;
  local_24 = DAT_802c342c;
  local_20 = DAT_802c3430;
  local_34 = DAT_802c3434;
  local_30 = DAT_802c3438;
  local_2c = DAT_802c343c;
  *psVar3 = (short)((int)*(char *)(iVar5 + 0x18) << 8);
  *(code **)(psVar3 + 0x5e) = FUN_802be358;
  FUN_800372f8((int)psVar3,10);
  *(undefined *)(puVar7 + 0x53a) = *(undefined *)(iVar5 + 0x19);
  *(undefined2 *)((int)puVar7 + 0x14de) = 5;
  *(undefined *)(puVar7 + 0x53d) = 0xff;
  (**(code **)(*DAT_803dd70c + 4))(psVar3,puVar7,4,1);
  *puVar7 = *puVar7 | 0x4000;
  puVar7[0xa9] = (uint)FLOAT_803e901c;
  puVar6 = puVar7 + 1;
  (**(code **)(*DAT_803dd728 + 4))(puVar6,0,0x48683,1);
  (**(code **)(*DAT_803dd728 + 0xc))(puVar6,4,&DAT_80335e64,&DAT_80335e94,&local_38);
  (**(code **)(*DAT_803dd728 + 8))(puVar6,1,&DAT_80335ea4,&DAT_80335ebc,8);
  *(undefined *)(puVar7 + 0x9a) = 0x28;
  (**(code **)(*DAT_803dd728 + 0x20))(psVar3,puVar6);
  FUN_80036018((int)psVar3);
  *(undefined2 *)(*(int *)(psVar3 + 0x2a) + 0xb2) = 9;
  FUN_80115200((int)psVar3,puVar7 + 0xfb,0xe000,0x31c7,2);
  FUN_80114238((int)(puVar7 + 0xfb),(wchar_t *)&local_34,(wchar_t *)&local_28);
  FUN_80114230((double)FLOAT_803e9020,(int)(puVar7 + 0xfb));
  *(byte *)((int)puVar7 + 0x9fd) = *(byte *)((int)puVar7 + 0x9fd) | 2;
  puVar7[0x511] = (uint)FLOAT_803e8f80;
  *(undefined2 *)((int)puVar7 + 0x14e2) = *(undefined2 *)(iVar5 + 0x1a);
  puVar7[0x3d4] = (uint)&DAT_80335f30;
  puVar7[0x3d6] = (uint)&DAT_80335edc;
  fVar2 = FLOAT_803e8fd0;
  puVar7[0x4e3] = (uint)FLOAT_803e8fd0;
  puVar7[0x4e1] = (uint)fVar2;
  puVar7[0x4e2] = (uint)FLOAT_803e9024;
  puVar7[0x3ea] = (uint)&DAT_80335f70;
  *(undefined *)(puVar7 + 0x50a) = 0x29;
  puVar7[0x3eb] = (uint)&DAT_80336014;
  *(undefined *)((int)puVar7 + 0x1429) = 0x29;
  puVar7[0x3ec] = (uint)&DAT_803360b8;
  *(undefined *)((int)puVar7 + 0x142a) = 0x2e;
  puVar7[0x3ed] = (uint)&DAT_80336014;
  *(undefined *)((int)puVar7 + 0x142b) = 0x29;
  puVar7[0x3ee] = (uint)&DAT_803360b8;
  *(undefined *)(puVar7 + 0x50b) = 0x2e;
  puVar7[0x4ce] = (uint)FLOAT_803e9028;
  sVar1 = *psVar3;
  puVar7[0x3fb] = (int)sVar1;
  puVar7[0x3f3] = (int)sVar1;
  *(short *)(puVar7 + 0x3f7) = sVar1;
  *(short *)(puVar7 + 0x3f4) = sVar1;
  *(byte *)(puVar7 + 0x53b) = *(byte *)(puVar7 + 0x53b) & 0xf7;
  *(undefined *)(puVar7 + 0x53d) = 2;
  FUN_800803f8(puVar7 + 0x53c);
  FUN_80080404((float *)(puVar7 + 0x53c),0x1e);
  *(byte *)(puVar7 + 0x53b) = *(byte *)(puVar7 + 0x53b) & 0xfd;
  *(undefined *)((int)puVar7 + 0x14f5) = 1;
  puVar7[0x2d5] = 0;
  uVar4 = FUN_80020078(0x9ec);
  if (uVar4 != 0) {
    *(undefined *)((int)puVar7 + 0x14ed) = 1;
  }
  uVar4 = FUN_80026dc0();
  puVar7[0x53e] = uVar4;
  FUN_80026cfc((double)FLOAT_803e8fbc,(double)FLOAT_803e8fb4,(double)FLOAT_803e902c,puVar7[0x53e]);
  *(code **)(psVar3 + 0x84) = FUN_802bcef8;
  FUN_80026cf4(puVar7[0x53e],1);
  FUN_8028688c();
  return;
}

