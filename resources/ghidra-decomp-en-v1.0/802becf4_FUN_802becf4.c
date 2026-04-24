// Function: FUN_802becf4
// Entry: 802becf4
// Size: 804 bytes

void FUN_802becf4(void)

{
  short sVar1;
  float fVar2;
  short *psVar3;
  int iVar4;
  uint uVar5;
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
  
  uVar8 = FUN_802860dc();
  psVar3 = (short *)((ulonglong)uVar8 >> 0x20);
  iVar4 = (int)uVar8;
  puVar7 = *(uint **)(psVar3 + 0x5c);
  local_38 = DAT_803e82d8;
  local_28 = DAT_802c2ca8;
  local_24 = DAT_802c2cac;
  local_20 = DAT_802c2cb0;
  local_34 = DAT_802c2cb4;
  local_30 = DAT_802c2cb8;
  local_2c = DAT_802c2cbc;
  *psVar3 = (short)((int)*(char *)(iVar4 + 0x18) << 8);
  *(code **)(psVar3 + 0x5e) = FUN_802bdbe8;
  FUN_80037200(psVar3,10);
  *(undefined *)(puVar7 + 0x53a) = *(undefined *)(iVar4 + 0x19);
  *(undefined2 *)((int)puVar7 + 0x14de) = 5;
  *(undefined *)(puVar7 + 0x53d) = 0xff;
  (**(code **)(*DAT_803dca8c + 4))(psVar3,puVar7,4,1);
  *puVar7 = *puVar7 | 0x4000;
  puVar7[0xa9] = (uint)FLOAT_803e8384;
  puVar6 = puVar7 + 1;
  (**(code **)(*DAT_803dcaa8 + 4))(puVar6,0,0x48683,1);
  (**(code **)(*DAT_803dcaa8 + 0xc))(puVar6,4,&DAT_80335204,&DAT_80335234,&local_38);
  (**(code **)(*DAT_803dcaa8 + 8))(puVar6,1,&DAT_80335244,&DAT_8033525c,8);
  *(undefined *)(puVar7 + 0x9a) = 0x28;
  (**(code **)(*DAT_803dcaa8 + 0x20))(psVar3,puVar6);
  FUN_80035f20(psVar3);
  *(undefined2 *)(*(int *)(psVar3 + 0x2a) + 0xb2) = 9;
  FUN_80114f64(psVar3,puVar7 + 0xfb,0xffffe000,0x31c7,2);
  FUN_80113f9c(puVar7 + 0xfb,&local_34,&local_28,2);
  FUN_80113f94((double)FLOAT_803e8388,puVar7 + 0xfb);
  *(byte *)((int)puVar7 + 0x9fd) = *(byte *)((int)puVar7 + 0x9fd) | 2;
  puVar7[0x511] = (uint)FLOAT_803e82e8;
  *(undefined2 *)((int)puVar7 + 0x14e2) = *(undefined2 *)(iVar4 + 0x1a);
  puVar7[0x3d4] = (uint)&DAT_803352d0;
  puVar7[0x3d6] = (uint)&DAT_8033527c;
  fVar2 = FLOAT_803e8338;
  puVar7[0x4e3] = (uint)FLOAT_803e8338;
  puVar7[0x4e1] = (uint)fVar2;
  puVar7[0x4e2] = (uint)FLOAT_803e838c;
  puVar7[0x3ea] = (uint)&DAT_80335310;
  *(undefined *)(puVar7 + 0x50a) = 0x29;
  puVar7[0x3eb] = (uint)&DAT_803353b4;
  *(undefined *)((int)puVar7 + 0x1429) = 0x29;
  puVar7[0x3ec] = (uint)&DAT_80335458;
  *(undefined *)((int)puVar7 + 0x142a) = 0x2e;
  puVar7[0x3ed] = (uint)&DAT_803353b4;
  *(undefined *)((int)puVar7 + 0x142b) = 0x29;
  puVar7[0x3ee] = (uint)&DAT_80335458;
  *(undefined *)(puVar7 + 0x50b) = 0x2e;
  puVar7[0x4ce] = (uint)FLOAT_803e8390;
  sVar1 = *psVar3;
  puVar7[0x3fb] = (int)sVar1;
  puVar7[0x3f3] = (int)sVar1;
  *(short *)(puVar7 + 0x3f7) = sVar1;
  *(short *)(puVar7 + 0x3f4) = sVar1;
  *(byte *)(puVar7 + 0x53b) = *(byte *)(puVar7 + 0x53b) & 0xf7;
  *(undefined *)(puVar7 + 0x53d) = 2;
  FUN_8008016c(puVar7 + 0x53c);
  FUN_80080178(puVar7 + 0x53c,0x1e);
  *(byte *)(puVar7 + 0x53b) = *(byte *)(puVar7 + 0x53b) & 0xfd;
  *(undefined *)((int)puVar7 + 0x14f5) = 1;
  puVar7[0x2d5] = 0;
  iVar4 = FUN_8001ffb4(0x9ec);
  if (iVar4 != 0) {
    *(undefined *)((int)puVar7 + 0x14ed) = 1;
  }
  uVar5 = FUN_80026cfc(&DAT_803dc768,1);
  puVar7[0x53e] = uVar5;
  FUN_80026c38((double)FLOAT_803e8324,(double)FLOAT_803e831c,(double)FLOAT_803e8394,puVar7[0x53e]);
  *(code **)(psVar3 + 0x84) = FUN_802bc788;
  FUN_80026c30(puVar7[0x53e],1);
  FUN_80286128();
  return;
}

