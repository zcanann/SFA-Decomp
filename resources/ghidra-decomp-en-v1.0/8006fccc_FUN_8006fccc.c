// Function: FUN_8006fccc
// Entry: 8006fccc
// Size: 300 bytes

void FUN_8006fccc(void)

{
  undefined4 *puVar1;
  undefined *puVar2;
  int iVar3;
  
  puVar1 = &DAT_80392de0;
  puVar2 = &DAT_80391de0;
  iVar3 = 0x10;
  do {
    *(undefined *)((int)puVar1 + 0x33) = 0;
    puVar2[0xe] = 0;
    *(undefined *)((int)puVar1 + 0x6b) = 0;
    puVar2[0x1e] = 0;
    *(undefined *)((int)puVar1 + 0xa3) = 0;
    puVar2[0x2e] = 0;
    *(undefined *)((int)puVar1 + 0xdb) = 0;
    puVar2[0x3e] = 0;
    *(undefined *)((int)puVar1 + 0x113) = 0;
    puVar2[0x4e] = 0;
    *(undefined *)((int)puVar1 + 0x14b) = 0;
    puVar2[0x5e] = 0;
    *(undefined *)((int)puVar1 + 0x183) = 0;
    puVar2[0x6e] = 0;
    *(undefined *)((int)puVar1 + 0x1bb) = 0;
    puVar2[0x7e] = 0;
    *(undefined *)((int)puVar1 + 499) = 0;
    puVar2[0x8e] = 0;
    *(undefined *)((int)puVar1 + 0x22b) = 0;
    puVar2[0x9e] = 0;
    *(undefined *)((int)puVar1 + 0x263) = 0;
    puVar2[0xae] = 0;
    *(undefined *)((int)puVar1 + 0x29b) = 0;
    puVar2[0xbe] = 0;
    *(undefined *)((int)puVar1 + 0x2d3) = 0;
    puVar2[0xce] = 0;
    *(undefined *)((int)puVar1 + 0x30b) = 0;
    puVar2[0xde] = 0;
    *(undefined *)((int)puVar1 + 0x343) = 0;
    puVar2[0xee] = 0;
    *(undefined *)((int)puVar1 + 0x37b) = 0;
    puVar2[0xfe] = 0;
    puVar1 = puVar1 + 0xe0;
    puVar2 = puVar2 + 0x100;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  DAT_80391dd0 = FUN_80054d54(0x19);
  DAT_80391dd4 = FUN_80054d54(0x18);
  DAT_80391dd8 = FUN_80054d54(0x1a);
  DAT_80391ddc = FUN_80054d54(0x646);
  DAT_80391dc0 = FLOAT_803dee5c;
  DAT_80391dc4 = FLOAT_803dee60;
  DAT_80391dc8 = FLOAT_803dee60;
  DAT_80391dcc = FLOAT_803dee64;
  DAT_803dcff4 = 0;
  DAT_803dcff8 = 0;
  DAT_803dcff9 = 0;
  DAT_803dcffa = 0;
  return;
}

