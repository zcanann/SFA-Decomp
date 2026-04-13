// Function: FUN_8006fd7c
// Entry: 8006fd7c
// Size: 204 bytes

void FUN_8006fd7c(int param_1)

{
  undefined *puVar1;
  undefined4 *puVar2;
  int iVar3;
  
  DAT_803ddc7a = (undefined)param_1;
  if (param_1 != 0) {
    return;
  }
  puVar2 = &DAT_80393a40;
  puVar1 = &DAT_80392a40;
  iVar3 = 0x10;
  do {
    *(undefined *)((int)puVar2 + 0x33) = 0;
    puVar1[0xe] = 0;
    *(undefined *)((int)puVar2 + 0x6b) = 0;
    puVar1[0x1e] = 0;
    *(undefined *)((int)puVar2 + 0xa3) = 0;
    puVar1[0x2e] = 0;
    *(undefined *)((int)puVar2 + 0xdb) = 0;
    puVar1[0x3e] = 0;
    *(undefined *)((int)puVar2 + 0x113) = 0;
    puVar1[0x4e] = 0;
    *(undefined *)((int)puVar2 + 0x14b) = 0;
    puVar1[0x5e] = 0;
    *(undefined *)((int)puVar2 + 0x183) = 0;
    puVar1[0x6e] = 0;
    *(undefined *)((int)puVar2 + 0x1bb) = 0;
    puVar1[0x7e] = 0;
    *(undefined *)((int)puVar2 + 499) = 0;
    puVar1[0x8e] = 0;
    *(undefined *)((int)puVar2 + 0x22b) = 0;
    puVar1[0x9e] = 0;
    *(undefined *)((int)puVar2 + 0x263) = 0;
    puVar1[0xae] = 0;
    *(undefined *)((int)puVar2 + 0x29b) = 0;
    puVar1[0xbe] = 0;
    *(undefined *)((int)puVar2 + 0x2d3) = 0;
    puVar1[0xce] = 0;
    *(undefined *)((int)puVar2 + 0x30b) = 0;
    puVar1[0xde] = 0;
    *(undefined *)((int)puVar2 + 0x343) = 0;
    puVar1[0xee] = 0;
    *(undefined *)((int)puVar2 + 0x37b) = 0;
    puVar1[0xfe] = 0;
    puVar2 = puVar2 + 0xe0;
    puVar1 = puVar1 + 0x100;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  DAT_803ddc79 = 0;
  DAT_803ddc78 = 0;
  return;
}

