// Function: FUN_801af38c
// Entry: 801af38c
// Size: 476 bytes

void FUN_801af38c(int param_1)

{
  int iVar1;
  char cVar2;
  uint *puVar3;
  
  puVar3 = *(uint **)(param_1 + 0xb8);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  iVar1 = FUN_8001ffb4(0x36e);
  if (iVar1 != 0) {
    *puVar3 = *puVar3 & 4;
  }
  iVar1 = FUN_8001ffb4(0x543);
  if (iVar1 == 0) {
    iVar1 = FUN_8001ffb4(0x387);
    if (iVar1 == 0) {
      iVar1 = FUN_8001ffb4(0x386);
      if (iVar1 == 0) {
        iVar1 = FUN_8001ffb4(0x385);
        if (iVar1 == 0) {
          iVar1 = FUN_8001ffb4(900);
          if (iVar1 != 0) {
            *(byte *)(puVar3 + 1) = *(byte *)(puVar3 + 1) & 199 | 8;
          }
        }
        else {
          *(byte *)(puVar3 + 1) = *(byte *)(puVar3 + 1) & 199 | 0x10;
        }
      }
      else {
        *(byte *)(puVar3 + 1) = *(byte *)(puVar3 + 1) & 199 | 0x18;
      }
    }
    else {
      *(byte *)(puVar3 + 1) = *(byte *)(puVar3 + 1) & 199 | 0x20;
    }
  }
  else {
    *(byte *)(puVar3 + 1) = *(byte *)(puVar3 + 1) & 199 | 0x28;
  }
  FUN_80088870(&DAT_80323910,&DAT_803238d8,&DAT_80323948,&DAT_80323980);
  iVar1 = FUN_800e87c4();
  if (iVar1 == 0) {
    cVar2 = (**(code **)(*DAT_803dcaac + 0x4c))((int)*(char *)(param_1 + 0xac),0);
    if (cVar2 == '\0') {
      FUN_800887f8(0x1f);
    }
    FUN_80008cbc(0,0,0x23c,0);
  }
  else {
    cVar2 = (**(code **)(*DAT_803dcaac + 0x4c))((int)*(char *)(param_1 + 0xac),0);
    if (cVar2 == '\0') {
      FUN_800887f8(0x3f);
    }
    FUN_80008b74(0,0,0x23c,0);
  }
  *(undefined2 *)(puVar3 + 3) = 0;
  return;
}

