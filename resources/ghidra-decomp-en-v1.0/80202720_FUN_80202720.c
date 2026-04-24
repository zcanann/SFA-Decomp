// Function: FUN_80202720
// Entry: 80202720
// Size: 416 bytes

void FUN_80202720(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar6 >> 0x20);
  iVar2 = (int)uVar6;
  iVar5 = *(int *)(iVar1 + 0xb8);
  iVar3 = *(int *)(iVar1 + 0x4c);
  iVar4 = *(int *)(iVar5 + 0x40c);
  if (*(char *)(iVar2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e62a8,iVar1,0xe,0);
    *(undefined *)(iVar2 + 0x346) = 0;
  }
  *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) | 8;
  if (FLOAT_803e634c < *(float *)(iVar1 + 0x98)) {
    *(byte *)(iVar4 + 0x14) = *(byte *)(iVar4 + 0x14) | 2;
    FUN_80035f00(iVar1);
  }
  if (*(char *)(iVar2 + 0x27a) != '\0') {
    *(float *)(iVar2 + 0x2a0) = FLOAT_803e62f4;
    *(float *)(iVar2 + 0x280) = FLOAT_803e62a8;
  }
  if (*(char *)(iVar2 + 0x346) != '\0') {
    FUN_8000bb18(iVar1,0x1ea);
    *(float *)(iVar4 + 4) = FLOAT_803e62c8;
    FUN_80030334((double)FLOAT_803e62a8,iVar1,8,0);
    *(undefined4 *)(iVar2 + 0x2d0) = 0;
    *(undefined *)(iVar2 + 0x25f) = 0;
    *(undefined *)(iVar2 + 0x349) = 0;
    *(undefined2 *)(iVar5 + 0x402) = 0;
    *(byte *)(iVar5 + 0x404) = *(byte *)(iVar5 + 0x404) | *(byte *)(iVar3 + 0x2b);
    if (*(int *)(iVar4 + 0x18) != 0) {
      FUN_800378c4(*(int *)(iVar4 + 0x18),0x11,iVar1,0x13);
      *(undefined4 *)(iVar4 + 0x18) = 0;
      *(undefined2 *)(iVar4 + 0x1c) = 0xffff;
    }
    if ((*(byte *)(iVar4 + 0x15) & 2) == 0) {
      *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) | 8;
    }
    *(undefined *)(iVar4 + 0x34) = 1;
  }
  (**(code **)(*DAT_803dca8c + 0x34))(iVar1,iVar2,7,0,&DAT_80329640);
  FUN_80286128(0);
  return;
}

