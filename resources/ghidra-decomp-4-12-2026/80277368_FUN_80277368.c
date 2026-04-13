// Function: FUN_80277368
// Entry: 80277368
// Size: 564 bytes

void FUN_80277368(int param_1,uint *param_2)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  int *piVar4;
  byte bVar5;
  int iVar6;
  int iVar7;
  
  uVar1 = param_2[1] >> 8 & 0x1f;
  if (uVar1 < 0x10) {
    iVar7 = *(int *)(param_1 + uVar1 * 4 + 0xac);
  }
  else {
    iVar7 = *(int *)(&DAT_803be654 + uVar1 * 4);
  }
  if ((*param_2 >> 8 & 0xff) == 0) {
    uVar1 = *param_2 >> 0x10;
    if (uVar1 == 0xffff) {
      if (DAT_803deeec != (code *)0x0) {
        (*DAT_803deeec)(*(undefined4 *)(*(int *)(param_1 + 0xf8) + 8),iVar7);
      }
    }
    else {
      iVar6 = 0;
      for (bVar5 = 0; bVar5 < DAT_803bdfc0; bVar5 = bVar5 + 1) {
        iVar2 = DAT_803deee8 + iVar6;
        if (((*(int *)(iVar2 + 0x34) != 0) && (uVar1 == *(ushort *)(iVar2 + 0x102))) &&
           (uVar3 = FUN_80279c00(*(uint *)(*(int *)(iVar2 + 0xf8) + 8)), uVar3 != 0xffffffff)) {
          piVar4 = (int *)(DAT_803deee8 + (uVar3 & 0xff) * 0x404);
          if (*(byte *)(piVar4 + 0xfb) < 4) {
            *(byte *)(piVar4 + 0xfb) = *(byte *)(piVar4 + 0xfb) + 1;
            piVar4[*(byte *)((int)piVar4 + 0x3ee) + 0xfc] = iVar7;
            *(byte *)((int)piVar4 + 0x3ee) = *(char *)((int)piVar4 + 0x3ee) + 1U & 3;
            if ((*(char *)(piVar4 + 0x1a) != '\0') && (piVar4[0x16] != 0)) {
              piVar4[0xe] = piVar4[0x19];
              piVar4[0xd] = piVar4[0x16];
              piVar4[0x16] = 0;
              FUN_802790f4(piVar4);
            }
          }
        }
        iVar6 = iVar6 + 0x404;
      }
    }
  }
  else {
    uVar1 = param_2[1] & 0x1f;
    if (uVar1 < 0x10) {
      uVar1 = *(uint *)(param_1 + uVar1 * 4 + 0xac);
    }
    else {
      uVar1 = *(uint *)(&DAT_803be654 + uVar1 * 4);
    }
    uVar1 = FUN_80279c00(uVar1);
    if (uVar1 != 0xffffffff) {
      piVar4 = (int *)(DAT_803deee8 + (uVar1 & 0xff) * 0x404);
      if (*(byte *)(piVar4 + 0xfb) < 4) {
        *(byte *)(piVar4 + 0xfb) = *(byte *)(piVar4 + 0xfb) + 1;
        piVar4[*(byte *)((int)piVar4 + 0x3ee) + 0xfc] = iVar7;
        *(byte *)((int)piVar4 + 0x3ee) = *(char *)((int)piVar4 + 0x3ee) + 1U & 3;
        if ((*(char *)(piVar4 + 0x1a) != '\0') && (piVar4[0x16] != 0)) {
          piVar4[0xe] = piVar4[0x19];
          piVar4[0xd] = piVar4[0x16];
          piVar4[0x16] = 0;
          FUN_802790f4(piVar4);
        }
      }
    }
  }
  return;
}

