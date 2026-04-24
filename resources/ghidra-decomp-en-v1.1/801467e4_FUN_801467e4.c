// Function: FUN_801467e4
// Entry: 801467e4
// Size: 464 bytes

void FUN_801467e4(void)

{
  byte bVar1;
  undefined2 *puVar2;
  char in_r8;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  puVar2 = (undefined2 *)FUN_80286830();
  if (in_r8 != '\0') {
    iVar6 = *(int *)(puVar2 + 0x5c);
    FUN_8003b9ec((int)puVar2);
    iVar4 = *(int *)(puVar2 + 0x5c);
    iVar5 = 0;
    iVar3 = iVar4;
    do {
      FUN_80038524(puVar2,iVar5 + 4,(float *)(iVar3 + 0x3d8),(undefined4 *)(iVar3 + 0x3dc),
                   (float *)(iVar3 + 0x3e0),0);
      iVar3 = iVar3 + 0xc;
      iVar5 = iVar5 + 1;
    } while (iVar5 < 4);
    FUN_80038524(puVar2,8,(float *)(iVar4 + 0x408),(undefined4 *)(iVar4 + 0x40c),
                 (float *)(iVar4 + 0x410),0);
    iVar3 = FUN_800396d0((int)puVar2,0);
    *(undefined2 *)(iVar4 + 0x414) = *(undefined2 *)(iVar3 + 2);
    if ((*(uint *)(iVar6 + 0x54) & 0x10) != 0) {
      bVar1 = *(byte *)(iVar6 + 8);
      if (bVar1 == 3) {
        if (*(char *)(iVar6 + 10) == '\x04') {
          FUN_8013b184(puVar2);
        }
      }
      else if ((bVar1 < 3) && (1 < bVar1)) {
        FUN_8013b184(puVar2);
      }
      if ((((*(uint *)(iVar6 + 0x54) & 0x200) == 0) && (*(char *)(iVar6 + 8) == '\v')) &&
         (2 < *(byte *)(iVar6 + 10))) {
        if (*(byte *)(iVar6 + 10) != 3) {
          *(undefined4 *)(*(int *)(iVar6 + 0x700) + 0xc) = *(undefined4 *)(iVar6 + 0x408);
          *(undefined4 *)(*(int *)(iVar6 + 0x700) + 0x10) = *(undefined4 *)(iVar6 + 0x40c);
          *(undefined4 *)(*(int *)(iVar6 + 0x700) + 0x14) = *(undefined4 *)(iVar6 + 0x410);
        }
        FUN_8003b9ec(*(int *)(iVar6 + 0x700));
      }
    }
    FUN_801394ec(puVar2,iVar6);
    FUN_80038378(puVar2,4,4,(float *)(iVar6 + 0x7d8));
    *(float *)(iVar6 + 0x838) = *(float *)(iVar6 + 0x838) - FLOAT_803dc074;
    if (FLOAT_803e306c < *(float *)(iVar6 + 0x838)) {
      FUN_8009a010((double)FLOAT_803e31cc,(double)FLOAT_803e3078,puVar2,6,(int *)0x0);
    }
  }
  FUN_8028687c();
  return;
}

