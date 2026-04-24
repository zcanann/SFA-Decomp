// Function: FUN_80276e38
// Entry: 80276e38
// Size: 212 bytes

void FUN_80276e38(int param_1,uint *param_2)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  
  iVar5 = 0;
  *(undefined *)(param_1 + 0x104) = 0;
  uVar1 = *param_2;
  uVar3 = uVar1 >> 8 & 0xff;
  if (uVar3 != 0) {
    for (uVar4 = 0; uVar4 < DAT_803bd360; uVar4 = uVar4 + 1) {
      iVar2 = DAT_803de268 + iVar5;
      if (*(int *)(iVar2 + 0x34) != 0) {
        if (((*(uint *)(iVar2 + 0x118) & 2) == 0) && (uVar3 == *(byte *)(iVar2 + 0x104))) {
          if ((uVar1 >> 0x10 & 0xff) == 0) {
            FUN_80278610();
          }
          else {
            FUN_8027a02c(uVar4);
          }
        }
      }
      iVar5 = iVar5 + 0x404;
    }
    *(char *)(param_1 + 0x104) = (char)uVar3;
  }
  return;
}

