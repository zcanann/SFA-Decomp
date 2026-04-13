// Function: FUN_8027759c
// Entry: 8027759c
// Size: 212 bytes

void FUN_8027759c(int param_1,uint *param_2)

{
  uint uVar1;
  int *piVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  
  iVar5 = 0;
  *(undefined *)(param_1 + 0x104) = 0;
  uVar1 = *param_2;
  uVar3 = uVar1 >> 8 & 0xff;
  if (uVar3 != 0) {
    for (uVar4 = 0; uVar4 < DAT_803bdfc0; uVar4 = uVar4 + 1) {
      piVar2 = (int *)(DAT_803deee8 + iVar5);
      if (((piVar2[0xd] != 0) && ((piVar2[0x46] & 2U) == 0)) && (uVar3 == *(byte *)(piVar2 + 0x41)))
      {
        if ((uVar1 >> 0x10 & 0xff) == 0) {
          FUN_80278d74(piVar2);
        }
        else {
          FUN_8027a790(uVar4);
        }
      }
      iVar5 = iVar5 + 0x404;
    }
    *(char *)(param_1 + 0x104) = (char)(uVar1 >> 8);
  }
  return;
}

