// Function: FUN_80084c58
// Entry: 80084c58
// Size: 140 bytes

int FUN_80084c58(int param_1,uint param_2)

{
  int iVar1;
  int iVar2;
  char *pcVar3;
  
  iVar2 = 0;
  iVar1 = 0;
  do {
    if (*(short *)(param_1 + 0x62) <= iVar1) {
      return -1;
    }
    pcVar3 = (char *)(*(int *)(param_1 + 0x94) + iVar1 * 4);
    if (*pcVar3 == '\0') {
      iVar2 = (int)*(short *)(pcVar3 + 2);
    }
    else if ((*pcVar3 == '\v') && (0 < *(short *)(pcVar3 + 2))) {
      if (((*(uint *)(pcVar3 + 4) & 0x3f) == 9) && (*(uint *)(pcVar3 + 4) >> 0x10 == param_2)) {
        return iVar2;
      }
      iVar1 = iVar1 + *(short *)(pcVar3 + 2);
    }
    iVar2 = iVar2 + (uint)(byte)pcVar3[1];
    iVar1 = iVar1 + 1;
  } while( true );
}

