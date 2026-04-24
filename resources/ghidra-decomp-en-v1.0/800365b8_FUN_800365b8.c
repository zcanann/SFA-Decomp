// Function: FUN_800365b8
// Entry: 800365b8
// Size: 336 bytes

undefined4
FUN_800365b8(double param_1,double param_2,double param_3,int param_4,int param_5,char param_6,
            undefined param_7,undefined param_8)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  if (param_6 == '\0') {
    return 0;
  }
  iVar3 = *(int *)(param_4 + 0x54);
  if ((*(ushort *)(iVar3 + 0x60) & 1) == 0) {
    return 0;
  }
  if ((param_5 != 0) && (*(int *)(param_5 + 0x54) != 0)) {
    *(int *)(*(int *)(param_5 + 0x54) + 0x50) = param_4;
  }
  iVar2 = 0;
  while( true ) {
    iVar1 = (int)*(char *)(iVar3 + 0x71);
    if (iVar1 <= iVar2) break;
    iVar1 = iVar3 + iVar2 * 4;
    if (*(int *)(iVar1 + 0x7c) == param_5) {
      iVar2 = iVar3 + iVar2;
      if (param_6 < *(char *)(iVar2 + 0x75)) {
        *(undefined *)(iVar2 + 0x72) = param_8;
        *(char *)(iVar2 + 0x75) = param_6;
        *(undefined *)(iVar2 + 0x78) = param_7;
        *(float *)(iVar1 + 0x88) = (float)param_1;
        *(float *)(iVar1 + 0x94) = (float)param_2;
        *(float *)(iVar1 + 0xa0) = (float)param_3;
      }
      iVar2 = *(char *)(iVar3 + 0x71) + 1;
    }
    iVar2 = iVar2 + 1;
  }
  if ((iVar2 == iVar1) && (iVar1 < 3)) {
    *(undefined *)(iVar3 + iVar1 + 0x72) = param_8;
    *(char *)(iVar3 + *(char *)(iVar3 + 0x71) + 0x75) = param_6;
    *(undefined *)(iVar3 + *(char *)(iVar3 + 0x71) + 0x78) = param_7;
    *(int *)(iVar3 + *(char *)(iVar3 + 0x71) * 4 + 0x7c) = param_5;
    *(float *)(iVar3 + *(char *)(iVar3 + 0x71) * 4 + 0x88) = (float)param_1;
    *(float *)(iVar3 + *(char *)(iVar3 + 0x71) * 4 + 0x94) = (float)param_2;
    *(float *)(iVar3 + *(char *)(iVar3 + 0x71) * 4 + 0xa0) = (float)param_3;
    *(char *)(iVar3 + 0x71) = *(char *)(iVar3 + 0x71) + '\x01';
  }
  return 1;
}

