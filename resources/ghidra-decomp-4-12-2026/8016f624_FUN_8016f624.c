// Function: FUN_8016f624
// Entry: 8016f624
// Size: 232 bytes

undefined4 FUN_8016f624(int param_1,undefined4 param_2,int param_3)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  if ((*(byte *)(piVar2 + 0x1c) & 8) == 0) {
    for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
      cVar1 = *(char *)(param_3 + iVar3 + 0x81);
      if (cVar1 == '\x01') {
        if (*piVar2 != 0) {
          FUN_8001dc30((double)FLOAT_803e3fc8,*piVar2,'\x01');
        }
        *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
      }
      else if (cVar1 == '\x02') {
        if (*piVar2 != 0) {
          FUN_8001dc30((double)FLOAT_803e3fc8,*piVar2,'\0');
        }
        *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
      }
    }
  }
  return 0;
}

