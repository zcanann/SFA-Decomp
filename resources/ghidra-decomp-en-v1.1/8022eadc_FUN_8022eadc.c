// Function: FUN_8022eadc
// Entry: 8022eadc
// Size: 308 bytes

void FUN_8022eadc(int param_1,char param_2)

{
  int *piVar1;
  int iVar2;
  double dVar3;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if ((param_2 != '\0') && (*(int *)(iVar2 + 0x14) == 0)) {
    piVar1 = FUN_8001f58c(param_1,'\x01');
    *(int **)(iVar2 + 0x14) = piVar1;
    if (*(int *)(iVar2 + 0x14) != 0) {
      FUN_8001dbf0(*(int *)(iVar2 + 0x14),2);
      dVar3 = (double)FLOAT_803e7ca0;
      FUN_8001de4c(dVar3,dVar3,dVar3,*(int **)(iVar2 + 0x14));
      FUN_8001dbd8(*(int *)(iVar2 + 0x14),1);
      if (*(short *)(param_1 + 0x46) == 0x6ae) {
        FUN_8001dbb4(*(int *)(iVar2 + 0x14),0xff,0x14,0x50,0);
      }
      else if (*(char *)(param_1 + 0xad) == '\0') {
        FUN_8001dbb4(*(int *)(iVar2 + 0x14),0x3c,0xff,0x5a,0);
      }
      else {
        FUN_8001dbb4(*(int *)(iVar2 + 0x14),0x3c,0x5a,0xff,0);
      }
      if (*(short *)(param_1 + 0x46) == 0x655) {
        FUN_8001dcfc((double)FLOAT_803e7ca4,(double)FLOAT_803e7ca8,*(int *)(iVar2 + 0x14));
      }
      else {
        FUN_8001dcfc((double)FLOAT_803e7cac,(double)FLOAT_803e7cb0,*(int *)(iVar2 + 0x14));
      }
      FUN_8001de04(*(int *)(iVar2 + 0x14),1);
    }
  }
  return;
}

