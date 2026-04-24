// Function: FUN_8014c064
// Entry: 8014c064
// Size: 184 bytes

void FUN_8014c064(int param_1)

{
  char cVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  if (((piVar2[0xb7] & 0x2000U) == 0) ||
     (cVar1 = FUN_8014a150(param_1,piVar2,param_1 + 0x18,*piVar2 + 0x68), cVar1 == '\0')) {
    cVar1 = (**(code **)(*DAT_803dca9c + 0x8c))
                      ((double)FLOAT_803e25dc,*piVar2,param_1,&DAT_803dbc58,0xffffffff);
    if (cVar1 == '\0') {
      piVar2[0xb7] = piVar2[0xb7] | 0x2000;
    }
    else {
      piVar2[0xb7] = piVar2[0xb7] & 0xffffdfff;
    }
  }
  return;
}

