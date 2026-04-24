// Function: FUN_80086058
// Entry: 80086058
// Size: 288 bytes

void FUN_80086058(undefined4 param_1,undefined4 param_2,int param_3)

{
  char cVar1;
  bool bVar2;
  char *pcVar3;
  
  if (*(int *)(param_3 + 0x94) == 0) {
    return;
  }
  *(undefined2 *)(param_3 + 0x68) = 0xffff;
  *(undefined2 *)(param_3 + 0x66) = 0;
  *(float *)(param_3 + 0x20) = FLOAT_803defb0;
  bVar2 = false;
  while( true ) {
    if (bVar2) {
      return;
    }
    if ((int)*(short *)(param_3 + 0x62) <= (int)*(short *)(param_3 + 0x66)) break;
    pcVar3 = (char *)(*(int *)(param_3 + 0x94) + *(short *)(param_3 + 0x66) * 4);
    cVar1 = *pcVar3;
    if (cVar1 == '\0') {
      if (*(short *)(param_3 + 0x58) < *(short *)(pcVar3 + 2)) {
        bVar2 = true;
      }
      else {
        *(short *)(param_3 + 0x68) = *(short *)(pcVar3 + 2);
        *(short *)(param_3 + 0x66) = *(short *)(param_3 + 0x66) + 1;
      }
    }
    else if ((cVar1 == '\v') && (0 < *(short *)(pcVar3 + 2))) {
      if (*(short *)(param_3 + 0x58) < *(short *)(param_3 + 0x68)) {
        bVar2 = true;
      }
      else {
        *(ushort *)(param_3 + 0x68) = *(short *)(param_3 + 0x68) + (ushort)(byte)pcVar3[1];
        *(short *)(param_3 + 0x66) = *(short *)(pcVar3 + 2) + *(short *)(param_3 + 0x66) + 1;
      }
    }
    else if (*(short *)(param_3 + 0x58) < *(short *)(param_3 + 0x68)) {
      bVar2 = true;
    }
    else {
      if (cVar1 != '\x0f') {
        *(ushort *)(param_3 + 0x68) = *(short *)(param_3 + 0x68) + (ushort)(byte)pcVar3[1];
      }
      *(short *)(param_3 + 0x66) = *(short *)(param_3 + 0x66) + 1;
    }
  }
  return;
}

