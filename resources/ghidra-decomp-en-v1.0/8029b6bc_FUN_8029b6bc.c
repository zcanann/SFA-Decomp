// Function: FUN_8029b6bc
// Entry: 8029b6bc
// Size: 244 bytes

int FUN_8029b6bc(int param_1,int param_2)

{
  char cVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  iVar2 = FUN_802ac7dc(param_1,param_2,iVar3);
  if (iVar2 == 0) {
    if (*(short *)(param_1 + 0xa0) != 0x449) {
      FUN_80030334((double)FLOAT_803e7ea4,param_1,0x449,0);
      *(float *)(param_2 + 0x2a0) = FLOAT_803e7f4c;
      FUN_8000bb18(param_1,0x40b);
      cVar1 = *(char *)(iVar3 + 0x8c8);
      if ((cVar1 != 'B') && (cVar1 != 'L')) {
        (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0x3c,0xfe);
      }
    }
    if (*(char *)(param_2 + 0x346) == '\0') {
      iVar2 = 0;
    }
    else {
      *(code **)(param_2 + 0x308) = FUN_802a514c;
      iVar2 = -1;
    }
  }
  return iVar2;
}

