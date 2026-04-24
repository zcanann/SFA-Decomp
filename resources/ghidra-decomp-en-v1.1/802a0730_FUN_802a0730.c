// Function: FUN_802a0730
// Entry: 802a0730
// Size: 240 bytes

void FUN_802a0730(int param_1,int param_2)

{
  char cVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  sVar2 = *(short *)(param_2 + 0x274);
  if (((((sVar2 != 0x15) && (sVar2 != 0x14)) && (sVar2 != 0x12)) &&
      ((sVar2 != 0x13 && (sVar2 != 0xe)))) && ((sVar2 != 0xf && (sVar2 != 0x10)))) {
    cVar1 = *(char *)(iVar4 + 0x8c8);
    if ((((cVar1 != 'H') && (cVar1 != 'G')) && (cVar1 != 'B')) &&
       (iVar3 = FUN_80080490(), iVar3 == 0)) {
      (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0,0xff);
      *(undefined *)(iVar4 + 0x8c8) = 0x42;
    }
    *(uint *)(iVar4 + 0x360) = *(uint *)(iVar4 + 0x360) | 0x800000;
    FUN_80035f9c(param_1);
  }
  *(undefined2 *)(param_1 + 0xa2) = 0xffff;
  return;
}

