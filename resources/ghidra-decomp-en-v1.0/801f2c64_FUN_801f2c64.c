// Function: FUN_801f2c64
// Entry: 801f2c64
// Size: 344 bytes

void FUN_801f2c64(int param_1)

{
  char cVar1;
  undefined uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  cVar1 = FUN_800353a4(param_1,&DAT_80328898,0xb,(*(byte *)(iVar3 + 0x22) & 0x80) != 0,iVar3 + 0x10)
  ;
  if (cVar1 == '\0') {
    *(byte *)(iVar3 + 0x22) = *(byte *)(iVar3 + 0x22) & 0x7f;
    uVar2 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
    switch(uVar2) {
    case 1:
      FUN_801f27e4(param_1);
      break;
    case 2:
      FUN_801f2290(param_1);
      break;
    case 4:
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      if (*(short *)(param_1 + 0xa0) != 2) {
        FUN_80030334((double)FLOAT_803e5d98,param_1,2,0);
      }
      FUN_8002fa48((double)FLOAT_803e5d9c,
                   (double)(float)((double)CONCAT44(0x43300000,(uint)DAT_803db410) - DOUBLE_803e5da0
                                  ),param_1,0);
      break;
    case 6:
      FUN_801f20d4(param_1);
    }
  }
  else {
    *(byte *)(iVar3 + 0x22) = *(byte *)(iVar3 + 0x22) | 0x80;
  }
  return;
}

