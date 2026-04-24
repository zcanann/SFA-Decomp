// Function: FUN_80172b1c
// Entry: 80172b1c
// Size: 260 bytes

void FUN_80172b1c(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  iVar2 = *(int *)(iVar1 + 0xb8);
  if ((((param_6 != '\0') && (*(float *)(iVar2 + 8) == FLOAT_803e345c)) &&
      (*(int *)(iVar1 + 0xf4) == 0)) &&
     ((*(short *)(iVar1 + 0x46) == 0x156 || (*(char *)(iVar2 + 0x1e) == '\0')))) {
    if (((*(uint *)(*(int *)(iVar1 + 0x50) + 0x44) & 0x10000) != 0) &&
       (*(char *)(iVar2 + 0x36) != '\0')) {
      FUN_8003b608(*(undefined *)(iVar2 + 0x38),*(undefined *)(iVar2 + 0x39),
                   *(undefined *)(iVar2 + 0x3a));
    }
    FUN_8003b8f4((double)FLOAT_803e3454,iVar1,(int)uVar3,param_3,param_4,param_5);
    if (*(short *)(iVar1 + 0x46) == 0xa8) {
      FUN_800972dc((double)FLOAT_803e3454,(double)FLOAT_803e348c,iVar1,7,5,1,10,0,0x20000000);
    }
  }
  FUN_80286128();
  return;
}

