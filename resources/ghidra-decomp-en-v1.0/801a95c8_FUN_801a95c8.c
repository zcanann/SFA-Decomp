// Function: FUN_801a95c8
// Entry: 801a95c8
// Size: 324 bytes

void FUN_801a95c8(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  char *pcVar2;
  double dVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  pcVar2 = *(char **)(iVar1 + 0xb8);
  if (param_6 != '\0') {
    if (*pcVar2 == '\x02') {
      if ((pcVar2[1] & 2U) != 0) {
        *(short *)(pcVar2 + 0xc) = *(short *)(pcVar2 + 0xc) + 0x1000;
        dVar3 = (double)FUN_80293e80((double)((FLOAT_803e45e0 *
                                              (float)((double)CONCAT44(0x43300000,
                                                                       (int)*(short *)(pcVar2 + 0xc)
                                                                       ^ 0x80000000) -
                                                     DOUBLE_803e45e8)) / FLOAT_803e45e4));
        FUN_8003b608((int)(FLOAT_803e45d8 * (float)((double)FLOAT_803e45dc + dVar3)) + 0x7fU & 0xff,
                     0xff,0xff);
      }
    }
    else if (*pcVar2 == '\x03') {
      if (*(short *)(pcVar2 + 0xc) < 32000) {
        *(short *)(pcVar2 + 0xc) = *(short *)(pcVar2 + 0xc) + 0xff;
      }
      FUN_8003b608((int)(*(short *)(pcVar2 + 0xc) >> 7),0xff,0xff);
    }
    else {
      FUN_8003b608(0xff,0xff,0xff);
    }
    FUN_8003b8f4((double)FLOAT_803e45dc,iVar1,(int)uVar4,param_3,param_4,param_5);
  }
  FUN_80286128();
  return;
}

