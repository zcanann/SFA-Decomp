// Function: FUN_80217abc
// Entry: 80217abc
// Size: 492 bytes

void FUN_80217abc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int local_38;
  undefined4 local_34;
  float fStack_30;
  undefined4 uStack_2c;
  undefined4 auStack_28 [10];
  
  uVar1 = FUN_80286840();
  iVar5 = *(int *)(uVar1 + 0xb8);
  iVar4 = *(int *)(uVar1 + 0x4c);
  if ((-1 < (char)*(byte *)(iVar5 + 0x1a8)) && ((*(byte *)(iVar5 + 0x1a8) >> 4 & 1) == 0)) {
    iVar2 = FUN_80036868(uVar1,&local_38,(int *)0x0,&local_34,&fStack_30,&uStack_2c,auStack_28);
    if ((*(byte *)(iVar5 + 0x1a8) >> 1 & 1) == 0) {
      if ((((iVar2 - 0xeU < 2) || (iVar2 == 5)) && (*(int *)(iVar5 + 0xc) != local_38)) &&
         ((int)*(short *)(local_38 + 0x46) != *(int *)(iVar5 + 0x19c))) {
        *(int *)(iVar5 + 0xc) = local_38;
        *(char *)(iVar5 + 0x1a6) = *(char *)(iVar5 + 0x1a6) - (char)local_34;
        FUN_802224e4(uVar1,&fStack_30);
        FUN_8009ab54((double)FLOAT_803e758c,uVar1);
        FUN_8000bb38(uVar1,0x3cc);
        if (*(char *)(iVar5 + 0x1a6) < '\x01') {
          iVar3 = FUN_8002ba84();
          FUN_8000bb38(uVar1,0x4b6);
          FUN_8009adfc((double)FLOAT_803e7590,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,uVar1,0,1,1,1,0,1,0);
          *(byte *)(iVar5 + 0x1a8) = *(byte *)(iVar5 + 0x1a8) & 0x7f | 0x80;
          FUN_800201ac((int)*(short *)(iVar4 + 0x1e),1);
          if (iVar3 != 0) {
            (**(code **)(**(int **)(iVar3 + 0x68) + 0x34))(iVar3,0,0);
          }
          *(ushort *)(uVar1 + 6) = *(ushort *)(uVar1 + 6) | 0x4000;
        }
      }
    }
    else if (((iVar2 != 0) && ((int)*(short *)(local_38 + 0x46) != *(int *)(iVar5 + 0x19c))) &&
            (*(int *)(iVar5 + 400) != 0)) {
      FUN_8017082c();
    }
    if (iVar2 == 0) {
      *(undefined4 *)(iVar5 + 0xc) = 0;
    }
    else {
      *(int *)(iVar5 + 0xc) = local_38;
    }
  }
  FUN_8028688c();
  return;
}

