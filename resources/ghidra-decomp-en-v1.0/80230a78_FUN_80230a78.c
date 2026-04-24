// Function: FUN_80230a78
// Entry: 80230a78
// Size: 592 bytes

void FUN_80230a78(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  char cVar4;
  int iVar3;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_8022d768();
  if (*(char *)(iVar5 + 0x18) == '\0') {
    FUN_80089710(7,1,0);
    if (*(char *)(iVar5 + 0x1b) == '\0') {
      FUN_800895e0(7,0x96,100,0xf0,0,0);
    }
    else {
      FUN_800895e0(7,0xaa,0x78,0xff,0x69,0x40);
    }
    FUN_800894a8((double)FLOAT_803e70e4,(double)FLOAT_803e70e4,(double)FLOAT_803e70e0,7);
    FUN_80008cbc(0,0,0x21f,0);
    FUN_80008cbc(0,0,0x22b,0);
    FUN_8005cea8(0);
    *(undefined *)(iVar5 + 0x18) = 1;
    FUN_8005cdf8(0);
  }
  if (*(char *)(iVar5 + 0x19) == '\0') {
    if (*(char *)(iVar5 + 0x1b) == '\0') {
      cVar4 = FUN_8000cfa0();
      if (cVar4 == '\0') {
        FUN_8000d200(*(undefined4 *)(iVar5 + 0x1c),FUN_8000d138);
      }
      uVar2 = 0;
    }
    else {
      uVar2 = 3;
    }
    (**(code **)(*DAT_803dca54 + 0x48))(uVar2,param_1,0xffffffff);
    *(undefined *)(iVar5 + 0x19) = 1;
    FUN_800200e8(0x9d6,0);
    FUN_800200e8(0x9d8,0);
    FUN_800200e8(0x9d7,0);
  }
  if (*(char *)(iVar5 + 0x1a) == '\0') {
    iVar3 = FUN_800592e4();
    if (((FLOAT_803e70e8 < *(float *)(iVar1 + 0x14) - *(float *)(iVar3 + 0x28)) &&
        (iVar3 = FUN_8022d750(iVar1), iVar3 == 0)) && (iVar3 = FUN_8022d710(iVar1), iVar3 == 0)) {
      FUN_8011f354(2);
      (**(code **)(*DAT_803dca54 + 0x7c))(*(undefined2 *)(iVar5 + 0x20),0,0);
      iVar3 = FUN_8022d508(iVar1);
      iVar1 = FUN_8022d514(iVar1);
      if (iVar1 < iVar3) {
        FUN_800200e8(0x9d7,1);
      }
      else {
        FUN_800200e8(0x9d8,1);
      }
      *(undefined *)(iVar5 + 0x1a) = 1;
      FUN_8000a518(2,0);
      FUN_8000a518(0xf3,0);
    }
  }
  return;
}

