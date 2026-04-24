// Function: FUN_80125fe8
// Entry: 80125fe8
// Size: 136 bytes

void FUN_80125fe8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  
  iVar2 = 0;
  piVar3 = &DAT_803aa058;
  do {
    iVar1 = *piVar3;
    if (iVar1 != 0) {
      if (0x90000000 < *(uint *)(iVar1 + 0x4c)) {
        *(undefined4 *)(iVar1 + 0x4c) = 0;
      }
      param_1 = FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar3
                            );
      *piVar3 = 0;
    }
    piVar3 = piVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 6);
  return;
}

