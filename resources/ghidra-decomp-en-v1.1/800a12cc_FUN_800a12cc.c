// Function: FUN_800a12cc
// Entry: 800a12cc
// Size: 252 bytes

void FUN_800a12cc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short param_9,int param_10)

{
  uint uVar1;
  uint *puVar2;
  int iVar3;
  
  iVar3 = 0;
  puVar2 = &DAT_8039ce58;
  do {
    uVar1 = *puVar2;
    if ((uVar1 != 0) && ((param_9 == *(short *)(uVar1 + 0x10c) || (param_10 != 0)))) {
      if (*(uint *)(uVar1 + 0xa0) != 0) {
        param_1 = FUN_800238c4(*(uint *)(uVar1 + 0xa0));
      }
      if (*(int *)*puVar2 != 0) {
        FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*(int *)*puVar2
                    );
      }
      *(undefined4 *)(*puVar2 + 300) = 0;
      if ((*(char *)(*puVar2 + 0x13f) == '\0') && (*(int *)(*puVar2 + 0x98) != 0)) {
        FUN_80054484();
      }
      if (*(char *)(*puVar2 + 0x13f) == '\0') {
        *(undefined4 *)(*puVar2 + 0x98) = 0;
      }
      param_1 = FUN_800238c4(*puVar2);
      *puVar2 = 0;
    }
    puVar2 = puVar2 + 1;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 0x32);
  return;
}

