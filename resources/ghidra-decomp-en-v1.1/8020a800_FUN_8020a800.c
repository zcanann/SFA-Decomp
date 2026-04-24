// Function: FUN_8020a800
// Entry: 8020a800
// Size: 532 bytes

void FUN_8020a800(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  
  iVar2 = FUN_80286840();
  iVar6 = *(int *)(iVar2 + 0xb8);
  *(byte *)(iVar6 + 0x198) = *(byte *)(iVar6 + 0x198) & 0xef | 0x10;
  if ((double)FLOAT_803e71a8 < (double)*(float *)(iVar6 + 0x18c)) {
    FUN_800168a8((double)*(float *)(iVar6 + 0x18c),param_2,param_3,param_4,param_5,param_6,param_7,
                 param_8,0x569);
    *(float *)(iVar6 + 0x18c) = *(float *)(iVar6 + 0x18c) - FLOAT_803dc074;
    if (*(float *)(iVar6 + 0x18c) < FLOAT_803e71a8) {
      *(float *)(iVar6 + 0x18c) = FLOAT_803e71a8;
    }
  }
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar5 = iVar5 + 1) {
    bVar1 = *(byte *)(param_11 + iVar5 + 0x81);
    if (bVar1 == 8) {
      FUN_800201ac(0x5db,0);
      (**(code **)(*DAT_803dd72c + 0x50))(2,0xf,1);
      uVar4 = 1;
      iVar3 = *DAT_803dd72c;
      (**(code **)(iVar3 + 0x50))(2,0x10);
      uVar7 = FUN_800201ac(0xe7b,0);
      FUN_80055464(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x79,'\0',uVar4,
                   iVar3,param_13,param_14,param_15,param_16);
      FUN_8005517c();
    }
    else if (bVar1 < 8) {
      if (bVar1 == 6) {
        iVar3 = FUN_80036f50(0x1e,iVar2,(float *)0x0);
        if ((iVar3 != 0) && (*(char *)(iVar2 + 0xeb) != '\0')) {
          (**(code **)(**(int **)(iVar3 + 0x68) + 0x20))(iVar3,2);
          FUN_80037da8(iVar2,iVar3);
        }
      }
      else if ((5 < bVar1) && (iVar3 = FUN_80036f50(0x1e,iVar2,(float *)0x0), iVar3 != 0)) {
        (**(code **)(**(int **)(iVar3 + 0x68) + 0x20))(iVar3,0);
        FUN_80037e24(iVar2,iVar3,1);
        *(float *)(iVar6 + 0x18c) = FLOAT_803e71ac;
      }
    }
    else if (bVar1 < 10) {
      *(byte *)(iVar6 + 0x198) = *(byte *)(iVar6 + 0x198) & 0xfd | 2;
    }
  }
  if ((*(byte *)(iVar6 + 0x198) >> 1 & 1) != 0) {
    FUN_8009a010((double)FLOAT_803e71b0,(double)FLOAT_803e71b4,iVar2,6,(int *)0x0);
  }
  FUN_8028688c();
  return;
}

