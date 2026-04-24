// Function: FUN_801e209c
// Entry: 801e209c
// Size: 764 bytes

undefined4
FUN_801e209c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,undefined4 param_10,int param_11)

{
  float fVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined8 uVar8;
  double dVar9;
  int local_28;
  int local_24;
  longlong local_20;
  
  iVar7 = *(int *)(param_9 + 0xb8);
  *(undefined *)(param_9 + 0xac) = 0xff;
  FUN_801e1b78(param_9,iVar7);
  fVar1 = FLOAT_803e6364;
  *(float *)(iVar7 + 0x44) = FLOAT_803e6364;
  *(float *)(iVar7 + 0x38) = fVar1;
  *(float *)(iVar7 + 0x3c) = fVar1;
  *(float *)(iVar7 + 0x40) = fVar1;
  *(undefined **)(param_11 + 0xe8) = &LAB_801e1b58;
  for (iVar6 = 0; fVar1 = FLOAT_803e6364, iVar6 < (int)(uint)*(byte *)(param_11 + 0x8b);
      iVar6 = iVar6 + 1) {
    switch(*(undefined *)(param_11 + iVar6 + 0x81)) {
    case 2:
      if (*(char *)(iVar7 + 0x79) == '\x01') {
        *(undefined *)(iVar7 + 0x79) = 0;
      }
      else {
        *(undefined *)(iVar7 + 0x79) = 1;
      }
      break;
    case 3:
      iVar3 = FUN_8002e1f4(&local_24,&local_28);
      for (iVar6 = local_24; iVar6 < local_28; iVar6 = iVar6 + 1) {
        iVar5 = *(int *)(iVar3 + iVar6 * 4);
        if (*(short *)(iVar5 + 0x46) == 0xf7) {
          *(int *)(iVar7 + 0x4c) = iVar5;
          iVar6 = local_28;
        }
      }
      *(undefined *)(iVar7 + 0x85) = 1;
      break;
    case 4:
      *(undefined *)(iVar7 + 0x85) = 0;
      break;
    case 5:
      if (*(char *)(iVar7 + 0x79) == '\x02') {
        *(undefined *)(iVar7 + 0x79) = 0;
      }
      else {
        *(undefined *)(iVar7 + 0x79) = 2;
      }
      break;
    case 6:
      FUN_8000bb38(param_9,0x143);
      break;
    case 7:
      FUN_8000b844(param_9,0x143);
      break;
    case 8:
      if (*(char *)(iVar7 + 0x79) == '\b') {
        *(undefined *)(iVar7 + 0x79) = 1;
      }
      else {
        *(undefined *)(iVar7 + 0x79) = 8;
      }
      break;
    case 9:
      *(undefined *)(iVar7 + 0xab) = 1;
      break;
    case 10:
      *(undefined *)(iVar7 + 0xab) = 0;
      break;
    case 0xb:
      uVar4 = FUN_801e2b60();
      FUN_8000bb38(uVar4,0x2c6);
      break;
    case 0xc:
      *(undefined4 *)(iVar7 + 0x9c) = 0xa3;
      FUN_8000a538(*(int **)(iVar7 + 0x9c),1);
      FUN_8000a538(*(int **)(iVar7 + 0x98),0);
      break;
    case 0xd:
      *(float *)(iVar7 + 0xac) = FLOAT_803e6490;
      *(undefined *)(iVar7 + 0x78) = 1;
      *(float *)(iVar7 + 0x74) = FLOAT_803e6364;
    }
  }
  if ((FLOAT_803e6364 <= *(float *)(iVar7 + 0xac)) &&
     (*(float *)(iVar7 + 0xac) = *(float *)(iVar7 + 0xac) - FLOAT_803dc074,
     *(float *)(iVar7 + 0xac) < fVar1)) {
    *(float *)(iVar7 + 0xac) = fVar1;
    *(undefined *)(iVar7 + 0x78) = 0;
  }
  fVar1 = FLOAT_803e6428;
  if (*(char *)(iVar7 + 0x78) == '\0') {
    *(float *)(iVar7 + 0x74) = -(FLOAT_803e6428 * FLOAT_803dc074 - *(float *)(iVar7 + 0x74));
  }
  else {
    *(float *)(iVar7 + 0x74) = FLOAT_803e6428 * FLOAT_803dc074 + *(float *)(iVar7 + 0x74);
  }
  dVar9 = (double)fVar1;
  fVar1 = *(float *)(iVar7 + 0x74);
  fVar2 = FLOAT_803e6364;
  if ((FLOAT_803e6364 <= fVar1) && (fVar2 = fVar1, FLOAT_803e648c < fVar1)) {
    fVar2 = FLOAT_803e648c;
  }
  *(float *)(iVar7 + 0x74) = fVar2;
  if (FLOAT_803e6364 < *(float *)(iVar7 + 0x74)) {
    iVar6 = (int)*(float *)(iVar7 + 0x74);
    local_20 = (longlong)iVar6;
    uVar8 = FUN_80019940(0xff,0xff,0xff,(byte)iVar6);
    FUN_800168a8(uVar8,dVar9,param_3,param_4,param_5,param_6,param_7,param_8,0x4b1);
  }
  *(undefined4 *)(iVar7 + 0x2c) = *(undefined4 *)(param_9 + 0xc);
  *(undefined4 *)(iVar7 + 0x30) = *(undefined4 *)(param_9 + 0x10);
  *(undefined4 *)(iVar7 + 0x34) = *(undefined4 *)(param_9 + 0x14);
  *(undefined2 *)(param_11 + 0x6e) = *(undefined2 *)(param_11 + 0x70);
  *(undefined *)(param_11 + 0x56) = 0;
  return 0;
}

