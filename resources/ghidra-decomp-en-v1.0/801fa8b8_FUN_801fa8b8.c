// Function: FUN_801fa8b8
// Entry: 801fa8b8
// Size: 772 bytes

void FUN_801fa8b8(short *param_1)

{
  short sVar1;
  int iVar2;
  ushort uVar3;
  short *psVar4;
  int iVar5;
  int local_28 [2];
  double local_20;
  
  iVar5 = *(int *)(param_1 + 0x26);
  psVar4 = *(short **)(param_1 + 0x5c);
  local_28[0] = 0;
  if (*(char *)((int)psVar4 + 5) == '\0') {
    *(undefined *)((int)psVar4 + 9) = 5;
    *(undefined *)((int)psVar4 + 0xb) = 0x28;
    *(undefined *)(psVar4 + 5) = 5;
  }
  else {
    *(undefined *)((int)psVar4 + 9) = 6;
    *(undefined *)((int)psVar4 + 0xb) = 0x14;
    *(undefined *)(psVar4 + 5) = 10;
  }
  psVar4[1] = psVar4[1] - (short)(int)FLOAT_803db414;
  sVar1 = *(short *)(iVar5 + 0x1a);
  if (sVar1 == 0) {
    local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(psVar4 + 5));
    FUN_800972dc((double)FLOAT_803e60b8,(double)(float)(local_20 - DOUBLE_803e60c0),param_1,
                 *(undefined *)((int)psVar4 + 9),5,1,*(undefined *)((int)psVar4 + 0xb),0,0);
  }
  else if (sVar1 == 1) {
    local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(psVar4 + 5));
    FUN_800972dc((double)FLOAT_803e60b8,(double)(float)(local_20 - DOUBLE_803e60c0),param_1,
                 *(undefined *)((int)psVar4 + 9),2,1,*(undefined *)((int)psVar4 + 0xb),0,0);
  }
  else {
    local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(psVar4 + 5));
    FUN_800972dc((double)FLOAT_803e60b8,(double)(float)(local_20 - DOUBLE_803e60c0),param_1,
                 *(undefined *)((int)psVar4 + 9),1,1,*(undefined *)((int)psVar4 + 0xb),0,0);
  }
  iVar2 = FUN_8002b9ec();
  FUN_80021704(iVar2 + 0x18,param_1 + 0xc);
  *(undefined *)((int)psVar4 + 7) = *(undefined *)((int)psVar4 + 5);
  iVar2 = FUN_8001ffb4((int)*psVar4);
  if (iVar2 == 0) {
    iVar2 = FUN_8003687c(param_1,local_28,0,0);
    if ((((local_28[0] != 0) && (iVar2 != 0)) && (local_28[0] != 0)) &&
       (*(short *)(local_28[0] + 0x46) == 0x14b)) {
      uVar3 = FUN_8016f16c(local_28[0]);
      if (*(ushort *)(iVar5 + 0x1a) == (uVar3 & 0xff)) {
        *(char *)((int)psVar4 + 5) = '\x01' - *(char *)((int)psVar4 + 5);
      }
      else {
        FUN_8000bb18(0,0xb3);
      }
    }
    local_20 = (double)(longlong)(int)FLOAT_803db414;
    *param_1 = *param_1 + (short)(int)FLOAT_803db414 * 0x82;
  }
  if ((*(char *)((int)psVar4 + 5) != '\0') && (*(char *)(psVar4 + 3) != '\0')) {
    *(undefined *)(psVar4 + 3) = 0;
    FUN_8000bb18(param_1,0x80);
    FUN_8000bb18(0,0x109);
  }
  if (*(char *)((int)psVar4 + 5) != *(char *)((int)psVar4 + 7)) {
    if (*(char *)((int)psVar4 + 5) == '\0') {
      FUN_8000b7bc(param_1,0x40);
      (**(code **)(*DAT_803dca78 + 0x14))(param_1);
      if ((*psVar4 != -1) && (iVar5 = FUN_8001ffb4(), iVar5 != 0)) {
        FUN_800200e8((int)*psVar4,0);
      }
    }
    else {
      if ((*psVar4 != -1) && (iVar5 = FUN_8001ffb4(), iVar5 == 0)) {
        FUN_800200e8((int)*psVar4,1);
      }
      *(undefined *)(psVar4 + 3) = 1;
    }
  }
  return;
}

