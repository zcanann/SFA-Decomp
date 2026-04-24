// Function: FUN_8016dea8
// Entry: 8016dea8
// Size: 504 bytes

void FUN_8016dea8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 *param_9)

{
  int iVar1;
  uint uVar2;
  undefined2 *puVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 in_r10;
  undefined8 uVar6;
  double dVar7;
  double dVar8;
  undefined2 local_28;
  undefined2 local_26;
  undefined2 local_24;
  float local_20;
  undefined4 local_1c;
  float local_18;
  undefined4 local_14;
  
  if (DAT_803ad338 != '\0') {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803ad334);
    DAT_803ad334 = 0;
  }
  DAT_803ad318 = *param_9;
  dVar7 = (double)FLOAT_803e3f40;
  DAT_803ad31c = (float)(dVar7 + (double)(float)param_9[1]);
  DAT_803ad320 = param_9[2];
  DAT_803ad330 = FLOAT_803e3f8c;
  DAT_803ad324 = FLOAT_803e3f20;
  DAT_803ad328 = FLOAT_803e3f28;
  DAT_803ad32c = FLOAT_803e3f20;
  dVar8 = (double)FLOAT_803e3f94;
  FUN_8000e670((double)FLOAT_803e3f90,dVar7,dVar8);
  iVar1 = FUN_8002bac4();
  if ((iVar1 != 0) && (uVar2 = FUN_8002e144(), (uVar2 & 0xff) != 0)) {
    DAT_803ad338 = '\x01';
    local_1c = DAT_803ad318;
    local_18 = DAT_803ad31c;
    local_14 = DAT_803ad320;
    local_20 = FLOAT_803e3f20;
    local_28 = 0;
    local_24 = 0;
    local_26 = 0;
    uVar4 = 0;
    iVar5 = *DAT_803dd708;
    uVar6 = (**(code **)(iVar5 + 8))(iVar1,0x565,&local_28,0x200000,0xffffffff);
    puVar3 = FUN_8002becc(0x24,0x63c);
    *(undefined *)(puVar3 + 2) = 1;
    *(undefined *)(puVar3 + 3) = 0xff;
    *(undefined *)((int)puVar3 + 5) = 2;
    *(undefined *)((int)puVar3 + 7) = 0xff;
    *(undefined4 *)(puVar3 + 4) = DAT_803ad318;
    *(float *)(puVar3 + 6) = DAT_803ad31c;
    *(undefined4 *)(puVar3 + 8) = DAT_803ad320;
    DAT_803ad334 = FUN_8002e088(uVar6,dVar7,dVar8,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                                *(undefined *)(iVar1 + 0xac),0xffffffff,*(uint **)(iVar1 + 0x30),
                                uVar4,iVar5,in_r10);
    uVar2 = FUN_80020078(0xc55);
    if (uVar2 != 0) {
      *(undefined *)(DAT_803ad334 + 0xad) = 1;
    }
    FUN_80035a6c(DAT_803ad334,1);
    FUN_80035eec(DAT_803ad334,0x11,5,0);
    *(float *)(DAT_803ad334 + 8) = FLOAT_803e3f68;
    *(undefined *)(DAT_803ad334 + 0x36) = 0xff;
  }
  return;
}

