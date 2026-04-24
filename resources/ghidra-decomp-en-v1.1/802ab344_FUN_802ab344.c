// Function: FUN_802ab344
// Entry: 802ab344
// Size: 352 bytes

void FUN_802ab344(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  undefined4 in_r6;
  float *pfVar2;
  undefined4 in_r7;
  short *psVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short sVar4;
  int *piVar5;
  undefined4 *puVar6;
  short *psVar7;
  double dVar8;
  short asStack_38 [4];
  float fStack_30;
  undefined4 local_2c;
  
  iVar1 = FUN_80286840();
  piVar5 = *(int **)(*(int *)(iVar1 + 0x7c) + *(char *)(iVar1 + 0xad) * 4);
  FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
               (int)**(short **)(*(int *)(iVar1 + 0xb8) + 0x3f8),0,in_r6,in_r7,in_r8,in_r9,in_r10);
  dVar8 = (double)*(float *)(iVar1 + 8);
  pfVar2 = &fStack_30;
  psVar3 = asStack_38;
  FUN_80027ec4((double)FLOAT_803e8b3c,dVar8,piVar5,0,0,pfVar2,psVar3);
  DAT_803dbbe8 = local_2c;
  FUN_8003042c((double)FLOAT_803e8b3c,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
               (int)DAT_80333b8c,0,pfVar2,psVar3,in_r8,in_r9,in_r10);
  dVar8 = (double)*(float *)(iVar1 + 8);
  pfVar2 = &fStack_30;
  psVar3 = asStack_38;
  FUN_80027ec4((double)FLOAT_803e8b3c,dVar8,piVar5,0,0,pfVar2,psVar3);
  DAT_803dbbec = local_2c;
  psVar7 = &DAT_80333bca;
  puVar6 = &DAT_803dbc18;
  for (sVar4 = 0xc; sVar4 < 0x10; sVar4 = sVar4 + 1) {
    FUN_8003042c((double)FLOAT_803e8b3c,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                 (int)*psVar7,0,pfVar2,psVar3,in_r8,in_r9,in_r10);
    dVar8 = (double)*(float *)(iVar1 + 8);
    pfVar2 = &fStack_30;
    psVar3 = asStack_38;
    FUN_80027ec4((double)FLOAT_803e8b3c,dVar8,piVar5,0,0,pfVar2,psVar3);
    *puVar6 = local_2c;
    psVar7 = psVar7 + 1;
    puVar6 = puVar6 + 1;
  }
  FUN_8002f624(iVar1,0,0,0);
  FUN_8028688c();
  return;
}

