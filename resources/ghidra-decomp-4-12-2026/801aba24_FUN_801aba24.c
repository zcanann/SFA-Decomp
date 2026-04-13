// Function: FUN_801aba24
// Entry: 801aba24
// Size: 612 bytes

void FUN_801aba24(uint param_1)

{
  uint uVar1;
  int iVar2;
  char cVar3;
  byte bVar4;
  float *pfVar5;
  double dVar6;
  undefined auStack_28 [12];
  float local_1c;
  float local_18;
  float local_14;
  
  uVar1 = FUN_80020078((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1a));
  if (uVar1 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    uVar1 = FUN_80020078(0x40);
    if (uVar1 == 0) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
    }
    else {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
    }
    pfVar5 = *(float **)(param_1 + 0xb8);
    iVar2 = FUN_8003811c(param_1);
    if ((iVar2 != 0) && (cVar3 = FUN_80133868(), cVar3 == '\0')) {
      *pfVar5 = FLOAT_803e5358;
    }
    if (FLOAT_803e5348 < *pfVar5) {
      if ((*(byte *)(param_1 + 0xaf) & 4) == 0) {
        *pfVar5 = FLOAT_803e5348;
      }
      else {
        *pfVar5 = *pfVar5 - FLOAT_803dc074;
        FUN_8012f288(*(undefined2 *)(*(int *)(param_1 + 0x50) + 0x7c));
      }
    }
    iVar2 = FUN_8002bac4();
    dVar6 = FUN_80021794((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
    if ((dVar6 < (double)FLOAT_803e535c) && (bVar4 = FUN_80296434(iVar2), bVar4 != 0)) {
      FUN_8000bb38(param_1,0x109);
      FUN_800201ac((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1a),1);
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    }
    local_1c = FLOAT_803e5340;
    local_18 = FLOAT_803e5344;
    local_14 = FLOAT_803e5348;
    FUN_800979c0((double)FLOAT_803e534c,(double)FLOAT_803e5350,(double)FLOAT_803e5350,
                 (double)FLOAT_803e5354,param_1,5,5,2,0x19,(int)auStack_28,0);
    local_1c = FLOAT_803e5344;
    FUN_800979c0((double)FLOAT_803e534c,(double)FLOAT_803e5350,(double)FLOAT_803e5350,
                 (double)FLOAT_803e5354,param_1,5,5,2,0x19,(int)auStack_28,0);
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    local_1c = FLOAT_803e5340;
    local_18 = FLOAT_803e5344;
    local_14 = FLOAT_803e5348;
    FUN_800979c0((double)FLOAT_803e534c,(double)FLOAT_803e5350,(double)FLOAT_803e5350,
                 (double)FLOAT_803e5354,param_1,5,2,2,0x19,(int)auStack_28,0);
    local_1c = FLOAT_803e5344;
    FUN_800979c0((double)FLOAT_803e534c,(double)FLOAT_803e5350,(double)FLOAT_803e5350,
                 (double)FLOAT_803e5354,param_1,5,2,2,0x19,(int)auStack_28,0);
  }
  return;
}

