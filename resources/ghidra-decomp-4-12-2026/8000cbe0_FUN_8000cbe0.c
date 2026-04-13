// Function: FUN_8000cbe0
// Entry: 8000cbe0
// Size: 300 bytes

double FUN_8000cbe0(float *param_1,float *param_2)

{
  int iVar1;
  undefined2 *puVar2;
  int iVar3;
  float *pfVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  float afStack_28 [6];
  
  iVar1 = FUN_8002bac4();
  puVar2 = FUN_8000facc();
  iVar3 = FUN_80080490();
  if ((iVar1 == 0) || (iVar3 != 0)) {
    if (puVar2 == (undefined2 *)0x0) {
      return (double)FLOAT_803df1f0;
    }
    if (iVar1 == 0) {
      pfVar4 = (float *)(puVar2 + 0x22);
    }
    else {
      FUN_80247eb8((float *)(puVar2 + 0x22),(float *)(iVar1 + 0x18),afStack_28);
      dVar7 = FUN_80247f54(afStack_28);
      dVar5 = (double)((float)(dVar7 - (double)FLOAT_803df234) / FLOAT_803df238);
      dVar7 = DOUBLE_803df248;
      if (DOUBLE_803df248 < dVar5) {
        dVar7 = dVar5;
      }
      dVar6 = DOUBLE_803df240;
      if ((dVar7 <= DOUBLE_803df240) && (dVar6 = DOUBLE_803df248, DOUBLE_803df248 < dVar5)) {
        dVar6 = dVar5;
      }
      FUN_80247edc((double)(float)dVar6,afStack_28,afStack_28);
      FUN_80247e94((float *)(iVar1 + 0x18),afStack_28,afStack_28);
      pfVar4 = afStack_28;
    }
  }
  else {
    pfVar4 = (float *)(iVar1 + 0x18);
  }
  FUN_80247eb8(pfVar4,param_1,param_2);
  dVar7 = FUN_80247f54(param_2);
  return dVar7;
}

