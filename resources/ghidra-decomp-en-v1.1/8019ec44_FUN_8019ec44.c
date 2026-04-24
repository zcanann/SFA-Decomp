// Function: FUN_8019ec44
// Entry: 8019ec44
// Size: 316 bytes

void FUN_8019ec44(void)

{
  bool bVar1;
  undefined2 *puVar2;
  int iVar3;
  int iVar4;
  float *pfVar5;
  int iVar6;
  double dVar7;
  
  puVar2 = (undefined2 *)FUN_80286840();
  pfVar5 = *(float **)(puVar2 + 0x5c);
  iVar4 = *(int *)(puVar2 + 0x26);
  iVar3 = FUN_8002bac4();
  iVar6 = *(int *)(puVar2 + 0x26);
  bVar1 = false;
  dVar7 = (double)FUN_800217c8((float *)(iVar3 + 0x18),(float *)(puVar2 + 0xc));
  if (((dVar7 < (double)(float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(iVar6 + 0x1a) ^ 0x80000000) -
                               DOUBLE_803e4eb8)) && (pfVar5[0x8c] == 4.2039e-45)) &&
     ((puVar2[0x58] & 0x1000) == 0)) {
    bVar1 = true;
  }
  if (bVar1) {
    FUN_80080404(pfVar5,0x3c);
    *(undefined4 *)(puVar2 + 0x7a) = 1;
    *puVar2 = *(undefined2 *)(pfVar5 + 0x34);
    (**(code **)(*DAT_803dd6d4 + 0x48))(4,puVar2,0xffffffff);
    *pfVar5 = FLOAT_803e4edc;
    FUN_80020000(0x901);
    pfVar5[0x31] = 1.68156e-44;
    FUN_800201ac((int)*(short *)(iVar4 + 0x1e),1);
    *(undefined4 *)(puVar2 + 0x7a) = 0;
  }
  else {
    FUN_800394f0(puVar2,pfVar5 + 0x1b,0x296,0x1000,0xffffffff,1);
    FUN_8000bb38((uint)puVar2,0xd4);
  }
  FUN_8028688c();
  return;
}

