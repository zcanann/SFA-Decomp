// Function: FUN_8019e6c8
// Entry: 8019e6c8
// Size: 316 bytes

void FUN_8019e6c8(void)

{
  bool bVar1;
  undefined2 *puVar2;
  int iVar3;
  int iVar4;
  float *pfVar5;
  int iVar6;
  double dVar7;
  
  puVar2 = (undefined2 *)FUN_802860dc();
  pfVar5 = *(float **)(puVar2 + 0x5c);
  iVar4 = *(int *)(puVar2 + 0x26);
  iVar3 = FUN_8002b9ec();
  iVar6 = *(int *)(puVar2 + 0x26);
  bVar1 = false;
  dVar7 = (double)FUN_80021704(iVar3 + 0x18,puVar2 + 0xc);
  if (((dVar7 < (double)(float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(iVar6 + 0x1a) ^ 0x80000000) -
                               DOUBLE_803e4220)) && (pfVar5[0x8c] == 4.203895e-45)) &&
     ((puVar2[0x58] & 0x1000) == 0)) {
    bVar1 = true;
  }
  if (!bVar1) {
    FUN_800393f8(puVar2,pfVar5 + 0x1b,0x296,0x1000,0xffffffff,1);
    FUN_8000bb18(puVar2,0xd4);
  }
  else {
    FUN_80080178(pfVar5,0x3c);
    *(undefined4 *)(puVar2 + 0x7a) = 1;
    *puVar2 = *(undefined2 *)(pfVar5 + 0x34);
    (**(code **)(*DAT_803dca54 + 0x48))(4,puVar2,0xffffffff);
    *pfVar5 = FLOAT_803e4244;
    FUN_8001ff3c(0x901);
    pfVar5[0x31] = 1.681558e-44;
    FUN_800200e8((int)*(short *)(iVar4 + 0x1e),1);
    *(undefined4 *)(puVar2 + 0x7a) = 0;
  }
  FUN_80286128(bVar1);
  return;
}

