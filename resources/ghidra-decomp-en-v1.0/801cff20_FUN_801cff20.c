// Function: FUN_801cff20
// Entry: 801cff20
// Size: 1472 bytes

void FUN_801cff20(void)

{
  int iVar1;
  short *psVar2;
  char cVar6;
  int iVar3;
  int iVar4;
  float fVar5;
  undefined4 uVar7;
  float *pfVar8;
  double dVar9;
  double dVar10;
  
  iVar1 = FUN_802860dc();
  pfVar8 = *(float **)(iVar1 + 0xb8);
  psVar2 = (short *)FUN_8002b9ec();
  if (FLOAT_803e5278 < *pfVar8) {
    FUN_80016870(0x435);
    *pfVar8 = *pfVar8 - FLOAT_803db414;
    if (*pfVar8 < FLOAT_803e5278) {
      *pfVar8 = FLOAT_803e5278;
    }
  }
  cVar6 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(iVar1 + 0xac));
  if (cVar6 != '\x01') {
    (**(code **)(*DAT_803dcaac + 0x44))((int)*(char *)(iVar1 + 0xac),1);
  }
  cVar6 = (**(code **)(*DAT_803dcaac + 0x40))(7);
  if (cVar6 == '\x01') {
    (**(code **)(*DAT_803dcaac + 0x44))(7,2);
    FUN_800200e8(0xf22,1);
    FUN_800200e8(0xf23,1);
    FUN_800200e8(0xf24,1);
    FUN_800200e8(0xf25,1);
  }
  iVar3 = (**(code **)(*DAT_803dca58 + 0x24))(0);
  if (iVar3 == 0) {
    if ((*(short *)(pfVar8 + 4) != 0x1a) &&
       (*(undefined2 *)(pfVar8 + 4) = 0x1a, ((uint)pfVar8[2] & 0x10) != 0)) {
      FUN_8000a518(0x1a,1);
    }
  }
  else if ((*(short *)(pfVar8 + 4) != -1) &&
          (*(undefined2 *)(pfVar8 + 4) = 0xffff, ((uint)pfVar8[2] & 0x10) != 0)) {
    FUN_8000a518(0x1a,0);
  }
  FUN_801d7ed4(pfVar8 + 2,8,0xffffffff,0xffffffff,0x3a0,0x35);
  FUN_801d7ed4(pfVar8 + 2,0x10,0xffffffff,0xffffffff,0x3a1,(int)*(short *)(pfVar8 + 4));
  FUN_801d7ed4(pfVar8 + 2,0x20,0xffffffff,0xffffffff,0x393,0x36);
  FUN_801d7ed4(pfVar8 + 2,0x40,0xffffffff,0xffffffff,0xcbb,0xc4);
  uVar7 = 0;
  iVar3 = FUN_8001ffb4(0x19f);
  iVar4 = FUN_8001ffb4(0x19d);
  if ((iVar4 != iVar3) && (cVar6 = FUN_80014054(), cVar6 != '\0')) {
    uVar7 = 1;
  }
  FUN_800200e8(0xf31,uVar7);
  FUN_801d7ed4(pfVar8 + 2,0x80,0xffffffff,0xffffffff,0xf31,0xaf);
  iVar3 = FUN_8001ffb4(0x398);
  if ((iVar3 != 0) &&
     (cVar6 = (**(code **)(*DAT_803dcaac + 0x4c))((int)*(char *)(iVar1 + 0xac),0x1f), cVar6 == '\0')
     ) {
    (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(iVar1 + 0xac),0x1f,1);
  }
  if ((((uint)pfVar8[2] & 2) == 0) || (iVar3 = FUN_80014670(), iVar3 == 0)) {
    switch(*(undefined *)(pfVar8 + 1)) {
    case 0:
      iVar3 = FUN_8001ffb4(0x19d);
      if (iVar3 != 0) {
        (**(code **)(*DAT_803dca54 + 0x48))(0,iVar1,0xffffffff);
        *(undefined *)(pfVar8 + 1) = 2;
        FUN_800200e8(0xecd,1);
      }
      break;
    case 1:
      (**(code **)(*DAT_803dca54 + 0x54))(iVar1,0x64a);
      (**(code **)(*DAT_803dca54 + 0x48))(0,iVar1,0x20);
      *(undefined *)(pfVar8 + 1) = 2;
      FUN_800200e8(0xecd,1);
      break;
    case 2:
      iVar1 = FUN_801cfd68(pfVar8);
      if (iVar1 != 0) {
        *(undefined *)((int)pfVar8 + 5) = 0x32;
        pfVar8[2] = (float)((uint)pfVar8[2] | 1);
      }
      break;
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
      FUN_801cfd68(pfVar8);
      break;
    case 8:
      iVar1 = FUN_801cfd68(pfVar8);
      if (iVar1 == 1) {
        pfVar8[2] = (float)((uint)pfVar8[2] | 4);
      }
      break;
    case 9:
      if ((psVar2[0x58] & 0x1000U) != 0) {
        *(undefined *)(pfVar8 + 1) = 10;
      }
      break;
    case 10:
      if ((psVar2[0x58] & 0x1000U) == 0) {
        fVar5 = pfVar8[2];
        if (((uint)fVar5 & 1) == 0) {
          if (((uint)fVar5 & 4) == 0) {
            dVar10 = (double)FUN_80014668();
            dVar9 = (double)FLOAT_803e527c;
            FUN_8001467c();
            FUN_800146bc(0x15,(uint)*(byte *)((int)pfVar8 + 5) + (int)(dVar10 / dVar9));
            FUN_8001469c();
          }
          else {
            pfVar8[2] = (float)((uint)fVar5 & 0xfffffffd);
            pfVar8[2] = (float)((uint)pfVar8[2] & 0xfffffffb);
            FUN_8001467c();
            FUN_8000a518(0xaf,0);
            FUN_800200e8(0x19f,1);
          }
        }
        else {
          pfVar8[2] = (float)((uint)fVar5 & 0xfffffffe);
          pfVar8[2] = (float)((uint)pfVar8[2] | 2);
          FUN_800146bc(0x15,*(undefined *)((int)pfVar8 + 5));
          FUN_8001469c();
          (**(code **)(*DAT_803dcaac + 0x1c))(psVar2 + 6,(int)*psVar2,0,0);
        }
        (**(code **)(*DAT_803dca54 + 0x48))(*(undefined *)(pfVar8 + 3),iVar1,0xffffffff);
        *(undefined *)(pfVar8 + 1) = *(undefined *)((int)pfVar8 + 0xd);
      }
      break;
    case 0xb:
      iVar1 = FUN_8001ffb4(0xecd);
      if (iVar1 != 0) {
        FUN_800200e8(0xecd,0);
      }
      break;
    case 0xc:
      (**(code **)(*DAT_803dca54 + 0x54))(iVar1,0x5a);
      (**(code **)(*DAT_803dca54 + 0x48))(1,iVar1,8);
      *(undefined *)(pfVar8 + 1) = 0xb;
    }
  }
  else {
    FUN_8000bb18(0,0x28d);
    (**(code **)(*DAT_803dcaac + 0x28))();
  }
  FUN_80286128();
  return;
}

