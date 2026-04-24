// Function: FUN_801d8308
// Entry: 801d8308
// Size: 1264 bytes

void FUN_801d8308(void)

{
  char cVar4;
  int iVar1;
  short *psVar2;
  int iVar3;
  uint *puVar5;
  byte bVar7;
  uint uVar6;
  undefined8 uVar8;
  double local_28;
  
  uVar8 = FUN_802860dc();
  iVar3 = (int)((ulonglong)uVar8 >> 0x20);
  puVar5 = (uint *)uVar8;
  cVar4 = (**(code **)(*DAT_803dcaac + 0x4c))((int)*(char *)(iVar3 + 0xac),0);
  if ((cVar4 == '\0') && (iVar1 = FUN_8001ffb4(0x13f), iVar1 == 0)) {
    *(undefined *)((int)puVar5 + 6) = 0;
    (**(code **)(*DAT_803dca68 + 100))();
    for (bVar7 = 0; bVar7 < 0x12; bVar7 = bVar7 + 1) {
      FUN_800200e8((int)(short)(&DAT_80327618)[bVar7],0);
    }
  }
  psVar2 = (short *)FUN_8002b9ec();
  switch(*(undefined *)((int)puVar5 + 6)) {
  case 0:
    iVar3 = FUN_8001ffb4(0x13f);
    if (iVar3 == 0) {
      *(undefined *)((int)puVar5 + 6) = 1;
    }
    else {
      *(undefined *)((int)puVar5 + 6) = 7;
    }
    break;
  case 1:
    iVar3 = FUN_8001ffb4(0x124);
    if (iVar3 != 0) {
      (**(code **)(*DAT_803dcaac + 0x1c))(psVar2 + 6,(int)*psVar2,1,0);
      puVar5[2] = (uint)FLOAT_803e54b0;
      (**(code **)(*DAT_803dca68 + 0x58))(100000,0x5db);
      *(undefined *)((int)puVar5 + 6) = 2;
    }
    break;
  case 2:
    uVar6 = 0x12;
    for (bVar7 = 0; bVar7 < 0x12; bVar7 = bVar7 + 1) {
      iVar1 = FUN_8001ffb4((int)(short)(&DAT_80327618)[bVar7]);
      if (iVar1 != 0) {
        uVar6 = uVar6 - 1 & 0xff;
      }
    }
    FUN_80137948(s_numBloops__d_80327754,uVar6);
    if (uVar6 == 0) {
      (**(code **)(*DAT_803dca68 + 100))();
      (**(code **)(*DAT_803dca4c + 8))(0x14,1);
      *(undefined *)((int)puVar5 + 6) = 3;
      FUN_8000bb18(0,0x7e);
    }
    else {
      local_28 = (double)CONCAT44(0x43300000,uVar6);
      puVar5[2] = (uint)-((float)(local_28 - DOUBLE_803e54b8) * FLOAT_803db414 - (float)puVar5[2]);
      if ((float)puVar5[2] < FLOAT_803e54b4) {
        cVar4 = (**(code **)(*DAT_803dcaac + 0x4c))((int)*(char *)(iVar3 + 0xac),0);
        if (cVar4 == '\0') {
          puVar5[2] = (uint)FLOAT_803e54b4;
          (**(code **)(*DAT_803dca68 + 0x5c))(1);
        }
        else {
          (**(code **)(*DAT_803dca68 + 100))();
          (**(code **)(*DAT_803dca4c + 8))(0x14,1);
          *(undefined *)((int)puVar5 + 6) = 5;
        }
      }
      else {
        (**(code **)(*DAT_803dca68 + 0x5c))((int)(float)puVar5[2]);
      }
    }
    break;
  case 3:
    iVar1 = (**(code **)(*DAT_803dca4c + 0x14))();
    if ((iVar1 != 0) && (iVar1 = FUN_8002b9ec(), (*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0)) {
      FUN_800200e8(0x13f,1);
      (**(code **)(*DAT_803dca54 + 0x48))(3,iVar3,0xffffffff);
      *(undefined *)((int)puVar5 + 6) = 4;
    }
    break;
  case 4:
    *(undefined *)((int)puVar5 + 6) = 7;
    break;
  case 5:
    iVar1 = (**(code **)(*DAT_803dca4c + 0x14))();
    if ((iVar1 != 0) && (iVar1 = FUN_8002b9ec(), (*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0)) {
      (**(code **)(*DAT_803dca54 + 0x48))(2,iVar3,0xffffffff);
      *(undefined *)((int)puVar5 + 6) = 6;
    }
    break;
  case 6:
    (**(code **)(*DAT_803dcaac + 0x28))();
    break;
  case 7:
    iVar3 = FUN_8001ffb4(0xea6);
    if (iVar3 == 0) {
      FUN_800200e8(0xea6,1);
      iVar3 = FUN_8001ffb4(0x1a2);
      if (iVar3 == 0) {
        FUN_800200e8(0x9d5,1);
      }
    }
  }
  if (*(char *)((int)puVar5 + 6) == '\x02') {
    if (*(short *)((int)puVar5 + 0x12) != 0xf2) {
      *(undefined2 *)((int)puVar5 + 0x12) = 0xf2;
      FUN_800200e8(0xc0,1);
      *puVar5 = *puVar5 & 0xfffffffd;
    }
  }
  else if (*(short *)((int)puVar5 + 0x12) != 0xcc) {
    *(undefined2 *)((int)puVar5 + 0x12) = 0xcc;
    FUN_800200e8(0xc0,1);
    *puVar5 = *puVar5 & 0xfffffffd;
  }
  iVar3 = FUN_8001ffb4(0xea8);
  if ((iVar3 == 0) && (iVar3 = FUN_8001ffb4(0x91b), iVar3 != 0)) {
    FUN_800200e8(0xea8,1);
    (**(code **)(*DAT_803dcaac + 0x1c))(0,0,1,0);
  }
  FUN_80286128();
  return;
}

