// Function: FUN_801d88f8
// Entry: 801d88f8
// Size: 1264 bytes

void FUN_801d88f8(void)

{
  int iVar1;
  char cVar6;
  uint uVar2;
  short *psVar3;
  uint uVar4;
  int iVar5;
  uint *puVar7;
  byte bVar8;
  undefined8 uVar9;
  undefined8 local_28;
  
  uVar9 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar9 >> 0x20);
  puVar7 = (uint *)uVar9;
  cVar6 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(iVar1 + 0xac),0);
  if ((cVar6 == '\0') && (uVar2 = FUN_80020078(0x13f), uVar2 == 0)) {
    *(undefined *)((int)puVar7 + 6) = 0;
    (**(code **)(*DAT_803dd6e8 + 100))();
    for (bVar8 = 0; bVar8 < 0x12; bVar8 = bVar8 + 1) {
      FUN_800201ac((int)(short)(&DAT_80328258)[bVar8],0);
    }
  }
  psVar3 = (short *)FUN_8002bac4();
  switch(*(undefined *)((int)puVar7 + 6)) {
  case 0:
    uVar2 = FUN_80020078(0x13f);
    if (uVar2 == 0) {
      *(undefined *)((int)puVar7 + 6) = 1;
    }
    else {
      *(undefined *)((int)puVar7 + 6) = 7;
    }
    break;
  case 1:
    uVar2 = FUN_80020078(0x124);
    if (uVar2 != 0) {
      (**(code **)(*DAT_803dd72c + 0x1c))(psVar3 + 6,(int)*psVar3,1,0);
      puVar7[2] = (uint)FLOAT_803e6148;
      (**(code **)(*DAT_803dd6e8 + 0x58))(100000,0x5db);
      *(undefined *)((int)puVar7 + 6) = 2;
    }
    break;
  case 2:
    uVar2 = 0x12;
    for (bVar8 = 0; bVar8 < 0x12; bVar8 = bVar8 + 1) {
      uVar4 = FUN_80020078((int)(short)(&DAT_80328258)[bVar8]);
      if (uVar4 != 0) {
        uVar2 = uVar2 - 1 & 0xff;
      }
    }
    FUN_80137cd0();
    if (uVar2 == 0) {
      (**(code **)(*DAT_803dd6e8 + 100))();
      (**(code **)(*DAT_803dd6cc + 8))(0x14,1);
      *(undefined *)((int)puVar7 + 6) = 3;
      FUN_8000bb38(0,0x7e);
    }
    else {
      local_28 = (double)CONCAT44(0x43300000,uVar2);
      puVar7[2] = (uint)-((float)(local_28 - DOUBLE_803e6150) * FLOAT_803dc074 - (float)puVar7[2]);
      if ((float)puVar7[2] < FLOAT_803e614c) {
        cVar6 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(iVar1 + 0xac),0);
        if (cVar6 == '\0') {
          puVar7[2] = (uint)FLOAT_803e614c;
          (**(code **)(*DAT_803dd6e8 + 0x5c))(1);
        }
        else {
          (**(code **)(*DAT_803dd6e8 + 100))();
          (**(code **)(*DAT_803dd6cc + 8))(0x14,1);
          *(undefined *)((int)puVar7 + 6) = 5;
        }
      }
      else {
        (**(code **)(*DAT_803dd6e8 + 0x5c))((int)(float)puVar7[2]);
      }
    }
    break;
  case 3:
    iVar5 = (**(code **)(*DAT_803dd6cc + 0x14))();
    if ((iVar5 != 0) && (iVar5 = FUN_8002bac4(), (*(ushort *)(iVar5 + 0xb0) & 0x1000) == 0)) {
      FUN_800201ac(0x13f,1);
      (**(code **)(*DAT_803dd6d4 + 0x48))(3,iVar1,0xffffffff);
      *(undefined *)((int)puVar7 + 6) = 4;
    }
    break;
  case 4:
    *(undefined *)((int)puVar7 + 6) = 7;
    break;
  case 5:
    iVar5 = (**(code **)(*DAT_803dd6cc + 0x14))();
    if ((iVar5 != 0) && (iVar5 = FUN_8002bac4(), (*(ushort *)(iVar5 + 0xb0) & 0x1000) == 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(2,iVar1,0xffffffff);
      *(undefined *)((int)puVar7 + 6) = 6;
    }
    break;
  case 6:
    (**(code **)(*DAT_803dd72c + 0x28))();
    break;
  case 7:
    uVar2 = FUN_80020078(0xea6);
    if (uVar2 == 0) {
      FUN_800201ac(0xea6,1);
      uVar2 = FUN_80020078(0x1a2);
      if (uVar2 == 0) {
        FUN_800201ac(0x9d5,1);
      }
    }
  }
  if (*(char *)((int)puVar7 + 6) == '\x02') {
    if (*(short *)((int)puVar7 + 0x12) != 0xf2) {
      *(undefined2 *)((int)puVar7 + 0x12) = 0xf2;
      FUN_800201ac(0xc0,1);
      *puVar7 = *puVar7 & 0xfffffffd;
    }
  }
  else if (*(short *)((int)puVar7 + 0x12) != 0xcc) {
    *(undefined2 *)((int)puVar7 + 0x12) = 0xcc;
    FUN_800201ac(0xc0,1);
    *puVar7 = *puVar7 & 0xfffffffd;
  }
  uVar2 = FUN_80020078(0xea8);
  if ((uVar2 == 0) && (uVar2 = FUN_80020078(0x91b), uVar2 != 0)) {
    FUN_800201ac(0xea8,1);
    (**(code **)(*DAT_803dd72c + 0x1c))(0,0,1,0);
  }
  FUN_8028688c();
  return;
}

