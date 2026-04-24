// Function: FUN_801d9310
// Entry: 801d9310
// Size: 2452 bytes

void FUN_801d9310(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  uint uVar1;
  char cVar4;
  uint uVar2;
  int iVar3;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint *puVar5;
  undefined8 extraout_f1;
  undefined8 uVar6;
  undefined8 extraout_f1_00;
  
  puVar5 = *(uint **)(param_9 + 0xb8);
  if ((double)FLOAT_803e614c < (double)(float)puVar5[3]) {
    FUN_800168a8((double)(float)puVar5[3],param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 0x3f6);
    puVar5[3] = (uint)((float)puVar5[3] - FLOAT_803dc074);
    if ((float)puVar5[3] < FLOAT_803e614c) {
      puVar5[3] = (uint)FLOAT_803e614c;
    }
  }
  FUN_801d86e4(puVar5);
  uVar1 = FUN_80020078(0x3aa);
  if (uVar1 != 0) {
    if (*(char *)(param_9 + 0xac) == 8) {
      cVar4 = (**(code **)(*DAT_803dd72c + 0x4c))(8,0x1d);
      if (cVar4 == '\0') {
        (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0x1d,1);
      }
    }
    else {
      cVar4 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(param_9 + 0xac),0x1d);
      if (cVar4 != '\0') {
        (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0x1d,0);
      }
    }
  }
  uVar1 = FUN_80020078(0x3b8);
  if (uVar1 == 0) {
    cVar4 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(param_9 + 0xac),0x1c);
    if (cVar4 != '\0') {
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0x1c,0);
    }
  }
  else {
    cVar4 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(param_9 + 0xac),0x1c);
    if (cVar4 == '\0') {
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0x1c,1);
    }
  }
  uVar1 = FUN_80020078(999);
  if ((uVar1 != 0) &&
     (cVar4 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(param_9 + 0xac),0x1b),
     cVar4 == '\0')) {
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0x1b,1);
  }
  uVar1 = FUN_80020078(0x11);
  if (uVar1 == 0) {
    cVar4 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(param_9 + 0xac),0x1a);
    uVar6 = extraout_f1_00;
    if (cVar4 != '\0') {
      uVar6 = (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0x1a,0);
    }
  }
  else {
    cVar4 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(param_9 + 0xac),0x1a);
    uVar6 = extraout_f1;
    if (cVar4 == '\0') {
      uVar6 = (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0x1a,1);
    }
  }
  switch(*(undefined *)((int)puVar5 + 5)) {
  case 1:
    uVar6 = FUN_801d90f0(param_9,puVar5);
    break;
  case 2:
    uVar1 = FUN_80020078(0xbf);
    if ((uVar1 == 0) || (uVar1 = FUN_80020078(0xc2), 5 < uVar1)) {
      uVar1 = FUN_80020078(0xc2);
      if ((uVar1 == 6) && (*(short *)((int)puVar5 + 0x12) != 0xcc)) {
        *(undefined2 *)((int)puVar5 + 0x12) = 0xcc;
        uVar6 = FUN_800201ac(0xc0,1);
        *puVar5 = *puVar5 & 0xfffffffd;
      }
    }
    else if (*(short *)((int)puVar5 + 0x12) != 0xdb) {
      *(undefined2 *)((int)puVar5 + 0x12) = 0xdb;
      uVar6 = FUN_800201ac(0xc0,1);
      *puVar5 = *puVar5 & 0xfffffffd;
    }
    uVar1 = FUN_80020078(0xc2);
    uVar2 = FUN_80020078(0x66d);
    if ((uVar2 + uVar1 == 6) && (uVar1 = FUN_80020078(0xe5b), uVar1 == 0)) {
      FUN_8000bb38(param_9,0x7e);
      uVar6 = FUN_800201ac(0xe5b,1);
    }
    break;
  case 3:
    uVar6 = FUN_801d8de8(param_9,puVar5);
    break;
  case 4:
    if (*(short *)((int)puVar5 + 0x12) != 0xcc) {
      *(undefined2 *)((int)puVar5 + 0x12) = 0xcc;
      uVar6 = FUN_800201ac(0xc0,1);
      *puVar5 = *puVar5 & 0xfffffffd;
    }
    if (*(byte *)(puVar5 + 1) < 2) {
      *(byte *)(puVar5 + 1) = *(byte *)(puVar5 + 1) + 1;
    }
    else {
      uVar1 = FUN_80020078(0xdff);
      if (uVar1 == 0) {
        FUN_80014b94(0);
        FUN_80014b84(0);
        FUN_80014b68(0,0x100);
        FUN_80014b68(0,0x200);
        uVar6 = FUN_80014b68(0,0x1000);
        iVar3 = FUN_8002bac4();
        if ((*(ushort *)(iVar3 + 0xb0) & 0x1000) == 0) {
          (**(code **)(*DAT_803dd6d4 + 0x48))(7,param_9,0xffffffff);
          uVar6 = FUN_800201ac(0xdff,1);
        }
      }
      else {
        uVar1 = FUN_80020078(0xede);
        if (uVar1 == 0) {
          FUN_800201ac(0xede,1);
          uVar6 = FUN_800201ac(0x9d5,1);
        }
      }
    }
    break;
  case 5:
    uVar1 = FUN_80020078(0x23c);
    if (uVar1 == 0) {
      if (*(short *)((int)puVar5 + 0x12) == 0xcc) {
        *(undefined2 *)((int)puVar5 + 0x12) = 0xffff;
      }
    }
    else if (*(short *)((int)puVar5 + 0x12) != 0xcc) {
      *(undefined2 *)((int)puVar5 + 0x12) = 0xcc;
      uVar6 = FUN_800201ac(0xc0,1);
      *puVar5 = *puVar5 & 0xfffffffd;
    }
    uVar1 = FUN_80020078(0x90);
    if (((uVar1 != 0) && (uVar1 = FUN_80020078(0xeb3), uVar1 == 0)) &&
       (iVar3 = FUN_8002bac4(), (*(ushort *)(iVar3 + 0xb0) & 0x1000) == 0)) {
      uVar6 = FUN_800201ac(0xeb3,1);
    }
    break;
  case 6:
    uVar6 = FUN_801d88f8();
    break;
  case 7:
    uVar1 = FUN_80020078(0x1a0);
    if (uVar1 == 0) {
      if (*(short *)((int)puVar5 + 0x12) == 0xcc) {
        *(undefined2 *)((int)puVar5 + 0x12) = 0xffff;
      }
    }
    else if (*(short *)((int)puVar5 + 0x12) != 0xcc) {
      *(undefined2 *)((int)puVar5 + 0x12) = 0xcc;
      uVar6 = FUN_800201ac(0xc0,1);
      *puVar5 = *puVar5 & 0xfffffffd;
    }
    if (*(byte *)(puVar5 + 1) < 2) {
      *(byte *)(puVar5 + 1) = *(byte *)(puVar5 + 1) + 1;
    }
    else {
      uVar1 = FUN_80020078(0x177);
      if (uVar1 == 0) {
        FUN_80014b94(0);
        FUN_80014b84(0);
        FUN_80014b68(0,0x100);
        FUN_80014b68(0,0x200);
        uVar6 = FUN_80014b68(0,0x1000);
        iVar3 = FUN_8002bac4();
        if ((*(ushort *)(iVar3 + 0xb0) & 0x1000) == 0) {
          (**(code **)(*DAT_803dd6d4 + 0x48))(4,param_9,0xffffffff);
          uVar6 = FUN_800201ac(0x177,1);
        }
      }
    }
    break;
  case 8:
    if (*(short *)((int)puVar5 + 0x12) != 0xcc) {
      *(undefined2 *)((int)puVar5 + 0x12) = 0xcc;
      uVar6 = FUN_800201ac(0xc0,1);
      *puVar5 = *puVar5 & 0xfffffffd;
    }
    uVar1 = FUN_80020078(0x19c);
    if ((uVar1 != 0) && (uVar1 = FUN_80020078(0xf3e), uVar1 == 0)) {
      uVar6 = FUN_800201ac(0xf3e,1);
      uVar1 = FUN_80020078(0xc64);
      if (uVar1 == 0) {
        uVar6 = FUN_800201ac(0x9d5,1);
      }
    }
  }
  uVar1 = FUN_80020078(0xd36);
  if (uVar1 == 0) {
    uVar1 = FUN_80020078(0xd35);
    if (uVar1 == 0) {
      if (*(int *)(param_9 + 0xf8) != 0) {
        *(undefined4 *)(param_9 + 0xf8) = 0;
        if (*(int *)(param_9 + 0xf4) == 2) {
          uVar6 = FUN_80088afc(&DAT_803282b4,&DAT_8032827c,&DAT_803282ec,&DAT_80328324);
          uVar6 = FUN_80088a84(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3f);
          FUN_80008b74(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x244,0,
                       in_r7,in_r8,in_r9,in_r10);
          uVar6 = FUN_800890e0((double)FLOAT_803e614c,0);
        }
        else {
          uVar6 = FUN_80088afc(&DAT_803282b4,&DAT_8032827c,&DAT_803282ec,&DAT_80328324);
          uVar6 = FUN_80088a84(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x1f);
          uVar6 = FUN_80008cbc(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,
                               0x244,0,in_r7,in_r8,in_r9,in_r10);
        }
      }
    }
    else if (*(int *)(param_9 + 0xf8) != 1) {
      *(undefined4 *)(param_9 + 0xf8) = 1;
      if (*(int *)(param_9 + 0xf4) == 2) {
        uVar6 = FUN_80088a84(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
        uVar6 = FUN_80008b74(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x1bf
                             ,0,in_r7,in_r8,in_r9,in_r10);
        uVar6 = FUN_80008b74(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x1be
                             ,0,in_r7,in_r8,in_r9,in_r10);
        uVar6 = FUN_80008b74(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x1c0
                             ,0,in_r7,in_r8,in_r9,in_r10);
        uVar6 = FUN_80008b74(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x244
                             ,0,in_r7,in_r8,in_r9,in_r10);
      }
      else {
        uVar6 = FUN_80088a84(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
        uVar6 = FUN_80008cbc(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x1bf
                             ,0,in_r7,in_r8,in_r9,in_r10);
        uVar6 = FUN_80008cbc(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x1be
                             ,0,in_r7,in_r8,in_r9,in_r10);
        uVar6 = FUN_80008cbc(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x1c0
                             ,0,in_r7,in_r8,in_r9,in_r10);
        uVar6 = FUN_80008cbc(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x244
                             ,0,in_r7,in_r8,in_r9,in_r10);
      }
    }
  }
  else if (*(int *)(param_9 + 0xf8) != 2) {
    *(undefined4 *)(param_9 + 0xf8) = 2;
    uVar6 = FUN_80088a84(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
    if (*(int *)(param_9 + 0xf4) == 2) {
      uVar6 = FUN_80008b74(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x1bf,0
                           ,in_r7,in_r8,in_r9,in_r10);
      uVar6 = FUN_80008b74(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x231,0
                           ,in_r7,in_r8,in_r9,in_r10);
      uVar6 = FUN_80008b74(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x232,0
                           ,in_r7,in_r8,in_r9,in_r10);
      uVar6 = FUN_80008b74(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x244,0
                           ,in_r7,in_r8,in_r9,in_r10);
    }
    else {
      uVar6 = FUN_80008cbc(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x1bf,0
                           ,in_r7,in_r8,in_r9,in_r10);
      uVar6 = FUN_80008cbc(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x231,0
                           ,in_r7,in_r8,in_r9,in_r10);
      uVar6 = FUN_80008cbc(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x232,0
                           ,in_r7,in_r8,in_r9,in_r10);
      uVar6 = FUN_80008cbc(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x244,0
                           ,in_r7,in_r8,in_r9,in_r10);
    }
  }
  FUN_801d8284(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,(int)puVar5);
  return;
}

