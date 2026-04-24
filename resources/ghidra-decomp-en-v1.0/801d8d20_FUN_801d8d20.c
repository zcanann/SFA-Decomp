// Function: FUN_801d8d20
// Entry: 801d8d20
// Size: 2452 bytes

void FUN_801d8d20(int param_1)

{
  int iVar1;
  char cVar4;
  uint uVar2;
  int iVar3;
  uint *puVar5;
  
  puVar5 = *(uint **)(param_1 + 0xb8);
  if (FLOAT_803e54b4 < (float)puVar5[3]) {
    FUN_80016870(0x3f6);
    puVar5[3] = (uint)((float)puVar5[3] - FLOAT_803db414);
    if ((float)puVar5[3] < FLOAT_803e54b4) {
      puVar5[3] = (uint)FLOAT_803e54b4;
    }
  }
  FUN_801d80f4(puVar5);
  iVar1 = FUN_8001ffb4(0x3aa);
  if (iVar1 != 0) {
    if (*(char *)(param_1 + 0xac) == 8) {
      cVar4 = (**(code **)(*DAT_803dcaac + 0x4c))(8,0x1d);
      if (cVar4 == '\0') {
        (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0x1d,1);
      }
    }
    else {
      cVar4 = (**(code **)(*DAT_803dcaac + 0x4c))((int)*(char *)(param_1 + 0xac),0x1d);
      if (cVar4 != '\0') {
        (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0x1d,0);
      }
    }
  }
  iVar1 = FUN_8001ffb4(0x3b8);
  if (iVar1 == 0) {
    cVar4 = (**(code **)(*DAT_803dcaac + 0x4c))((int)*(char *)(param_1 + 0xac),0x1c);
    if (cVar4 != '\0') {
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0x1c,0);
    }
  }
  else {
    cVar4 = (**(code **)(*DAT_803dcaac + 0x4c))((int)*(char *)(param_1 + 0xac),0x1c);
    if (cVar4 == '\0') {
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0x1c,1);
    }
  }
  iVar1 = FUN_8001ffb4(999);
  if ((iVar1 != 0) &&
     (cVar4 = (**(code **)(*DAT_803dcaac + 0x4c))((int)*(char *)(param_1 + 0xac),0x1b),
     cVar4 == '\0')) {
    (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0x1b,1);
  }
  iVar1 = FUN_8001ffb4(0x11);
  if (iVar1 == 0) {
    cVar4 = (**(code **)(*DAT_803dcaac + 0x4c))((int)*(char *)(param_1 + 0xac),0x1a);
    if (cVar4 != '\0') {
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0x1a,0);
    }
  }
  else {
    cVar4 = (**(code **)(*DAT_803dcaac + 0x4c))((int)*(char *)(param_1 + 0xac),0x1a);
    if (cVar4 == '\0') {
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0x1a,1);
    }
  }
  switch(*(undefined *)((int)puVar5 + 5)) {
  case 1:
    FUN_801d8b00(param_1,puVar5);
    break;
  case 2:
    iVar1 = FUN_8001ffb4(0xbf);
    if ((iVar1 == 0) || (uVar2 = FUN_8001ffb4(0xc2), 5 < uVar2)) {
      iVar1 = FUN_8001ffb4(0xc2);
      if ((iVar1 == 6) && (*(short *)((int)puVar5 + 0x12) != 0xcc)) {
        *(undefined2 *)((int)puVar5 + 0x12) = 0xcc;
        FUN_800200e8(0xc0,1);
        *puVar5 = *puVar5 & 0xfffffffd;
      }
    }
    else if (*(short *)((int)puVar5 + 0x12) != 0xdb) {
      *(undefined2 *)((int)puVar5 + 0x12) = 0xdb;
      FUN_800200e8(0xc0,1);
      *puVar5 = *puVar5 & 0xfffffffd;
    }
    iVar1 = FUN_8001ffb4(0xc2);
    iVar3 = FUN_8001ffb4(0x66d);
    if ((iVar3 + iVar1 == 6) && (iVar1 = FUN_8001ffb4(0xe5b), iVar1 == 0)) {
      FUN_8000bb18(param_1,0x7e);
      FUN_800200e8(0xe5b,1);
    }
    break;
  case 3:
    FUN_801d87f8(param_1,puVar5);
    break;
  case 4:
    if (*(short *)((int)puVar5 + 0x12) != 0xcc) {
      *(undefined2 *)((int)puVar5 + 0x12) = 0xcc;
      FUN_800200e8(0xc0,1);
      *puVar5 = *puVar5 & 0xfffffffd;
    }
    if (*(byte *)(puVar5 + 1) < 2) {
      *(byte *)(puVar5 + 1) = *(byte *)(puVar5 + 1) + 1;
    }
    else {
      iVar1 = FUN_8001ffb4(0xdff);
      if (iVar1 == 0) {
        FUN_80014b68(0);
        FUN_80014b58(0);
        FUN_80014b3c(0,0x100);
        FUN_80014b3c(0,0x200);
        FUN_80014b3c(0,0x1000);
        iVar1 = FUN_8002b9ec();
        if ((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0) {
          (**(code **)(*DAT_803dca54 + 0x48))(7,param_1,0xffffffff);
          FUN_800200e8(0xdff,1);
        }
      }
      else {
        iVar1 = FUN_8001ffb4(0xede);
        if (iVar1 == 0) {
          FUN_800200e8(0xede,1);
          FUN_800200e8(0x9d5,1);
        }
      }
    }
    break;
  case 5:
    iVar1 = FUN_8001ffb4(0x23c);
    if (iVar1 == 0) {
      if (*(short *)((int)puVar5 + 0x12) == 0xcc) {
        *(undefined2 *)((int)puVar5 + 0x12) = 0xffff;
      }
    }
    else if (*(short *)((int)puVar5 + 0x12) != 0xcc) {
      *(undefined2 *)((int)puVar5 + 0x12) = 0xcc;
      FUN_800200e8(0xc0,1);
      *puVar5 = *puVar5 & 0xfffffffd;
    }
    iVar1 = FUN_8001ffb4(0x90);
    if (((iVar1 != 0) && (iVar1 = FUN_8001ffb4(0xeb3), iVar1 == 0)) &&
       (iVar1 = FUN_8002b9ec(), (*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0)) {
      FUN_800200e8(0xeb3,1);
    }
    break;
  case 6:
    FUN_801d8308(param_1,puVar5);
    break;
  case 7:
    iVar1 = FUN_8001ffb4(0x1a0);
    if (iVar1 == 0) {
      if (*(short *)((int)puVar5 + 0x12) == 0xcc) {
        *(undefined2 *)((int)puVar5 + 0x12) = 0xffff;
      }
    }
    else if (*(short *)((int)puVar5 + 0x12) != 0xcc) {
      *(undefined2 *)((int)puVar5 + 0x12) = 0xcc;
      FUN_800200e8(0xc0,1);
      *puVar5 = *puVar5 & 0xfffffffd;
    }
    if (*(byte *)(puVar5 + 1) < 2) {
      *(byte *)(puVar5 + 1) = *(byte *)(puVar5 + 1) + 1;
    }
    else {
      iVar1 = FUN_8001ffb4(0x177);
      if (iVar1 == 0) {
        FUN_80014b68(0);
        FUN_80014b58(0);
        FUN_80014b3c(0,0x100);
        FUN_80014b3c(0,0x200);
        FUN_80014b3c(0,0x1000);
        iVar1 = FUN_8002b9ec();
        if ((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0) {
          (**(code **)(*DAT_803dca54 + 0x48))(4,param_1,0xffffffff);
          FUN_800200e8(0x177,1);
        }
      }
    }
    break;
  case 8:
    if (*(short *)((int)puVar5 + 0x12) != 0xcc) {
      *(undefined2 *)((int)puVar5 + 0x12) = 0xcc;
      FUN_800200e8(0xc0,1);
      *puVar5 = *puVar5 & 0xfffffffd;
    }
    iVar1 = FUN_8001ffb4(0x19c);
    if ((iVar1 != 0) && (iVar1 = FUN_8001ffb4(0xf3e), iVar1 == 0)) {
      FUN_800200e8(0xf3e,1);
      iVar1 = FUN_8001ffb4(0xc64);
      if (iVar1 == 0) {
        FUN_800200e8(0x9d5,1);
      }
    }
  }
  iVar1 = FUN_8001ffb4(0xd36);
  if (iVar1 == 0) {
    iVar1 = FUN_8001ffb4(0xd35);
    if (iVar1 == 0) {
      if (*(int *)(param_1 + 0xf8) != 0) {
        *(undefined4 *)(param_1 + 0xf8) = 0;
        if (*(int *)(param_1 + 0xf4) == 2) {
          FUN_80088870(&DAT_80327674,&DAT_8032763c,&DAT_803276ac,&DAT_803276e4);
          FUN_800887f8(0x3f);
          FUN_80008b74(0,0,0x244,0);
          FUN_80088e54((double)FLOAT_803e54b4,0);
        }
        else {
          FUN_80088870(&DAT_80327674,&DAT_8032763c,&DAT_803276ac,&DAT_803276e4);
          FUN_800887f8(0x1f);
          FUN_80008cbc(0,0,0x244,0);
        }
      }
    }
    else if (*(int *)(param_1 + 0xf8) != 1) {
      *(undefined4 *)(param_1 + 0xf8) = 1;
      if (*(int *)(param_1 + 0xf4) == 2) {
        FUN_800887f8(0);
        FUN_80008b74(0,0,0x1bf,0);
        FUN_80008b74(0,0,0x1be,0);
        FUN_80008b74(0,0,0x1c0,0);
        FUN_80008b74(0,0,0x244,0);
      }
      else {
        FUN_800887f8(0);
        FUN_80008cbc(0,0,0x1bf,0);
        FUN_80008cbc(0,0,0x1be,0);
        FUN_80008cbc(0,0,0x1c0,0);
        FUN_80008cbc(0,0,0x244,0);
      }
    }
  }
  else if (*(int *)(param_1 + 0xf8) != 2) {
    *(undefined4 *)(param_1 + 0xf8) = 2;
    FUN_800887f8(0);
    if (*(int *)(param_1 + 0xf4) == 2) {
      FUN_80008b74(0,0,0x1bf,0);
      FUN_80008b74(0,0,0x231,0);
      FUN_80008b74(0,0,0x232,0);
      FUN_80008b74(0,0,0x244,0);
    }
    else {
      FUN_80008cbc(0,0,0x1bf,0);
      FUN_80008cbc(0,0,0x231,0);
      FUN_80008cbc(0,0,0x232,0);
      FUN_80008cbc(0,0,0x244,0);
    }
  }
  FUN_801d7c94(param_1,puVar5);
  return;
}

