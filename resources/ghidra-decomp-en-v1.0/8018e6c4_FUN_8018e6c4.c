// Function: FUN_8018e6c4
// Entry: 8018e6c4
// Size: 992 bytes

/* WARNING: Removing unreachable block (ram,0x8018e72c) */

void FUN_8018e6c4(void)

{
  byte bVar1;
  undefined2 *puVar2;
  int *piVar3;
  int iVar4;
  short sVar5;
  uint uVar6;
  int iVar7;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  float local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  puVar2 = (undefined2 *)FUN_802860dc();
  iVar7 = *(int *)(puVar2 + 0x5c);
  iVar4 = *(int *)(puVar2 + 0x26);
  uVar6 = 0;
  if (*(short *)(iVar7 + 10) == 0x11) {
    FUN_80137948((double)*(float *)(puVar2 + 6),(double)*(float *)(puVar2 + 10),s__x__f__f_80321f70,
                 puVar2);
  }
  bVar1 = *(byte *)(iVar4 + 0x28);
  if (bVar1 == 2) {
    sVar5 = *(short *)(iVar7 + 8);
    if (sVar5 == 0) {
      uVar6 = 0x200001;
    }
    if (sVar5 == 1) {
      uVar6 = 1;
    }
    if (sVar5 == 2) {
      uVar6 = 1;
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      sVar5 = *(short *)(iVar7 + 8);
      if (sVar5 == 0) {
        uVar6 = 2;
      }
      if (sVar5 == 1) {
        uVar6 = 2;
      }
      if (sVar5 == 2) {
        uVar6 = 2;
      }
    }
    else {
      sVar5 = *(short *)(iVar7 + 8);
      if (sVar5 == 0) {
        uVar6 = 4;
      }
      if (sVar5 == 1) {
        uVar6 = 4;
      }
      if (sVar5 == 2) {
        uVar6 = 4;
      }
    }
  }
  else if (bVar1 < 4) {
    uVar6 = 0;
  }
  else {
    uVar6 = 2;
  }
  if ((uVar6 & 1) == 0) {
    sVar5 = *(short *)(iVar7 + 8);
    if (sVar5 == 0) {
      if (*(short *)(iVar7 + 0xe) < 1) {
        (**(code **)(*DAT_803dca88 + 8))(puVar2,(int)*(short *)(iVar7 + 10),0,uVar6,0xffffffff,0);
      }
      else {
        for (sVar5 = 0; sVar5 < *(short *)(iVar7 + 0xe); sVar5 = sVar5 + 1) {
          (**(code **)(*DAT_803dca88 + 8))(puVar2,(int)*(short *)(iVar7 + 10),0,uVar6,0xffffffff,0);
        }
      }
    }
    else if (sVar5 == 1) {
      piVar3 = (int *)FUN_80013ec8(*(short *)(iVar7 + 10) + 0x58,1);
      if (*(short *)(iVar7 + 0xe) < 1) {
        (**(code **)(*piVar3 + 4))(puVar2,0,0,uVar6,0xffffffff,0);
      }
      else {
        for (sVar5 = 0; sVar5 < *(short *)(iVar7 + 0xe); sVar5 = sVar5 + 1) {
          (**(code **)(*piVar3 + 4))(puVar2,0,0,uVar6,0xffffffff,0);
        }
      }
      FUN_80013e2c(piVar3);
    }
    else if (sVar5 == 2) {
      piVar3 = (int *)FUN_80013ec8(*(short *)(iVar7 + 10) + 0xab,1);
      if (*(short *)(iVar7 + 0xe) < 1) {
        (**(code **)(*piVar3 + 4))(puVar2,0,0,uVar6,0xffffffff,*(ushort *)(iVar7 + 10) & 0xff,0);
      }
      else {
        for (sVar5 = 0; sVar5 < *(short *)(iVar7 + 0xe); sVar5 = sVar5 + 1) {
          (**(code **)(*piVar3 + 4))(puVar2,0,0,uVar6,0xffffffff,*(ushort *)(iVar7 + 10) & 0xff,0);
        }
      }
      FUN_80013e2c(piVar3);
    }
  }
  else {
    local_2c = *(undefined4 *)(puVar2 + 6);
    local_28 = *(undefined4 *)(puVar2 + 8);
    local_24 = *(undefined4 *)(puVar2 + 10);
    local_38 = *puVar2;
    local_34 = puVar2[2];
    local_36 = puVar2[1];
    local_30 = FLOAT_803e3e48;
    if (*(short *)(iVar7 + 0xe) < 1) {
      (**(code **)(*DAT_803dca88 + 8))
                (puVar2,(int)*(short *)(iVar7 + 0xc),&local_38,uVar6,0xffffffff,0);
    }
    else {
      for (sVar5 = 0; sVar5 < *(short *)(iVar7 + 0xe); sVar5 = sVar5 + 1) {
        (**(code **)(*DAT_803dca88 + 8))
                  (puVar2,(int)*(short *)(iVar7 + 10),&local_38,uVar6,0xffffffff,0);
      }
    }
  }
  FUN_80286128();
  return;
}

