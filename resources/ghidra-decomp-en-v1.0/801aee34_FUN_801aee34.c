// Function: FUN_801aee34
// Entry: 801aee34
// Size: 1368 bytes

/* WARNING: Removing unreachable block (ram,0x801af008) */

void FUN_801aee34(void)

{
  byte bVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  byte *pbVar6;
  int iVar7;
  uint *puVar8;
  
  iVar3 = FUN_802860dc();
  puVar8 = *(uint **)(iVar3 + 0xb8);
  iVar4 = FUN_8002b9ec();
  iVar5 = FUN_8002b9ac();
  pbVar6 = (byte *)(**(code **)(*DAT_803dcaac + 0x94))();
  iVar7 = (**(code **)(*DAT_803dca58 + 0x24))(0);
  if (iVar7 == 0) {
    if ((*(short *)(puVar8 + 3) != 0x1a) && (*(undefined2 *)(puVar8 + 3) = 0x1a, (*puVar8 & 8) != 0)
       ) {
      FUN_8000a518(0x1a,1);
    }
  }
  else if ((*(short *)(puVar8 + 3) != -1) &&
          (*(undefined2 *)(puVar8 + 3) = 0xffff, (*puVar8 & 8) != 0)) {
    FUN_8000a518(0x1a,0);
  }
  FUN_801d7ed4(puVar8,1,0xffffffff,0xffffffff,0x3a0,0x35);
  FUN_801d7ed4(puVar8,2,0xffffffff,0xffffffff,0xb36,0x96);
  FUN_801d7ed4(puVar8,8,0xffffffff,0xffffffff,0x3a1,(int)*(short *)(puVar8 + 3));
  if ((*puVar8 & 4) == 0) {
    iVar7 = FUN_8001ffb4(0x256);
    if ((iVar7 != 0) || (iVar7 = FUN_8001ffb4(0x1fd), iVar7 != 0)) {
      FUN_800200e8(0x36e,1);
      *puVar8 = *puVar8 | 4;
    }
  }
  else {
    iVar7 = FUN_8001ffb4(0x1fd);
    if ((iVar7 == 0) && (iVar7 = FUN_8001ffb4(0x256), iVar7 == 0)) {
      FUN_800200e8(0x36e,0);
      *puVar8 = *puVar8 & 0xfffffffb;
    }
  }
  if (iVar5 != 0) {
    FUN_80138908(iVar5,0);
    bVar1 = *(byte *)(puVar8 + 1) >> 3 & 7;
    if (bVar1 == 2) {
      if (*pbVar6 != 0) {
        FUN_80138908(iVar5,1);
        cVar2 = (char)*(byte *)(puVar8 + 1) >> 6;
        *(byte *)(puVar8 + 1) = (cVar2 + -1) * '@' | *(byte *)(puVar8 + 1) & 0x3f;
        if ((cVar2 == -1) && ((*(ushort *)(iVar5 + 0xb0) & 0x1000) == 0)) {
          FUN_800200e8(0x386,1);
          (**(code **)(*DAT_803dca54 + 0x48))(*(byte *)(puVar8 + 1) >> 3 & 7,iVar3,0xffffffff);
          *(byte *)(puVar8 + 1) =
               ((*(byte *)(puVar8 + 1) >> 3 & 7) + 1) * '\b' & 0x38 | *(byte *)(puVar8 + 1) & 199;
          *(byte *)(puVar8 + 1) = *(byte *)(puVar8 + 1) & 0xf8;
          goto LAB_801af374;
        }
      }
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        iVar4 = FUN_8001ffb4(900);
        if (iVar4 != 0) {
          FUN_80138908(iVar5,1);
          (**(code **)(*DAT_803dca54 + 0x48))(*(byte *)(puVar8 + 1) >> 3 & 7,iVar3,0xffffffff);
          *(byte *)(puVar8 + 1) =
               ((*(byte *)(puVar8 + 1) >> 3 & 7) + 1) * '\b' & 0x38 | *(byte *)(puVar8 + 1) & 199;
          *(byte *)(puVar8 + 1) = *(byte *)(puVar8 + 1) & 0xf8;
          goto LAB_801af374;
        }
      }
      else {
        iVar7 = FUN_8001ffb4(0xc1);
        if ((iVar7 != 0) && ((*(ushort *)(iVar4 + 0xb0) & 0x1000) == 0)) {
          FUN_800200e8(0x385,1);
          FUN_80138908(iVar5,1);
          (**(code **)(*DAT_803dca54 + 0x48))(*(byte *)(puVar8 + 1) >> 3 & 7,iVar3,0xffffffff);
          *(byte *)(puVar8 + 1) =
               ((*(byte *)(puVar8 + 1) >> 3 & 7) + 1) * '\b' & 0x38 | *(byte *)(puVar8 + 1) & 199;
          *(byte *)(puVar8 + 1) = *(byte *)(puVar8 + 1) & 0xf8;
          goto LAB_801af374;
        }
      }
    }
    else if (bVar1 == 4) {
      iVar4 = FUN_8001ffb4(0x543);
      if (iVar4 != 0) {
        FUN_80138908(iVar5,1);
        (**(code **)(*DAT_803dca54 + 0x48))(*(byte *)(puVar8 + 1) >> 3 & 7,iVar3,0xffffffff);
        *(byte *)(puVar8 + 1) =
             ((*(byte *)(puVar8 + 1) >> 3 & 7) + 1) * '\b' & 0x38 | *(byte *)(puVar8 + 1) & 199;
        *(byte *)(puVar8 + 1) = *(byte *)(puVar8 + 1) & 0xf8;
        goto LAB_801af374;
      }
    }
    else if (bVar1 < 4) {
      iVar4 = FUN_8001ffb4(0x1fd);
      if (iVar4 == 0) {
        iVar4 = FUN_8001ffb4(0x380);
        if (iVar4 == 0) {
          if (*(char *)((int)puVar8 + 5) < '\0') {
            FUN_800200e8(0x387,1);
            FUN_80138908(iVar5,1);
            (**(code **)(*DAT_803dca54 + 0x48))(*(byte *)(puVar8 + 1) >> 3 & 7,iVar3,0xffffffff);
            *(byte *)(puVar8 + 1) =
                 ((*(byte *)(puVar8 + 1) >> 3 & 7) + 1) * '\b' & 0x38 | *(byte *)(puVar8 + 1) & 199;
            *(byte *)(puVar8 + 1) = *(byte *)(puVar8 + 1) & 0xf8;
            goto LAB_801af374;
          }
        }
        else {
          *(byte *)((int)puVar8 + 5) = *(byte *)((int)puVar8 + 5) & 0x7f | 0x80;
        }
      }
      else {
        FUN_800200e8(0x387,1);
        *(byte *)(puVar8 + 1) =
             ((*(byte *)(puVar8 + 1) >> 3 & 7) + 1) * '\b' & 0x38 | *(byte *)(puVar8 + 1) & 199;
      }
    }
  }
  if (iVar5 != 0) {
    if ((*(ushort *)(iVar5 + 0xb0) & 0x1000) == 0) {
      puVar8[2] = (uint)((float)puVar8[2] + FLOAT_803db414);
    }
    iVar3 = FUN_8001ffb4(0x4e3);
    if ((iVar3 == 1) && (3 < *pbVar6)) {
      FUN_800200e8(0x4e3,0xff);
    }
    if (FLOAT_803e47c8 <= (float)puVar8[2]) {
      puVar8[2] = (uint)((float)puVar8[2] - FLOAT_803e47c8);
      iVar3 = FUN_8001ffb4(0x4e3);
      if ((iVar3 == 0xff) && (*pbVar6 < 4)) {
        FUN_800200e8(0x4e3,1);
      }
    }
  }
LAB_801af374:
  FUN_80286128();
  return;
}

