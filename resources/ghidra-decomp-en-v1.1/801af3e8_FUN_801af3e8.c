// Function: FUN_801af3e8
// Entry: 801af3e8
// Size: 1368 bytes

/* WARNING: Removing unreachable block (ram,0x801af5bc) */

void FUN_801af3e8(void)

{
  byte bVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  byte *pbVar6;
  int iVar7;
  uint uVar8;
  uint *puVar9;
  
  iVar3 = FUN_80286840();
  puVar9 = *(uint **)(iVar3 + 0xb8);
  iVar4 = FUN_8002bac4();
  iVar5 = FUN_8002ba84();
  pbVar6 = (byte *)(**(code **)(*DAT_803dd72c + 0x94))();
  iVar7 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
  if (iVar7 == 0) {
    if ((*(short *)(puVar9 + 3) != 0x1a) && (*(undefined2 *)(puVar9 + 3) = 0x1a, (*puVar9 & 8) != 0)
       ) {
      FUN_8000a538((int *)0x1a,1);
    }
  }
  else if ((*(short *)(puVar9 + 3) != -1) &&
          (*(undefined2 *)(puVar9 + 3) = 0xffff, (*puVar9 & 8) != 0)) {
    FUN_8000a538((int *)0x1a,0);
  }
  FUN_801d84c4(puVar9,1,-1,-1,0x3a0,(int *)0x35);
  FUN_801d84c4(puVar9,2,-1,-1,0xb36,(int *)0x96);
  FUN_801d84c4(puVar9,8,-1,-1,0x3a1,(int *)(int)*(short *)(puVar9 + 3));
  if ((*puVar9 & 4) == 0) {
    uVar8 = FUN_80020078(0x256);
    if ((uVar8 != 0) || (uVar8 = FUN_80020078(0x1fd), uVar8 != 0)) {
      FUN_800201ac(0x36e,1);
      *puVar9 = *puVar9 | 4;
    }
  }
  else {
    uVar8 = FUN_80020078(0x1fd);
    if ((uVar8 == 0) && (uVar8 = FUN_80020078(0x256), uVar8 == 0)) {
      FUN_800201ac(0x36e,0);
      *puVar9 = *puVar9 & 0xfffffffb;
    }
  }
  if (iVar5 != 0) {
    FUN_80138c90(iVar5,0);
    bVar1 = *(byte *)(puVar9 + 1) >> 3 & 7;
    if (bVar1 == 2) {
      if (*pbVar6 != 0) {
        FUN_80138c90(iVar5,1);
        cVar2 = (char)*(byte *)(puVar9 + 1) >> 6;
        *(byte *)(puVar9 + 1) = (cVar2 + -1) * '@' | *(byte *)(puVar9 + 1) & 0x3f;
        if ((cVar2 == -1) && ((*(ushort *)(iVar5 + 0xb0) & 0x1000) == 0)) {
          FUN_800201ac(0x386,1);
          (**(code **)(*DAT_803dd6d4 + 0x48))(*(byte *)(puVar9 + 1) >> 3 & 7,iVar3,0xffffffff);
          *(byte *)(puVar9 + 1) =
               ((*(byte *)(puVar9 + 1) >> 3 & 7) + 1) * '\b' & 0x38 | *(byte *)(puVar9 + 1) & 199;
          *(byte *)(puVar9 + 1) = *(byte *)(puVar9 + 1) & 0xf8;
          goto LAB_801af928;
        }
      }
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        uVar8 = FUN_80020078(900);
        if (uVar8 != 0) {
          FUN_80138c90(iVar5,1);
          (**(code **)(*DAT_803dd6d4 + 0x48))(*(byte *)(puVar9 + 1) >> 3 & 7,iVar3,0xffffffff);
          *(byte *)(puVar9 + 1) =
               ((*(byte *)(puVar9 + 1) >> 3 & 7) + 1) * '\b' & 0x38 | *(byte *)(puVar9 + 1) & 199;
          *(byte *)(puVar9 + 1) = *(byte *)(puVar9 + 1) & 0xf8;
          goto LAB_801af928;
        }
      }
      else {
        uVar8 = FUN_80020078(0xc1);
        if ((uVar8 != 0) && ((*(ushort *)(iVar4 + 0xb0) & 0x1000) == 0)) {
          FUN_800201ac(0x385,1);
          FUN_80138c90(iVar5,1);
          (**(code **)(*DAT_803dd6d4 + 0x48))(*(byte *)(puVar9 + 1) >> 3 & 7,iVar3,0xffffffff);
          *(byte *)(puVar9 + 1) =
               ((*(byte *)(puVar9 + 1) >> 3 & 7) + 1) * '\b' & 0x38 | *(byte *)(puVar9 + 1) & 199;
          *(byte *)(puVar9 + 1) = *(byte *)(puVar9 + 1) & 0xf8;
          goto LAB_801af928;
        }
      }
    }
    else if (bVar1 == 4) {
      uVar8 = FUN_80020078(0x543);
      if (uVar8 != 0) {
        FUN_80138c90(iVar5,1);
        (**(code **)(*DAT_803dd6d4 + 0x48))(*(byte *)(puVar9 + 1) >> 3 & 7,iVar3,0xffffffff);
        *(byte *)(puVar9 + 1) =
             ((*(byte *)(puVar9 + 1) >> 3 & 7) + 1) * '\b' & 0x38 | *(byte *)(puVar9 + 1) & 199;
        *(byte *)(puVar9 + 1) = *(byte *)(puVar9 + 1) & 0xf8;
        goto LAB_801af928;
      }
    }
    else if (bVar1 < 4) {
      uVar8 = FUN_80020078(0x1fd);
      if (uVar8 == 0) {
        uVar8 = FUN_80020078(0x380);
        if (uVar8 == 0) {
          if (*(char *)((int)puVar9 + 5) < '\0') {
            FUN_800201ac(0x387,1);
            FUN_80138c90(iVar5,1);
            (**(code **)(*DAT_803dd6d4 + 0x48))(*(byte *)(puVar9 + 1) >> 3 & 7,iVar3,0xffffffff);
            *(byte *)(puVar9 + 1) =
                 ((*(byte *)(puVar9 + 1) >> 3 & 7) + 1) * '\b' & 0x38 | *(byte *)(puVar9 + 1) & 199;
            *(byte *)(puVar9 + 1) = *(byte *)(puVar9 + 1) & 0xf8;
            goto LAB_801af928;
          }
        }
        else {
          *(byte *)((int)puVar9 + 5) = *(byte *)((int)puVar9 + 5) & 0x7f | 0x80;
        }
      }
      else {
        FUN_800201ac(0x387,1);
        *(byte *)(puVar9 + 1) =
             ((*(byte *)(puVar9 + 1) >> 3 & 7) + 1) * '\b' & 0x38 | *(byte *)(puVar9 + 1) & 199;
      }
    }
  }
  if (iVar5 != 0) {
    if ((*(ushort *)(iVar5 + 0xb0) & 0x1000) == 0) {
      puVar9[2] = (uint)((float)puVar9[2] + FLOAT_803dc074);
    }
    uVar8 = FUN_80020078(0x4e3);
    if ((uVar8 == 1) && (3 < *pbVar6)) {
      FUN_800201ac(0x4e3,0xff);
    }
    if (FLOAT_803e5460 <= (float)puVar9[2]) {
      puVar9[2] = (uint)((float)puVar9[2] - FLOAT_803e5460);
      uVar8 = FUN_80020078(0x4e3);
      if ((uVar8 == 0xff) && (*pbVar6 < 4)) {
        FUN_800201ac(0x4e3,1);
      }
    }
  }
LAB_801af928:
  FUN_8028688c();
  return;
}

